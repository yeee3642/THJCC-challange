#!/usr/bin/env python3
"""
Solution: the "forbidden attack" on AES-GCM with a repeated nonce.

GCM's tag is  T = GHASH_H(A, C) XOR E_K(J0), and GHASH is just a polynomial
evaluated at the authentication key H = E_K(0) over GF(2^128):

    GHASH_H(C) = sum_i  b_i * H^(nb - i + 1)          (b = blocks, then the
                                                       length block)

With the nonce repeated, J0 repeats, so E_K(J0) is the same constant in every
tag. Subtracting (= XOR) two tags cancels it:

    T1 XOR T2 = GHASH_H(C1) XOR GHASH_H(C2)

which is a polynomial in the *unknown* H whose coefficients we know. Its roots
are the H candidates. Root-finding in GF(2^128) is done the standard way:
gcd(P, x^(2^128) - x) to keep only linear factors, then equal-degree splitting
with the trace map. A third tag tells us which root is the real H.

Once H and E_K(J0) are known we can tag anything, and since the keystream also
repeats, a known plaintext/ciphertext pair gives us the keystream to encrypt a
message of our choosing.

Pure Python: no PyCryptodome primitives are used for the attack itself.
"""
import hashlib
import os
import subprocess
import sys

# ---------------------------------------------------------------- GF(2^128) --
# GCM's field: bit 127 of the integer is the x^0 coefficient (the "reflected"
# convention), reduction polynomial x^128 + x^7 + x^2 + x + 1.
R = 0xE1 << 120
# Careful: in this representation the multiplicative identity is *not* the
# integer 1 -- the x^0 coefficient lives in the most significant bit.
ONE = 1 << 127
X = [0, ONE]  # the polynomial "x"


def gmul(x, y):
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z


def ginv(a):
    """a^(2^128 - 2), i.e. the multiplicative inverse."""
    r, t = ONE, a
    for _ in range(127):
        t = gmul(t, t)
        r = gmul(r, t)
    return r


# ---------------------------------------------- polynomials over GF(2^128) ---
# Coefficient lists, index == degree, trailing zeros trimmed.
def ptrim(p):
    while p and p[-1] == 0:
        p.pop()
    return p


def padd(a, b):
    n = max(len(a), len(b))
    return ptrim([(a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0)
                  for i in range(n)])


def pmul(a, b):
    if not a or not b:
        return []
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    r[i + j] ^= gmul(x, y)
    return ptrim(r)


def psqr(a):
    """Squaring is linear in characteristic 2: (sum c_i x^i)^2 = sum c_i^2 x^2i."""
    if not a:
        return []
    r = [0] * (2 * len(a) - 1)
    for i, c in enumerate(a):
        r[2 * i] = gmul(c, c)
    return ptrim(r)


def pdivmod(a, m):
    a, q = a[:], [0] * max(0, len(a) - len(m) + 1)
    inv = ginv(m[-1])
    while len(a) >= len(m):
        sh = len(a) - len(m)
        if a[-1]:
            f = gmul(a[-1], inv)
            q[sh] = f
            for i, mc in enumerate(m):
                a[i + sh] ^= gmul(f, mc)
        a.pop()
    return ptrim(q), ptrim(a)


def pmod(a, m):
    return pdivmod(a, m)[1]


def pmonic(a):
    inv = ginv(a[-1])
    return [gmul(c, inv) for c in a]


def pgcd(a, b):
    a, b = a[:], b[:]
    while b:
        a, b = b, pmod(a, b)
    return pmonic(a) if a else a


def prand(seed):
    """Deterministic field elements, so the solve is reproducible."""
    n = seed[0]
    seed[0] += 1
    return int.from_bytes(hashlib.sha256(b"split%d" % n).digest()[:16], "big")


def proots(g, seed=None):
    """All roots in GF(2^128) of g, via gcd(g, x^(2^128)-x) + trace splitting."""
    if seed is None:
        seed = [0]
        f = X[:]
        for _ in range(128):             # x^(2^128) mod g
            f = pmod(psqr(f), g)
        g = pgcd(g, padd(f, X))          # keep only the distinct linear factors
        if len(g) <= 1:
            return []
    g = pmonic(g)
    if len(g) <= 1:
        return []
    if len(g) == 2:
        return [g[0]]                    # monic x + c  ->  root c (char 2)
    while True:
        a = prand(seed)
        if not a:
            continue
        u = pmod([0, a], g)              # a*x
        acc = u[:]
        for _ in range(127):             # trace map: sum (a*x)^(2^i)
            u = pmod(psqr(u), g)
            acc = padd(acc, u)
        h = pgcd(g, acc)
        if 0 < len(h) - 1 < len(g) - 1:
            return proots(h, seed) + proots(pdivmod(g, h)[0], seed)


# --------------------------------------------------------------------- GCM ---
def blocks(data):
    return [int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big")
            for i in range(0, len(data), 16)]


def ghash_blocks(ct, aad=b""):
    return blocks(aad) + blocks(ct) + [((len(aad) * 8) << 64) | (len(ct) * 8)]


def ghash(H, ct, aad=b""):
    y = 0
    for b in ghash_blocks(ct, aad):
        y = gmul(y ^ b, H)
    return y


def ghash_poly(ct, aad=b""):
    """GHASH as a polynomial in H: block i contributes b_i * H^(nb-i+1)."""
    bs = ghash_blocks(ct, aad)
    poly = [0] * (len(bs) + 1)
    for i, b in enumerate(bs):
        poly[len(bs) - i] = b
    return ptrim(poly)


# ------------------------------------------------------------------ attack ---
def main():
    here = os.path.dirname(os.path.abspath(__file__))
    p = subprocess.Popen([sys.executable, os.path.join(here, "server.py")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         text=True, bufsize=1)

    p.stdout.readline()                                  # NONCE (not needed)
    msgs = []
    for _ in range(3):
        _, pt, ct, tag = p.stdout.readline().split()
        msgs.append((bytes.fromhex(pt), bytes.fromhex(ct), bytes.fromhex(tag)))
    target = bytes.fromhex(p.stdout.readline().split()[1])

    (_, c1, t1), (_, c2, t2), (_, c3, t3) = msgs
    T1, T2 = int.from_bytes(t1, "big"), int.from_bytes(t2, "big")

    # P(H) = GHASH(C1) + GHASH(C2) + (T1 + T2) == 0
    poly = padd(padd(ghash_poly(c1), ghash_poly(c2)), [T1 ^ T2])
    print(f"[*] polynomial in H has degree {len(poly) - 1}")

    cands = proots(poly)
    print(f"[*] {len(cands)} root(s) in GF(2^128)")

    H = EKJ0 = None
    for cand in cands:
        ekj0 = T1 ^ ghash(cand, c1)
        if ghash(cand, c3) ^ ekj0 == int.from_bytes(t3, "big"):
            H, EKJ0 = cand, ekj0
            break
    assert H is not None, "no candidate reproduced the third tag"
    print(f"[*] H     = {H:032x}")
    print(f"[*] E(J0) = {EKJ0:032x}")

    # Same nonce, same keystream: msgs[0] hands us the first blocks of it.
    keystream = bytes(a ^ b for a, b in zip(msgs[0][0], msgs[0][1]))
    assert len(keystream) >= len(target), "need a longer known plaintext"
    forged_ct = bytes(a ^ b for a, b in zip(target, keystream))
    forged_tag = (ghash(H, forged_ct) ^ EKJ0).to_bytes(16, "big")

    p.stdin.write(f"{forged_ct.hex()} {forged_tag.hex()}\n")
    p.stdin.flush()
    reply = p.stdout.readline().strip()
    p.kill()
    print(f"[+] {reply}")
    assert reply.startswith("FLAG"), reply
    return reply


if __name__ == "__main__":
    main()
