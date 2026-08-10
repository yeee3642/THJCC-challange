#!/usr/bin/env python3
"""
Solution: Hidden Number Problem / Boneh-Venkatesan lattice attack on ECDSA
with short (biased) nonces.

Every signature gives  s*k = h + r*d  (mod n), i.e.

    k_i = a_i + b_i * d   (mod n),    a_i = h_i/s_i,  b_i = r_i/s_i

with the *unknown but small* k_i < K = 2^232 (the firmware only draws 29 random
bytes). That is exactly the Hidden Number Problem. Build the lattice

    rows:  n*e_i                                    (i = 0..M-1)
           (b_0, ..., b_{M-1}, K/n, 0)
           (a_0, ..., a_{M-1}, 0,   K)

whose vector  d*(row_b) + 1*(row_a) - (reductions)  equals
(k_0, ..., k_{M-1}, d*K/n, K) -- much shorter than the Gaussian-heuristic
length of the lattice, so LLL finds it. Read d off the second-to-last
coordinate, confirm against the public key, decrypt the flag.

Everything (including LLL) is pure Python; with fpylll/Sage you would just
call LLL() and use more signatures.
"""
import hashlib
import json
import os
from fractions import Fraction

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

NONCE_BITS = 232          # what the leaked firmware excerpt implies
M = 24                    # signatures to feed the lattice (dimension M + 2)


# ------------------------------------------------------------ curve helpers --
def add(pt1, pt2):
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    (x1, y1), (x2, y2) = pt1, pt2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if pt1 == pt2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, pt):
    r, a = None, pt
    while k:
        if k & 1:
            r = add(r, a)
        a = add(a, a)
        k >>= 1
    return r


def hint(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N


# ----------------------------------------------------------------------- LLL --
def lll(basis, delta=Fraction(99, 100)):
    """Textbook LLL (Cohen 2.6.3) with exact rational Gram-Schmidt."""
    b = [list(map(int, row)) for row in basis]
    n = len(b)
    mu = [[Fraction(0)] * n for _ in range(n)]
    B = [Fraction(0)] * n

    gram = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1):
            gram[i][j] = gram[j][i] = sum(x * y for x, y in zip(b[i], b[j]))

    for i in range(n):                       # Gram-Schmidt from the Gram matrix
        for j in range(i):
            s = Fraction(gram[i][j])
            for t in range(j):
                s -= mu[j][t] * mu[i][t] * B[t]
            mu[i][j] = s / B[j]
        s = Fraction(gram[i][i])
        for t in range(i):
            s -= mu[i][t] * mu[i][t] * B[t]
        B[i] = s

    def reduce(k, j):
        m = mu[k][j]
        q = (m.numerator * 2 + m.denominator) // (m.denominator * 2)  # round()
        if q == 0:
            return
        b[k] = [x - q * y for x, y in zip(b[k], b[j])]
        for t in range(j):
            mu[k][t] -= q * mu[j][t]
        mu[k][j] -= q

    k = 1
    while k < n:
        reduce(k, k - 1)
        if B[k] >= (delta - mu[k][k - 1] ** 2) * B[k - 1]:
            for j in range(k - 2, -1, -1):
                reduce(k, j)
            k += 1
        else:
            m, bk = mu[k][k - 1], B[k] + mu[k][k - 1] ** 2 * B[k - 1]
            mu[k][k - 1] = m * B[k - 1] / bk
            B[k] = B[k - 1] * B[k] / bk
            B[k - 1] = bk
            b[k], b[k - 1] = b[k - 1], b[k]
            for j in range(k - 1):
                mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
            for i in range(k + 1, n):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - m * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(k - 1, 1)
    return b


# -------------------------------------------------------------------- attack --
def main():
    here = os.path.dirname(os.path.abspath(__file__))
    data = json.load(open(os.path.join(here, "output.json")))
    Q = (int(data["Qx"], 16), int(data["Qy"], 16))
    sigs = [(bytes.fromhex(s["msg"]), int(s["r"], 16), int(s["s"], 16))
            for s in data["signatures"]][:M]

    K = 1 << NONCE_BITS
    a, bb = [], []
    for msg, r, s in sigs:
        sinv = pow(s, -1, N)
        a.append(hint(msg) * sinv % N)
        bb.append(r * sinv % N)

    dim = M + 2
    basis = [[0] * dim for _ in range(dim)]
    for i in range(M):                       # n * e_i, scaled by n
        basis[i][i] = N * N
    for i in range(M):
        basis[M][i] = N * bb[i]
        basis[M + 1][i] = N * a[i]
    basis[M][M] = K                          # == n * (K/n)
    basis[M + 1][M + 1] = N * K
    print(f"[*] reducing a {dim}x{dim} lattice ({M} signatures, {NONCE_BITS}-bit nonces)")

    reduced = lll(basis)

    d = None
    for row in reduced:
        for vec in (row, [-x for x in row]):
            if vec[M + 1] != N * K:
                continue
            cand = vec[M] // K % N
            if mul(cand, G) == Q:
                d = cand
                break
            k0 = vec[0] // N % N             # fallback: recover d from k_0
            cand = (sigs[0][2] * k0 - hint(sigs[0][0])) * pow(sigs[0][1], -1, N) % N
            if mul(cand, G) == Q:
                d = cand
                break
        if d is not None:
            break
    assert d is not None, "no lattice row yielded the key -- try a larger M"
    print(f"[+] private key d = {d:#066x}")

    from Crypto.Cipher import AES
    blob = bytes.fromhex(data["flag_enc"])
    key = hashlib.sha256(b"wallet-v1|" + d.to_bytes(32, "big")).digest()[:16]
    pt = AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:])
    flag = pt[:-pt[-1]].decode()
    print(f"[+] {flag}")
    return flag


if __name__ == "__main__":
    main()
