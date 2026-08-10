#!/usr/bin/env python3
"""
Solution: ECDSA private key recovery from a repeated nonce.

Both signatures use the same k, so they share the same r. From
    s1 = k^-1 (h1 + r*d)      s2 = k^-1 (h2 + r*d)     (mod n)
subtracting gives
    s1 - s2 = k^-1 (h1 - h2)  ->  k = (h1 - h2) / (s1 - s2)
and then
    d = (s1*k - h1) / r
Two sign flips are possible for k depending on the curve library, so we test
both candidates against the published public key.
"""
import hashlib
import os
import subprocess
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


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


def h(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    p = subprocess.Popen([sys.executable, os.path.join(here, "server.py")],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         text=True, bufsize=1)

    pub = p.stdout.readline().split()
    Q = (int(pub[1], 16), int(pub[2], 16))
    sigs = []
    for _ in range(2):
        _, msg, r, s = p.stdout.readline().split()
        sigs.append((bytes.fromhex(msg), int(r, 16), int(s, 16)))
    target = bytes.fromhex(p.stdout.readline().split()[1])

    (m1, r1, s1), (m2, r2, s2) = sigs
    assert r1 == r2, "nonces were not reused after all"
    print(f"[*] shared r = {r1:#x}")

    h1, h2 = h(m1), h(m2)
    k = (h1 - h2) * pow(s1 - s2, -1, N) % N
    d = (s1 * k - h1) * pow(r1, -1, N) % N
    if mul(d, G) != Q:  # the other sign of k
        k = N - k
        d = (s1 * k - h1) * pow(r1, -1, N) % N
    assert mul(d, G) == Q, "key recovery failed"
    print(f"[*] recovered k = {k:#x}")
    print(f"[*] recovered d = {d:#x}")

    # Sign the target with a nonce of our own choosing (a fresh one, obviously).
    kk = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
    r = mul(kk, G)[0] % N
    s = pow(kk, -1, N) * (h(target) + r * d) % N
    p.stdin.write(f"{r:x} {s:x}\n")
    p.stdin.flush()

    reply = p.stdout.readline().strip()
    p.kill()
    print(f"[+] {reply}")
    assert reply.startswith("FLAG"), reply
    return reply


if __name__ == "__main__":
    main()
