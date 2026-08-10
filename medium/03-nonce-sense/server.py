#!/usr/bin/env python3
"""
Nonce Sense -- line based signing service (secp256k1 / ECDSA / SHA-256).

Run locally:      python3 server.py
Run as a socket:  socat TCP-LISTEN:1338,reuseaddr,fork EXEC:"python3 server.py"

Protocol
--------
  <- PUB <Qx> <Qy>
  <- SIG <message hex> <r> <s>      (twice, on two different messages)
  <- TARGET <message hex>
  -> <r> <s>                        your signature over TARGET
  <- FLAG <flag>  |  NOPE
"""
import hashlib
import os
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

FLAG = os.environ.get("FLAG", "THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}")


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


def sign(d, msg, k):
    r = mul(k, G)[0] % N
    s = pow(k, -1, N) * (h(msg) + r * d) % N
    return r, s


def verify(Q, msg, r, s):
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    pt = add(mul(h(msg) * w % N, G), mul(r * w % N, Q))
    return pt is not None and pt[0] % N == r


MSG1 = b"transfer 1 coin to alice"
MSG2 = b"transfer 2 coins to bob"
TARGET = b"admin=true;action=release_flag"


def main():
    d = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
    Q = mul(d, G)

    # The bug: the per-session "random" is drawn once and never refreshed.
    k = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1

    print(f"PUB {Q[0]:x} {Q[1]:x}", flush=True)
    for msg in (MSG1, MSG2):
        r, s = sign(d, msg, k)
        print(f"SIG {msg.hex()} {r:x} {s:x}", flush=True)
    print(f"TARGET {TARGET.hex()}", flush=True)

    line = sys.stdin.readline().split()
    try:
        r, s = int(line[0], 16), int(line[1], 16)
    except Exception:
        print("NOPE", flush=True)
        return
    print(f"FLAG {FLAG}" if verify(Q, TARGET, r, s) else "NOPE", flush=True)


if __name__ == "__main__":
    main()
