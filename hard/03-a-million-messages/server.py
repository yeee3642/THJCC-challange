#!/usr/bin/env python3
"""
A Million Messages -- line based service (RSA-512, PKCS#1 v1.5 type 2).

Run locally:      python3 server.py
Run as a socket:  socat TCP-LISTEN:1340,reuseaddr,fork EXEC:"python3 server.py"

Protocol
--------
  <- N <hex>
  <- E <hex>
  <- C <hex>              the flag, PKCS#1 v1.5 padded, then encrypted
  -> <hex ciphertext>
  <- OK | BAD             whether the decryption had valid v1.5 type-2 padding
  -> quit
"""
import os
import sys
from Crypto.Util.number import getPrime

FLAG = os.environ.get("FLAG", "THJCC{bl31chenb4ch3r_st1ll_3ats_pkcs1_v1_5}")
BITS = 512
E = 65537
MAX_QUERIES = 2_000_000


def pkcs1_pad(msg, k):
    ps = b""
    while len(ps) < k - 3 - len(msg):
        ps += bytes(b for b in os.urandom(64) if b)  # PS must be nonzero
    ps = ps[: k - 3 - len(msg)]
    return b"\x00\x02" + ps + b"\x00" + msg


def main():
    while True:
        p, q = getPrime(BITS // 2), getPrime(BITS // 2)
        n = p * q
        if p != q and n.bit_length() == BITS and (p - 1) % E and (q - 1) % E:
            break
    d = pow(E, -1, (p - 1) * (q - 1))
    k = (n.bit_length() + 7) // 8

    msg = FLAG.encode()
    assert k - 3 - len(msg) >= 8, "flag too long for this modulus"
    c = pow(int.from_bytes(pkcs1_pad(msg, k), "big"), E, n)

    print(f"N {n:x}", flush=True)
    print(f"E {E:x}", flush=True)
    print(f"C {c:x}", flush=True)

    served = 0
    for line in sys.stdin:
        line = line.strip()
        if not line or line == "quit":
            break
        served += 1
        if served > MAX_QUERIES:
            print("BAD", flush=True)
            continue
        try:
            m = pow(int(line, 16) % n, d, n).to_bytes(k, "big")
        except Exception:
            print("BAD", flush=True)
            continue
        print("OK" if m[0] == 0x00 and m[1] == 0x02 else "BAD", flush=True)


if __name__ == "__main__":
    main()
