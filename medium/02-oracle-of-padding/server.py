#!/usr/bin/env python3
"""
Oracle of Padding -- line based service.

Run locally:      python3 server.py
Run as a socket:  socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 server.py"

Protocol
--------
  <- TOKEN <hex>          the encrypted session token (IV || ciphertext)
  -> <hex>                any IV || ciphertext you like
  <- OK | BAD             whether PKCS#7 unpadding succeeded
  -> quit
"""
import os
import sys
from Crypto.Cipher import AES

FLAG = os.environ.get("FLAG", "THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}")
KEY = os.urandom(16)
MAX_QUERIES = 200000


def pad(b):
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def unpad(b):
    if not b or len(b) % 16:
        raise ValueError("length")
    n = b[-1]
    if n < 1 or n > 16 or b[-n:] != bytes([n]) * n:
        raise ValueError("padding")
    return b[:-n]


def main():
    token = b'{"user":"guest","admin":false,"note":"' + FLAG.encode() + b'"}'
    iv = os.urandom(16)
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(pad(token))
    print("TOKEN " + (iv + ct).hex(), flush=True)

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
            raw = bytes.fromhex(line)
            if len(raw) < 32 or len(raw) % 16:
                raise ValueError("shape")
            unpad(AES.new(KEY, AES.MODE_CBC, raw[:16]).decrypt(raw[16:]))
            print("OK", flush=True)
        except Exception:
            print("BAD", flush=True)


if __name__ == "__main__":
    main()
