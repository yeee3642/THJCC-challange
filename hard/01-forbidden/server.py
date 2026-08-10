#!/usr/bin/env python3
"""
Forbidden -- line based service (AES-128-GCM).

Run locally:      python3 server.py
Run as a socket:  socat TCP-LISTEN:1339,reuseaddr,fork EXEC:"python3 server.py"

Protocol
--------
  <- NONCE <hex>
  <- MSG <plaintext hex> <ciphertext hex> <tag hex>     (three public notices)
  <- TARGET <plaintext hex>
  -> <ciphertext hex> <tag hex>       must authenticate to TARGET, same nonce
  <- FLAG <flag>  |  NOPE
  -> quit
"""
import os
import sys
from Crypto.Cipher import AES

FLAG = os.environ.get("FLAG", "THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}")

NOTICES = [
    b"welcome to the vault, there is nothing to see here",
    b"status: nominal",
    b"reminder: rotate your keys, some day, maybe, but not today",
]
TARGET = b"give me the flag"
MAX_TRIES = 100


def main():
    key = os.urandom(16)
    # The bug: one nonce, baked into the config, shared by every notice.
    nonce = os.urandom(12)

    print(f"NONCE {nonce.hex()}", flush=True)
    for pt in NOTICES:
        ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(pt)
        print(f"MSG {pt.hex()} {ct.hex()} {tag.hex()}", flush=True)
    print(f"TARGET {TARGET.hex()}", flush=True)

    tries = 0
    for line in sys.stdin:
        line = line.split()
        if not line or line[0] == "quit":
            break
        tries += 1
        if tries > MAX_TRIES:
            print("NOPE", flush=True)
            continue
        try:
            ct, tag = bytes.fromhex(line[0]), bytes.fromhex(line[1])
            pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        except Exception:
            print("NOPE", flush=True)
            continue
        print(f"FLAG {FLAG}" if pt == TARGET else "NOPE", flush=True)
        if pt == TARGET:
            break


if __name__ == "__main__":
    main()
