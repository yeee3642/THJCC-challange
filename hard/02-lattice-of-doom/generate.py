#!/usr/bin/env python3
"""Challenge generator -- keep away from players."""
import hashlib
import json
import os

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

FLAG = b"THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}"
NSIGS = 60
NONCE_BYTES = 29  # <-- the bug: 232 bits of nonce instead of 256


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
    d = int.from_bytes(os.urandom(32), "big") % (N - 1) + 1
    Q = mul(d, G)

    sigs = []
    for i in range(NSIGS):
        msg = b"authorize withdrawal #%04d" % i
        k = int.from_bytes(os.urandom(NONCE_BYTES), "big")
        if k == 0:
            continue
        r = mul(k, G)[0] % N
        s = pow(k, -1, N) * (h(msg) + r * d) % N
        sigs.append({"msg": msg.hex(), "r": f"{r:x}", "s": f"{s:x}"})

    # The flag is AES-encrypted under the private key nobody can possibly derive.
    from Crypto.Cipher import AES
    key = hashlib.sha256(b"wallet-v1|" + d.to_bytes(32, "big")).digest()[:16]
    iv = os.urandom(16)
    padded = FLAG + bytes([16 - len(FLAG) % 16]) * (16 - len(FLAG) % 16)
    enc = AES.new(key, AES.MODE_CBC, iv).encrypt(padded)

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "output.json"), "w") as f:
        json.dump({
            "curve": "secp256k1",
            "hash": "sha256",
            "Qx": f"{Q[0]:x}",
            "Qy": f"{Q[1]:x}",
            "signatures": sigs,
            "flag_enc": (iv + enc).hex(),
            "kdf": "AES-128-CBC, key = sha256(b'wallet-v1|' + d.to_bytes(32,'big'))[:16]",
        }, f, indent=2)
    print(f"wrote output.json ({len(sigs)} signatures)")


if __name__ == "__main__":
    main()
