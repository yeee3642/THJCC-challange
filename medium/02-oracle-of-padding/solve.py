#!/usr/bin/env python3
"""
Solution: Vaudenay CBC padding oracle.

For CBC, P_i = D_k(C_i) XOR C_{i-1}. We fully control C_{i-1}, so we submit a
two block message  (forged_prev || C_i)  and wiggle forged_prev until the
oracle reports valid PKCS#7. That pins down D_k(C_i) one byte at a time, and
the real plaintext is D_k(C_i) XOR the genuine previous block.

Cost: at most 256 queries per byte, 16 bytes per block.
"""
import os
import subprocess
import sys


class Oracle:
    """Talks to server.py over a pipe; swap for a socket to attack a remote."""

    def __init__(self, path):
        self.p = subprocess.Popen(
            [sys.executable, path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )
        line = self.p.stdout.readline().split()
        assert line[0] == "TOKEN", line
        self.token = bytes.fromhex(line[1])
        self.queries = 0

    def valid(self, blob: bytes) -> bool:
        self.queries += 1
        self.p.stdin.write(blob.hex() + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip() == "OK"

    def close(self):
        try:
            self.p.stdin.write("quit\n")
            self.p.stdin.flush()
        except Exception:
            pass
        self.p.kill()


def decrypt_block(oracle, block):
    """Recover D_k(block); caller XORs with the real previous block."""
    inter = bytearray(16)
    for pos in range(15, -1, -1):
        padval = 16 - pos
        suffix = bytes(inter[i] ^ padval for i in range(pos + 1, 16))
        for guess in range(256):
            forged = bytes(16 - len(suffix) - 1) + bytes([guess]) + suffix
            if not oracle.valid(forged + block):
                continue
            if pos == 15:
                # Could be a lucky 0x02 0x02 ... instead of a final 0x01.
                probe = bytearray(forged)
                probe[14] ^= 0xFF
                if not oracle.valid(bytes(probe) + block):
                    continue
            inter[pos] = guess ^ padval
            break
        else:
            raise RuntimeError(f"no valid byte at position {pos}")
    return bytes(inter)


def unpad(b):
    return b[: -b[-1]]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    oracle = Oracle(os.path.join(here, "server.py"))
    try:
        token = oracle.token
        blocks = [token[i:i + 16] for i in range(0, len(token), 16)]
        plain = b""
        for i in range(1, len(blocks)):
            inter = decrypt_block(oracle, blocks[i])
            piece = bytes(a ^ b for a, b in zip(inter, blocks[i - 1]))
            plain += piece
            print(f"[*] block {i}/{len(blocks)-1}: {piece}")
        plain = unpad(plain)
        print(f"[*] {oracle.queries} oracle queries")
        flag = plain[plain.index(b"THJCC{"): plain.index(b"}", plain.index(b"THJCC{")) + 1]
        print(f"[+] {flag.decode()}")
        return flag
    finally:
        oracle.close()


if __name__ == "__main__":
    main()
