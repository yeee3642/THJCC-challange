#!/usr/bin/env python3
"""
Solution: Bleichenbacher's adaptive chosen-ciphertext attack (CRYPTO '98),
a.k.a. the Million Message Attack, against a PKCS#1 v1.5 padding oracle.

The oracle says "OK" exactly when the decryption of what we sent lies in
[2B, 3B) with B = 2^(8(k-2)). Since (c * s^e)^d = m*s (mod n), each "OK" for a
multiplier s tells us

    2B <= m*s - r*n < 3B     for some integer r
    =>  (2B + r*n)/s <= m < (3B + r*n)/s

so every success intersects our set of candidate intervals with a shifted,
scaled copy of [2B, 3B). The set collapses to one interval, then to one point,
which is the padded plaintext.

The given ciphertext is already PKCS#1 conforming, so the blinding step (s0)
is skipped and we go straight to step 2a.
"""
import os
import subprocess
import sys


def ceil_div(a, b):
    return -(-a // b)


class Oracle:
    """Talks to server.py over a pipe; swap for a socket to attack a remote."""

    def __init__(self, path):
        self.p = subprocess.Popen(
            [sys.executable, path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )
        self.n = int(self.p.stdout.readline().split()[1], 16)
        self.e = int(self.p.stdout.readline().split()[1], 16)
        self.c = int(self.p.stdout.readline().split()[1], 16)
        self.k = (self.n.bit_length() + 7) // 8
        self.queries = 0

    def conforming(self, c):
        self.queries += 1
        self.p.stdin.write(f"{c:x}\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip() == "OK"

    def close(self):
        self.p.kill()


def bleichenbacher(oracle):
    n, e, c, k = oracle.n, oracle.e, oracle.c, oracle.k
    B = 1 << (8 * (k - 2))
    B2, B3 = 2 * B, 3 * B

    def ok(s):
        return oracle.conforming(c * pow(s, e, n) % n)

    assert oracle.conforming(c), "the given ciphertext should already conform"
    M = [(B2, B3 - 1)]
    s = ceil_div(n, B3)

    # Step 2a: smallest s >= n/3B that keeps the padding valid.
    while not ok(s):
        s += 1
    rounds = 0

    while True:
        rounds += 1
        # Step 3: narrow the intervals with the s we just found.
        M2 = set()
        for a, b in M:
            for r in range(ceil_div(a * s - B3 + 1, n), (b * s - B2) // n + 1):
                lo = max(a, ceil_div(B2 + r * n, s))
                hi = min(b, (B3 - 1 + r * n) // s)
                if lo <= hi:
                    M2.add((lo, hi))
        M = sorted(M2)
        assert M, "interval set collapsed to nothing"

        # Step 4: a single interval of width 0 is the answer.
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]

        if len(M) > 1:
            # Step 2b: several intervals left, just keep walking s upward.
            s += 1
            while not ok(s):
                s += 1
        else:
            # Step 2c: one interval -- jump straight to the useful multipliers.
            a, b = M[0]
            r = ceil_div(2 * (b * s - B2), n)
            found = False
            while not found:
                for s_try in range(ceil_div(B2 + r * n, b), ceil_div(B3 + r * n, a)):
                    if ok(s_try):
                        s, found = s_try, True
                        break
                r += 1
        if rounds % 10 == 0:
            width = M[0][1] - M[0][0]
            print(f"[*] round {rounds:3d}  intervals={len(M):3d}  "
                  f"width~2^{width.bit_length()}  queries={oracle.queries}")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    oracle = Oracle(os.path.join(here, "server.py"))
    try:
        m = bleichenbacher(oracle)
        raw = m.to_bytes(oracle.k, "big")
        print(f"[*] recovered padded plaintext after {oracle.queries} queries")
        assert raw[:2] == b"\x00\x02", raw[:8]
        flag = raw[raw.index(b"\x00", 2) + 1:].decode()
        print(f"[+] {flag}")
        return flag
    finally:
        oracle.close()


if __name__ == "__main__":
    main()
