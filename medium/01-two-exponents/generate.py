#!/usr/bin/env python3
"""Challenge generator -- keep away from players."""
import os
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = b"THJCC{n0t_c0pr1m3_but_st1ll_br0k3n_4nyw4y}"

# Two departments encrypt the very same memo with the very same modulus,
# because "everybody already trusts our RA".
E1 = 111  # 3 * 37
E2 = 39   # 3 * 13


def main():
    m = bytes_to_long(FLAG)
    while True:
        p = getPrime(512)
        q = getPrime(512)
        n = p * q
        if p != q and m ** 3 < n:
            break

    c1 = pow(m, E1, n)
    c2 = pow(m, E2, n)

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "output.txt"), "w") as f:
        f.write("# Intercepted from the internal memo bus\n")
        f.write(f"n  = {n}\n")
        f.write(f"e1 = {E1}\n")
        f.write(f"c1 = {c1}\n")
        f.write(f"e2 = {E2}\n")
        f.write(f"c2 = {c2}\n")
    print("wrote output.txt")


if __name__ == "__main__":
    main()
