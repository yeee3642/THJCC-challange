#!/usr/bin/env python3
"""
Solution: RSA common-modulus attack with a twist.

The textbook attack needs gcd(e1, e2) == 1 so that Bezout gives
    a*e1 + b*e2 = 1   ->   c1^a * c2^b = m^(a*e1 + b*e2) = m   (mod n)

Here gcd(111, 39) = 3, so Bezout only reaches
    a*e1 + b*e2 = 3   ->   c1^a * c2^b = m^3   (mod n)

The generator made sure m^3 < n, so the modular reduction never happened:
the value we recover *is* the integer m^3 and a plain integer cube root
finishes the job.
"""
import os
import re
from Crypto.Util.number import long_to_bytes, inverse


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def iroot(n, k):
    """Floor of the k-th root of n, plus an exactness flag (Newton, integers only)."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0, True
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // pow(x, k - 1)) // k
        if y >= x:
            break
        x = y
    return x, pow(x, k) == n


def parse(path):
    vals = {}
    for line in open(path):
        m = re.match(r"\s*(\w+)\s*=\s*(\d+)", line)
        if m:
            vals[m.group(1)] = int(m.group(2))
    return vals


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    v = parse(os.path.join(here, "output.txt"))
    n, e1, c1, e2, c2 = v["n"], v["e1"], v["c1"], v["e2"], v["c2"]

    g, a, b = egcd(e1, e2)
    print(f"[*] gcd(e1, e2) = {g}   (a={a}, b={b})")

    # Negative exponents become exponents of the modular inverse.
    x = pow(c1, a, n) if a >= 0 else pow(inverse(c1, n), -a, n)
    y = pow(c2, b, n) if b >= 0 else pow(inverse(c2, n), -b, n)
    mg = (x * y) % n  # == m**g  mod n
    print(f"[*] recovered m^{g} mod n ({mg.bit_length()} bits, n is {n.bit_length()} bits)")

    m, exact = iroot(mg, g)
    assert exact, "m^g wrapped around the modulus -- attack needs m^g < n"
    flag = long_to_bytes(m)
    print(f"[+] {flag.decode()}")
    return flag


if __name__ == "__main__":
    main()
