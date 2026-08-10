# Two Exponents — writeup

**Category:** crypto (medium) · **Attack:** RSA common modulus, non-coprime exponents

## The setup

```
n  = <1024-bit>
e1 = 111,  c1 = m^111 mod n
e2 = 39,   c2 = m^39  mod n
```

Same modulus, same message, two exponents. That is textbook *common modulus*.

## Why the textbook script fails

The standard attack takes Bézout coefficients `a, b` with `a*e1 + b*e2 = 1` and
computes

```
c1^a * c2^b = m^(a*e1 + b*e2) = m^1 = m   (mod n)
```

That step silently assumes `gcd(e1, e2) = 1`. Here:

```
111 = 3 · 37        39 = 3 · 13        gcd = 3
```

so Bézout can only reach 3, never 1. Running the usual script gives garbage —
this is the whole point of the challenge.

## The actual attack

Extended Euclid on `(111, 39)` gives `6·111 − 17·39 = 666 − 663 = 3`, so

```
c1^6 · c2^(−17) = m^(6·111 − 17·39) = m^3   (mod n)
```

A negative exponent is just the modular inverse: `c2^(−17) = (c2^{-1})^17 mod n`.

That leaves `m^3 mod n`, not `m`. The way out is a size argument: the flag is
41 bytes = 328 bits, so `m^3` is about 984 bits, while `n` is 1024 bits.

```
m^3 < n   ⟹   m^3 mod n *is* m^3 as an integer
```

The modular reduction never happened, so an ordinary integer cube root
recovers `m`. The generator enforces this with `assert m**3 < n` when picking
primes.

## Implementation notes

* Do the cube root with integer Newton iteration, not `round(x ** (1/3))` —
  a 984-bit float has 53 bits of mantissa and will be wrong.
* Check exactness (`x**k == n`) rather than trusting the iteration; if it is
  not exact, `m^g` wrapped the modulus and this route is closed.

```python
g, a, b = egcd(e1, e2)                      # g = 3
x = pow(c1, a, n)                           # a = 6
y = pow(inverse(c2, n), -b, n)              # b = -17
m, exact = iroot(x * y % n, g)
```

## Generalisation

The attack works whenever `gcd(e1, e2) = g` and `m^g < n`. If `m^g > n` you are
stuck with a `g`-th root modulo a composite, which is as hard as factoring —
unless `g` shares a factor with... nothing helpful here. Fixing the challenge
into an unsolvable one is as easy as making the flag longer, which is worth
remembering when you set the parameters.

**Flag:** `THJCC{n0t_c0pr1m3_but_st1ll_br0k3n_4nyw4y}`
