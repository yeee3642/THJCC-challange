# Lattice of Doom — writeup

**Category:** crypto (hard) · **Attack:** Hidden Number Problem via LLL (Boneh–Venkatesan; "Minerva" / "LadderLeak" class)

## The setup

`output.json` has a secp256k1 public key, 60 ECDSA signatures, and the flag
encrypted under a key derived from the private scalar. `signer_excerpt.py` is
the leaked firmware:

```python
NONCE_BYTES = 29

def make_nonce(trng):
    return int.from_bytes(trng.read(NONCE_BYTES), "big")
```

29 bytes is 232 bits. secp256k1's order is 256 bits. **Every nonce is missing
its top 24 bits** — they are all zero. The firmware comment ("10^69
possibilities, more atoms than the universe") is the trap: brute force is
hopeless and irrelevant, because the leak is structural, not a size problem.

## From ECDSA to the Hidden Number Problem

```
s·k = h + r·d   (mod n)
k   = h/s + (r/s)·d   (mod n)
```

Set `a_i = h_i·s_i^{-1} mod n` and `b_i = r_i·s_i^{-1} mod n`, both public:

```
k_i = a_i + b_i·d   (mod n),      0 < k_i < K = 2^232
```

One hidden value `d`, many public affine relations, each producing a result
that is *small*. That is exactly the Hidden Number Problem. Each signature
contributes 24 bits of information about a 256-bit secret, so ~11 signatures
are information-theoretically enough; take 24 for comfort.

## The lattice

Build the `(M+2)`-dimensional lattice spanned by the rows

```
        n·e_0
        n·e_1
          ⋮
        n·e_{M-1}
        ( b_0, b_1, …, b_{M-1},  K/n,  0 )
        ( a_0, a_1, …, a_{M-1},   0,   K )
```

Take `d` times the second-to-last row, plus 1 times the last row, and subtract
the right multiples of the `n·e_i` rows to reduce each coordinate mod `n`. The
result is a lattice vector:

```
v = ( k_0, k_1, …, k_{M-1},  d·K/n,  K )
```

Every coordinate is bounded by `K = 2^232`, whereas generic lattice vectors
here are much longer. Quantitatively, with `M = 24` (dimension 26):

```
det(L)          = n^(M-1) · K^2                    ≈ 2^6352
Gaussian heur.  = det^(1/26)                       ≈ 2^244.3
‖v‖             ≈ K·√26                            ≈ 2^234.4
```

The target is about `2^10` shorter than anything the lattice should contain by
chance, comfortably beyond LLL's `2^((n-1)/4) ≈ 2^6.3` approximation factor.
LLL will return it.

To keep everything in integers, multiply the whole basis by `n` — the `K/n`
entry becomes `K` and the rest scales accordingly. Ratios are unchanged.

## Reading off the key

Scan the reduced basis for a row whose last coordinate is `±n·K` (that is the
`1·(last row)` component, so the row is `±v`). Then

```
d = row[M] // K   mod n
```

Verify with `d·G == Q` before trusting it. As a fallback, the first coordinate
gives `k_0` directly, and `d = (s_0·k_0 − h_0)·r_0^{-1} mod n` — useful when
sign handling gets confusing. The reference solution tries both, for both
signs, over every row.

Then derive the AES key exactly as the generator documents in `output.json`
and decrypt the flag.

## Writing LLL without fpylll

No Sage, no fpylll, no numpy — so the solution ships a textbook LLL
(Cohen, *A Course in Computational Algebraic Number Theory*, algorithm 2.6.3)
with exact `Fraction` Gram–Schmidt. Two details make it fast enough:

* Compute the initial Gram–Schmidt from the **Gram matrix**, using
  `μ_ij = (G_ij − Σ_{t<j} μ_jt μ_it B_t) / B_j`. That is `O(n^3)` scalar
  rational operations instead of `O(n^3)` big-vector operations.
* Never recompute Gram–Schmidt after a swap. Use the standard rank-1 update
  for `μ` and `B`; recomputing from scratch on every swap is what makes naive
  pure-Python LLL unusable.

Rounding must be exact too — use `(2·num + den) // (2·den)` rather than
converting a 500-bit rational to a float.

Dimension 26 reduces in **~7 s**. With fpylll you would push `M` to 40+ and use
smaller biases.

```
[*] reducing a 26x26 lattice (24 signatures, 232-bit nonces)
[+] private key d = 0xa808ed16f3523aa75d754fef34d4247f4eebbc33ba38729e0c151149f7bb37a2
[+] THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}
```

## Tuning knobs for organisers

* Fewer leaked bits (e.g. 31-byte nonces = 8 bits of bias) needs `M ≈ 40+` and
  usually BKZ — a serious step up in difficulty.
* Reducing the signature count below `256 / bias` makes it unsolvable, not
  hard. Keep a healthy margin.
* Real-world equivalents: Minerva (2019) and LadderLeak (2020) recovered keys
  from **3–5 bits** of nonce bias leaked through timing.

**Flag:** `THJCC{l4tt1c3s_turn_b14s3d_n0nc3s_1nt0_pr1v4t3_k3ys}`
