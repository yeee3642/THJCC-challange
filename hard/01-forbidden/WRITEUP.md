# Forbidden — writeup

**Category:** crypto (hard) · **Attack:** the "forbidden attack" on AES-GCM with a repeated nonce (Joux; Böck–Zauner–Devlin–Somorovsky 2016)

## The setup

The server publishes three notices, each AES-128-GCM encrypted **under the same
key and the same nonce**, and gives you the plaintexts. You must produce a
`(ciphertext, tag)` pair that authenticates to `give me the flag` under that
same nonce.

Confidentiality is already gone the moment the nonce repeats (XOR two
ciphertexts and the keystream cancels). This challenge is about the other half:
**forging the authentication tag**, which needs the GHASH key.

## GCM in one equation

For a 96-bit nonce:

```
H     = E_K(0^128)                     the authentication key
J0    = nonce ‖ 0^31 ‖ 1
T     = GHASH_H(A, C) XOR E_K(J0)
```

and GHASH is *polynomial evaluation* over GF(2^128). With blocks
`b_1 … b_nb` (AAD blocks, then ciphertext blocks, then the 128-bit length
block):

```
GHASH_H(C) = Σ_{i=1..nb}  b_i · H^(nb − i + 1)
```

Everything in that sum is public except `H`.

## Cancelling the mask

Same nonce ⟹ same `J0` ⟹ **the same `E_K(J0)` in every tag**. XOR two tags and
it vanishes:

```
T1 XOR T2 = GHASH_H(C1) XOR GHASH_H(C2)
```

Move everything to one side and you have a polynomial with known coefficients
whose unknown is `H`:

```
P(x) = GHASH-poly(C1)(x) + GHASH-poly(C2)(x) + (T1 XOR T2)   ,   P(H) = 0
```

Note the design choice: the three notices have **different lengths** (50, 15
and 58 bytes). If two messages have equal length, the length blocks cancel and
`P` degenerates to something you can solve by a single division — no root
finding, and the challenge would be a medium. With different lengths `P` has
degree 5 here and must actually be factored.

## Root finding in GF(2^128)

No Python library does this, so you build it:

1. **Field arithmetic.** GCM uses the *bit-reflected* convention: in the
   128-bit integer, the **most significant** bit is the `x^0` coefficient, and
   the reduction polynomial is `x^128 + x^7 + x^2 + x + 1`, encoded as
   `R = 0xE1 << 120`.

   ```python
   def gmul(x, y):
       z, v = 0, y
       for i in range(128):
           if (x >> (127 - i)) & 1: z ^= v
           v = (v >> 1) ^ R if v & 1 else v >> 1
       return z
   ```

   **This is where the reference solution first broke.** The multiplicative
   identity is *not* the integer `1` — it is `1 << 127`. Every place that
   writes a monic polynomial, computes an inverse (`a^(2^128−2)`), or
   constructs the polynomial `x` must use that. With `1` as the identity the
   gcd step returns a constant and you get "0 roots" from a polynomial that
   definitely has one.

2. **Keep only the roots.** Every element of GF(2^128) satisfies
   `x^(2^128) = x`, so

   ```
   g = gcd(P(x), x^(2^128) − x)
   ```

   is the product of the distinct linear factors of `P`. Compute `x^(2^128) mod P`
   by 128 successive squarings. Squaring is cheap and linear in characteristic
   2: `(Σ c_i x^i)^2 = Σ c_i^2 x^(2i)`.

3. **Split `g`.** Equal-degree splitting with the trace map. For random `α`,

   ```
   Tr(y) = Σ_{i=0..127} y^(2^i)   ∈ {0, 1}
   h = gcd(g, Tr(α·x))
   ```

   separates the roots where `Tr(α·r) = 0` from the rest. Recurse on `h` and
   `g/h` until every factor is linear; a monic `x + c` has root `c`.

`P` has degree 5 here (the longest notice is 4 blocks, plus the length block).
How many of its roots live in the field varies with the key — typically 1 or 2.

## Picking the right root, then forging

Use the third notice as a filter. For each candidate `H`:

```
E_K(J0) = T1 XOR GHASH_H(C1)
check:    T3 == GHASH_H(C3) XOR E_K(J0)
```

Only the true `H` survives. Now you hold both secrets of the tag equation and
can authenticate anything.

For the ciphertext itself, the repeated nonce means the repeated keystream:

```
keystream = P1 XOR C1                    (first notice, known plaintext)
C*        = target XOR keystream[:len(target)]
T*        = GHASH_H(C*) XOR E_K(J0)
```

Submit `C* ‖ T*`. The target is exactly 16 bytes, and notice 1 is 50 bytes, so
there is plenty of keystream.

A sample run (the server mints a fresh key and nonce per connection, so `H` and
`E(J0)` differ every time):

```
[*] polynomial in H has degree 5
[*] 2 root(s) in GF(2^128)
[*] H     = fc1ad1cb700de771b10d4b13c78a5e8e
[*] E(J0) = 892f02e08a00d68d6b77bc6e577bf792
[+] FLAG THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}
```

Total runtime: ~1 second, pure Python.

## Why it is called "forbidden"

The GCM spec forbids nonce reuse in capital letters, and this is the reason:
a single repeat does not merely leak plaintext, it hands over the
authentication key permanently — every future message under that key can be
forged. The 2016 survey found this live on public HTTPS servers with broken
nonce generators. Use XChaCha20-Poly1305, or AES-GCM-SIV, or a strictly
increasing counter nonce that you never let wrap.

**Flag:** `THJCC{h_r3c0v3r3d_gcm_1s_f0rb1dd3n_w1th0ut_fr3sh_n0nc3s}`
