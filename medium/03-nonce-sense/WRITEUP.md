# Nonce Sense — writeup

**Category:** crypto (medium) · **Attack:** ECDSA nonce reuse (PS3 / Android Bitcoin wallet class)

## The setup

secp256k1 + SHA-256. On connect the server publishes its public key `Q`, two
signatures over two *different* messages, and a target message. Produce a valid
signature over the target and you get the flag. The private key is never sent.

The bug is in the README's own words: the per-session randomness is drawn once,
when the connection opens, and reused for both signatures.

## Spotting it

ECDSA signing is

```
r = (k·G).x mod n
s = k^{-1} (h + r·d) mod n
```

`r` depends only on `k`. **Two signatures with the same `r` means the same
`k`.** That is visible directly in the transcript — no analysis needed:

```
SIG <msg1> r=0x919f45… s=…
SIG <msg2> r=0x919f45… s=…      ← same r
```

## Recovering the key

With one `k` and two hashes:

```
s1 = k^{-1}(h1 + r·d)
s2 = k^{-1}(h2 + r·d)
```

Subtract — the `r·d` term cancels:

```
s1 − s2 = k^{-1}(h1 − h2)
k = (h1 − h2) · (s1 − s2)^{-1}   (mod n)
```

and then back-substitute into either equation:

```
d = (s1·k − h1) · r^{-1}   (mod n)
```

Everything is arithmetic mod `n`; no curve operations are needed for the
recovery itself, only for verification.

## The sign trap

Some implementations normalise `s` to the lower half of the range (BIP-62 /
low-S), which is equivalent to having used `n − k`. If `d·G ≠ Q`, retry with
`k ← n − k` and recompute `d`. The reference solution just tries both and
checks against the published `Q`:

```python
if mul(d, G) != Q:
    k = N - k
    d = (s1 * k - h1) * pow(r1, -1, N) % N
assert mul(d, G) == Q
```

## Finishing

Knowing `d` is not the win condition — the server wants a signature over
`admin=true;action=release_flag`. Sign it normally, with a nonce of your own
(a fresh random one; reusing the leaked `k` would work too, but let us not
repeat the mistake we are exploiting).

## Why this keeps happening in the wild

Real cases: Sony PS3 (2010, fixed `k` in the firmware signer), the Android
`SecureRandom` bug that drained Bitcoin wallets (2013), and a long tail of
hardware wallets with weak TRNGs. The defence is deterministic nonces —
RFC 6979 derives `k = HMAC-DRBG(d, h)`, so the same message and key always give
the same `k` and two different messages can never collide.

**Flag:** `THJCC{n3v3r_3v3r_r3us3_th3_s4m3_n0nc3}`
