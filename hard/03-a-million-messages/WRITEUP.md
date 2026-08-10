# A Million Messages — writeup

**Category:** crypto (hard) · **Attack:** Bleichenbacher's adaptive chosen-ciphertext attack on PKCS#1 v1.5 (CRYPTO '98)

## The setup

RSA-512, `e = 65537`, the flag PKCS#1 v1.5 type-2 padded and encrypted. The
service answers one bit per query: does the ciphertext you sent decrypt to
something starting with `00 02`?

No plaintext is ever returned. The claim in the README — "there is nothing to
leak" — is the classic mistake.

## What the oracle actually says

With `k = 64` bytes and `B = 2^(8(k−2))`, a conforming plaintext starts with
`00 02`, which means precisely

```
2B ≤ m < 3B
```

`m` is confined to an interval that is `1/256` of the modulus wide. RSA is
multiplicatively homomorphic:

```
(c · s^e)^d = m · s   (mod n)
```

So for a multiplier `s` of our choice, an `OK` answer tells us

```
2B ≤ m·s − r·n < 3B      for some integer r
⟺  (2B + r·n)/s ≤ m < (3B + r·n)/s
```

Every `OK` intersects our candidate set with a shifted, scaled copy of
`[2B, 3B)`. Intersect enough of them and the set collapses to a point.

## The algorithm

The given ciphertext is already conforming, so `s0 = 1` and the blinding step
is skipped. Start with `M = {[2B, 3B−1]}`.

**Step 2a — first multiplier.** Search upward from `s = ⌈n / 3B⌉` until the
oracle says `OK`. This is the expensive part: about **27 000 queries**, since
roughly 1 in 2^16 multipliers conforms.

**Step 3 — narrow.** For each interval `[a, b]` and each

```
r ∈ [ ⌈(a·s − 3B + 1)/n⌉ , ⌊(b·s − 2B)/n⌋ ]
```

produce

```
[ max(a, ⌈(2B + r·n)/s⌉) , min(b, ⌊(3B − 1 + r·n)/s⌋) ]
```

and keep the non-empty ones.

**Step 2b — several intervals left.** Just keep incrementing `s` until the next
`OK`.

**Step 2c — one interval left.** Stop searching blindly and jump to the
multipliers that can possibly work:

```
r  = ⌈2(b·s_prev − 2B) / n⌉
s ∈ [ ⌈(2B + r·n)/b⌉ , ⌈(3B + r·n)/a⌉ )    , increment r when exhausted
```

This is what makes the attack practical: after the first hit, each additional
`OK` roughly **halves the interval**, so the remaining ~480 rounds cost only
about 20 queries each.

**Step 4.** When a single interval has `a == b`, that value is `m`.

## Observed cost

A representative run — the server generates a fresh RSA key per connection, so
the exact counts move by a few thousand:

```
[*] round  10  intervals=  1  width~2^471  queries=27153
[*] round 100  intervals=  1  width~2^381  queries=27303
[*] round 300  intervals=  1  width~2^181  queries=27741
[*] round 480  intervals=  1  width~2^1    queries=28084
[*] recovered padded plaintext after 28084 queries
[+] THJCC{bl31chenb4ch3r_st1ll_3ats_pkcs1_v1_5}
```

**28 084 queries, ~14 s.** Note the shape: 27 153 of them are spent finding the
*first* `s`, and the entire 471-bit narrowing costs under a thousand. Players
who instrument their solver see this immediately and stop trying to optimise
the wrong loop.

## Implementation notes

* Do all ceilings with integers: `ceil_div(a, b) = -(-a // b)`. A float
  `ceil()` on 512-bit values is wrong and the failure is silent — the interval
  set goes empty ten rounds later and you debug the wrong step.
* Off-by-one in the step-3 `r` range is the most common bug. The bounds come
  from `2B ≤ m·s − r·n ≤ 3B − 1`; derive them, do not copy them.
* Deduplicate intervals (a `set`), otherwise the list grows and step 3 slows
  down for no reason.
* Assert that the original `c` conforms before you start; if it does not, you
  need the blinding step (step 1) first.

## Fix

The oracle exists whenever padding failure is distinguishable from any other
failure — different error message, different status code, different timing.
The v1.5 standard's own mitigation is to generate a random plaintext on
padding failure and continue, so the caller cannot tell. The real fix is
RSA-OAEP, or not using RSA encryption at all. Twenty-eight years on, this bug
keeps returning: ROBOT (2017) found it in F5, Citrix and Cisco stacks, and the
Marvin attack (2023) found the timing variant across most major TLS libraries.

**Flag:** `THJCC{bl31chenb4ch3r_st1ll_3ats_pkcs1_v1_5}`
