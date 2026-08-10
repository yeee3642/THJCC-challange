# Oracle of Padding — writeup

**Category:** crypto (medium) · **Attack:** CBC padding oracle (Vaudenay, 2002)

## The setup

The service hands out `IV ‖ C1 ‖ C2 ‖ …` (AES-128-CBC, PKCS#7) and then answers
`OK` / `BAD` for any blob you send, based only on whether unpadding succeeded.
It never returns plaintext. That single bit is enough.

## The mechanism

CBC decryption is

```
P_i = D_k(C_i) XOR C_{i-1}
```

`D_k(C_i)` is fixed once the ciphertext is fixed, and `C_{i-1}` is *entirely
under our control* if we send our own two-block message:

```
send:  X ‖ C_i          →  the server computes  D_k(C_i) XOR X  and checks its padding
```

So we are not attacking AES at all. We are searching for `X` values that make
`D_k(C_i) XOR X` end in valid PKCS#7, which pins down `D_k(C_i)` byte by byte.

## Byte at a time

Write `I = D_k(C_i)` (the "intermediate" block).

1. Vary `X[15]` over all 256 values. On success the last plaintext byte is
   almost always `0x01`, so `I[15] = X[15] XOR 0x01`.
2. Knowing `I[15]`, force the last byte to `0x02` by setting
   `X[15] = I[15] XOR 0x02`, then vary `X[14]`. Success means
   `I[14] = X[14] XOR 0x02`.
3. Continue for padding values `0x03 … 0x10`.

Then the real plaintext is `P_i = I XOR C_{i-1}` using the *genuine* previous
block.

## The trap everybody hits

Step 1 has a false positive. If the plaintext tail happens to be `… 0x02 0x02`
or `… 0x03 0x03 0x03`, the padding is also valid and you will record the wrong
`I[15]`. It shows up as a first block that decrypts to junk while everything
else looks fine.

Disambiguate by perturbing the second-to-last byte and re-asking:

```python
if pos == 15:
    probe = bytearray(forged)
    probe[14] ^= 0xFF
    if not oracle.valid(bytes(probe) + block):
        continue          # padding was longer than one byte -> wrong guess
```

If the padding really was a single `0x01`, byte 14 is irrelevant and the
oracle still says `OK`. If it was `0x02 0x02`, breaking byte 14 breaks the
padding.

## Cost

At most 256 queries per byte, 16 bytes per block, 6 blocks. The reference
solution lands around **12 000–12 600 queries** (it varies with the random
key), well inside the 200 000 budget, and finishes in under a second against a
local pipe.

```
[*] block 1/6: b'{"user":"guest",'
[*] block 2/6: b'"admin":false,"n'
[*] block 3/6: b'ote":"THJCC{p4dd'
[*] block 4/6: b'1ng_0r4cl3s_l34k'
[*] block 5/6: b'_0n3_byt3_p3r_qu'
[*] block 6/6: b'3ry}"}\n\n\n\n\n\n\n\n\n\n'
[*] 12130 oracle queries
```

Note block 6: the PKCS#7 padding (`\n` = `0x0a`, ten times) is recovered as
plaintext like everything else and must be stripped.

## Fix

Do not distinguish padding failures from MAC failures — encrypt-then-MAC and
reject on the MAC before you ever look at the padding. Constant-time unpadding
alone does not help if the error is observable at all (including via timing or
via a different HTTP status).

**Flag:** `THJCC{p4dd1ng_0r4cl3s_l34k_0n3_byt3_p3r_qu3ry}`
