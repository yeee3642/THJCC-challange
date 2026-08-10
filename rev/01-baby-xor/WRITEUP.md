# baby-xor — Author Writeup

**Flag:** `THJCC{x0r_15_th3_cl4ss1c_st4rt3r}`

## The check
Decompiled, `main` does:

```c
if (strlen(buf) != 33) { puts("[-] wrong length"); return 1; }
for (i = 0; i < 33; i++)
    if ((buf[i] ^ key[i % 3]) != enc[i]) { puts("[-] denied"); return 1; }
puts("[+] access granted");
```

So `enc[i] == input[i] ^ key[i%3]`, which means `flag[i] = enc[i] ^ key[i%3]`.
A repeating 3-byte XOR — the classic beginner primitive.

## Extracting the material
```
$ strings baby | grep -x r3v
r3v                                   # the key

$ objdump -s -j .rodata baby | tail -3
 0b68 267b3c31 700d0a03 042d0243 2d471e41  &{<1p....-.C-G.A
 0b78 6c151e07 05010215 2d400246 41024141  l.......-@.FA.AA
 0b88 0b                                   .
```

`enc[] = 26 7b 3c 31 70 0d 0a 03 ... 41 02 41 41 0b` (33 bytes),
`key = "r3v"`.

## Recover
```python
enc = bytes.fromhex("267b3c31700d0a03042d02432d471e416c151e07050102152d400246410241410b")
key = b"r3v"
print(bytes(enc[i] ^ key[i%3] for i in range(len(enc))).decode())
# THJCC{x0r_15_th3_cl4ss1c_st4rt3r}
```

Full self-verifying script: [`solve.py`](solve.py) — it recovers the flag and
pipes it back into `./baby` to confirm `[+] access granted`.

## Teaching point
Introduces the loop that defines every rev challenge: **find the comparison,
identify the transform, invert it.** XOR is self-inverse, so "invert" is trivial
here — which is exactly why it's the right first challenge.
