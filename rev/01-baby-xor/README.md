# baby-xor  🍼

**Category:** Reverse Engineering
**Difficulty:** Easy
**Points (suggested):** 100

A licensing check stands between you and the flag. Take it apart.

```
$ ./baby
license key> hello
[-] denied
```

The correct license key **is** the flag, in the form `THJCC{...}`.

## Files given to players
- `baby` — 64-bit ELF binary

## Hints
1. `strings` won't just hand you the flag — but not everything is hidden.
2. The comparison is byte-for-byte. What is each of your bytes compared *against*?
3. `objdump -s -j .rodata baby` shows two interesting blobs.

## Goal
Recover the flag and run `./baby` to see `[+] access granted`.
