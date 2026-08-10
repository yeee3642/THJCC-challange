# the gauntlet  🎰

**Category:** Reverse Engineering
**Difficulty:** Medium-Hard
**Points (suggested):** 250
**Arch:** ARM aarch64 ELF (stripped). Non-aarch64 players need `qemu-user` /
binfmt to run it — the flag is recoverable by static analysis alone either way.

We built a little machine to guard one flag. It has its own instruction set, its
own keystream, and a short memory of what it just did. It also doesn't feel like
showing you any of that up front.

```
$ ./vmcheck
flag> guess
nope.
```

The accepted input **is** the flag, in the form `THJCC{...}`.

## Files given to players
- `vmcheck` — 64-bit ELF binary, stripped

## What you're up against
- **Nothing is plaintext.** The bytecode and the expected ciphertext are both
  stored obfuscated. Grep for them and you'll find nothing; you have to locate
  the routine that unmasks them at startup and replay it yourself.
- **It bites back under a debugger.** Attaching doesn't fail loudly — the
  program keeps running and rejects *everything*, including the real flag, with
  no error and no hint that anything is different. Breakpointing the unmask
  routine to dump the arrays gets you correctly-sized garbage.
- **No symbols.** The binary is stripped. Find the interpreter by shape, not by
  name.
- **You must recover an instruction set** before you know what is being
  computed, and the dispatch is not a table of pointers.
- **The check is stateful.** Two registers persist across characters, so the
  transform applied to a character depends on more than that character.
  Attacking the 44 positions independently, in parallel, will not work — you get
  one character and then noise.

## Goal
Recover the flag and run `./vmcheck` to see `correct! that flag is the flag.`
