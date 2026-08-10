# THJCC — Crypto & Reversing Challenges

Eight original challenges: six **crypto** (three medium, three hard) and two
**reversing** (one easy, one medium-hard). Every one has a working reference
solution that runs end to end in pure Python.

Flag format: `THJCC{...}`

## The set

### Crypto

| # | Challenge | Difficulty | Technique | Format | Ref. solve time | Writeup |
|---|-----------|-----------|-----------|--------|-----------------|---------|
| 1 | [Two Exponents](medium/01-two-exponents) | medium | RSA common modulus where `gcd(e1,e2) = 3` → Bézout + integer cube root | file | < 1 s | [↗](medium/01-two-exponents/WRITEUP.md) |
| 2 | [Oracle of Padding](medium/02-oracle-of-padding) | medium | CBC padding oracle (Vaudenay) | service | < 1 s, ~12k queries | [↗](medium/02-oracle-of-padding/WRITEUP.md) |
| 3 | [Nonce Sense](medium/03-nonce-sense) | medium | ECDSA nonce reuse → key recovery → forgery | service | < 1 s | [↗](medium/03-nonce-sense/WRITEUP.md) |
| 4 | [Forbidden](hard/01-forbidden) | hard | AES-GCM nonce reuse → GHASH root-finding in GF(2^128) → tag forgery | service | ~1 s | [↗](hard/01-forbidden/WRITEUP.md) |
| 5 | [Lattice of Doom](hard/02-lattice-of-doom) | hard | Biased ECDSA nonces → Hidden Number Problem → LLL | file | ~7 s | [↗](hard/02-lattice-of-doom/WRITEUP.md) |
| 6 | [A Million Messages](hard/03-a-million-messages) | hard | Bleichenbacher PKCS#1 v1.5 padding oracle | service | ~14 s, ~28k queries | [↗](hard/03-a-million-messages/WRITEUP.md) |

### Reversing

| # | Challenge | Difficulty | Technique | Format | Ref. solve time | Writeup |
|---|-----------|-----------|-----------|--------|-----------------|---------|
| 7 | [baby-xor](rev/01-baby-xor) | easy | repeating-key XOR recovered from `.rodata` | binary | < 1 s | [↗](rev/01-baby-xor/WRITEUP.md) |
| 8 | [the gauntlet](rev/02-the-gauntlet) | medium-hard | stripped + anti-debug stack VM: recover the ISA, replay an LCG keystream, invert a mod-256 multiply and a feedback chain | binary | < 1 s | [↗](rev/02-the-gauntlet/WRITEUP.md) |

The three "hard" crypto ones each need a primitive that no Python standard library
gives you — GF(2^128) polynomial root finding, an LLL implementation, and a
correct interval-narrowing loop. Solving them by pasting a one-liner from a
writeup will not work; the reference solutions build those primitives from
scratch and are readable on purpose.

## Difficulty design

Each medium challenge is one textbook attack with exactly one twist that
punishes copy-pasting the standard script:

* **Two Exponents** — the usual common-modulus script assumes coprime
  exponents and silently produces garbage here. You recover `m^3`, not `m`,
  and the generator guarantees `m^3 < n` so the integer cube root closes it.
* **Oracle of Padding** — plain Vaudenay, but the last-byte false positive
  (`0x02 0x02` masquerading as `0x01`) must be handled or the first block
  decodes wrong.
* **Nonce Sense** — the key is not the goal; you must *use* it to forge a
  signature over a message the server chooses.

The hard ones are full papers-turned-code: Joux's forbidden attack,
Boneh–Venkatesan HNP, and Bleichenbacher '98.

The two reversing challenges are a deliberate pair — the same shape (find the
comparison, identify the transform, invert it) at two very different scales:

* **baby-xor** — repeating 3-byte XOR, key sitting in `.rodata`. XOR is
  self-inverse, so "invert it" is free. This is the on-ramp.
* **the gauntlet** — the same idea buried under six layers: `ptrace` anti-debug
  that silently corrupts the unmask key, obfuscated bytecode and ciphertext
  (nothing greppable), a stripped binary, a stack-VM ISA that must be recovered
  from a signed-offset jump table, a keystream LCG, a multiply that needs a
  modular inverse rather than another XOR, and a feedback register keyed on the
  *input* byte so the 44 positions cannot be attacked in parallel.

Both were validated by independent blind solvers who received only the binary
and the player README — see the reversing writeups, which record what review
caught (including two false claims and one memory-safety bug in earlier drafts).

## Running

Requires Python 3.9+ and `pycryptodome` (`pip install pycryptodome`). Nothing
else — no Sage, no fpylll, no gmpy2.

```bash
./run_all.sh              # generate everything and run all eight solutions
```

The reversing solutions need no dependencies at all — they recover the flag by
static inversion and only touch the binary for an optional self-check. Rebuilding
those two binaries needs `gcc`:

```bash
cd rev
python3 gen.py                                            # regenerate both .c files
gcc -O1    -o 01-baby-xor/baby        01-baby-xor/baby.c
gcc -O1 -s -o 02-the-gauntlet/vmcheck 02-the-gauntlet/vmcheck.c   # -s is required
python3 gen.py --dist                                     # rev/dist/ = hand-out tree
```

`-s` on the gauntlet is part of the difficulty: without it the binary ships with
symbol names that give the whole design away. Changing either flag in `gen.py`
regenerates the embedded ciphertext automatically, but the hex blobs pasted into
the two `solve.py` files must then be refreshed from `objdump` to match.

**The committed reversing binaries are ARM aarch64.** Players on x86_64 need
`qemu-user`/binfmt to run them, though the flags are recoverable by static
analysis on any host. To hand out x86_64 binaries, rebuild on an x86_64 machine.

Individual challenge:

```bash
cd hard/02-lattice-of-doom
python3 generate.py       # author only, refreshes output.json
python3 solve.py
```

The service-style challenges speak a line protocol on stdin/stdout, so they
drop straight into a socket wrapper:

```bash
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 server.py"
```

Ports used in the READMEs: 1337 padding oracle, 1338 nonce sense,
1339 forbidden, 1340 million messages.

## What to hand out vs. what to keep

| Give to players | Keep private |
|-----------------|--------------|
| `README.md` of each challenge | `solve.py` |
| `output.txt` / `output.json` | `generate.py` / `rev/gen.py` (contains the flags) |
| `server.py` — *only* where the README says the source is public | `WRITEUP.md` (release after the event) |
| `baby` / `vmcheck` — the compiled binaries only | `baby.c` / `vmcheck.c` |

For the reversing pair, `python3 rev/gen.py --dist` writes `rev/dist/<chal>/`
containing exactly the binary plus the player README, which is the safe thing to
upload. Never hand out a reversing challenge directory as-is: the `.c` source
next to the binary contains the flag in plaintext.

For `Lattice of Doom` also hand out `signer_excerpt.py`: the bias is meant to
be discoverable from the leaked firmware snippet, not guessed.

For the service challenges the flag is read from the `FLAG` environment
variable, so deployment does not need a source edit:

```bash
FLAG='THJCC{...}' socat TCP-LISTEN:1339,reuseaddr,fork EXEC:"python3 server.py"
```

## Deployment notes

* Every server is one-shot or short-lived per connection and holds no global
  state, so `socat ... ,fork` is enough. Each connection generates its own key.
* `Nonce Sense` and `Forbidden` mint a fresh key per connection — players
  cannot pool data across connections, which is intended.
* `A Million Messages` needs ~28k round trips. Give it a generous
  per-connection timeout (5 min+) and do not rate-limit below ~2k req/s or the
  intended solution stops being practical.
* Query budgets are enforced in-process (`MAX_QUERIES` / `MAX_TRIES`).

For the reversing pair (download-and-submit, no service needed):

* `the gauntlet` calls `ptrace(PTRACE_TRACEME)` and rejects everything if that
  indicates a tracer. `ENOSYS` is deliberately excluded so **qemu-user players
  are not punished**, but a sandbox that denies `ptrace` with `EPERM` would make
  the binary reject even the correct flag. Test in the environment you serve
  from; if `ptrace` is restricted, drop the anti-debug in `rev/gen.py` and
  rebuild.
* Do not serve `the gauntlet` over `nc`/xinetd without testing first: when
  `PTRACE_TRACEME` succeeds the parent becomes the tracer, so a child that then
  takes a signal enters signal-delivery-stop and waits for a tracer that never
  continues it — a hang rather than an exit.
