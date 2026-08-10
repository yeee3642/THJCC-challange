# the gauntlet — Author Writeup

**Flag:** `THJCC{st4ck_vm_1nv_mul_1dx_f33db4ck_ch41n3d}`

The binary is stripped, anti-debugged, and both data arrays are obfuscated, so
there are six layers to peel: anti-debug → deobfuscation → VM ISA → LCG
keystream → modular inverse → sequential feedback chaining.

## 1. Get past the anti-debug
`main` calls `ptrace(PTRACE_TRACEME, 0, 0, 0)` before anything else. If a
debugger already holds the process, that call returns `-1` and the result feeds
straight into the unmask key:

```c
adj = (ptrace(PTRACE_TRACEME,0,0,0) < 0) ? 0x7f : 0x00;
unveil(code, sizeof code, adj);
unveil(target, sizeof target, adj);
```

So under gdb the arrays unmask to garbage and the binary rejects *everything*,
including the real flag — with no error message. The obvious "break after
`unveil` and dump `.data`" shortcut yields nothing. Solve statically, or NOP the
ptrace call / force its return to 0 first.

Two deliberate details:

- The unmask loops terminate on a rolling-key sentinel rather than a length
  counter, and `adj` cancels out of that congruence — so the arrays are 18 and
  44 bytes on *both* paths. A player who breakpoints the deobfuscator gets
  correctly-sized garbage, which looks plausible enough to cost real time.
- `ENOSYS` is excluded from the check. qemu-user does not implement `ptrace`,
  and punishing cross-architecture players for that would break the challenge
  for everyone not on aarch64.

## 2. Unmask the data
`unveil` XORs an array in place with a *computed* key (no key blob to grep):

```c
unveil(p, n, adj):  p[i] ^= (i * 0x9d + 0x2f + adj) & 0xff
```

| array      | offset    | size |
|------------|-----------|------|
| `code[]`   | `0x20010` | 18   |
| `target[]` | `0x20028` | 44   |
| `lcg` seed | `0x20054` | 4 (`0x00C0FFEE`, stored `ee ff c0 00`) |
| `prev`     | `0x20058` | 1 (`0x5a`) |

Note the loops carry no length constant — the byte count is implied by the
terminator compare on the rolling key, so you recover it by replaying the key
sequence.

Deobfuscated bytecode:

```
12 13 20 10 4d 23 14 20 11 21 24 03 10 3b 20 32 31 ff
```

## 3. Recover the ISA
A `switch` inside `for(;;)` over `code[]` with an instruction pointer and a
stack — a stack machine, run once per input character. On aarch64 gcc compiles
the dispatch to a computed goto: a table of **signed byte offsets scaled by 4**
from a base label (`adr xN, base` + `add x0, xN, w0, sxtb #2`), *not* a pointer
table. Misreading the sign extension or the ×4 silently yields a plausible but
wrong opcode map — this is the step most solvers report as hardest.

| op   | mnemonic     | effect                              |
|------|--------------|-------------------------------------|
| 0x10 | PUSH_IMM     | push next code byte                 |
| 0x11 | PUSH_IDX     | push current character index        |
| 0x12 | PUSH_INP     | push current input byte             |
| 0x13 | PUSH_KS      | push next keystream byte (adv. LCG) |
| 0x14 | PUSH_PREV    | push `prev` register                |
| 0x20 | XOR          | `b ^ a`                             |
| 0x21 | ADD          | `(b + a) & 0xff`                    |
| 0x23 | MUL          | `(b * a) & 0xff`                    |
| 0x24 | ROL n        | rotate-left top by `n`              |
| 0x32 | SETPREV_INP  | `prev = input byte` (no stack effect) |
| 0x31 | OUT          | return `pop()`                      |
| 0xff | HALT         | stop                                |

(`SUB` 0x22, `ROR` 0x25 and `SETPREV` 0x30 are implemented but unused — decoys.)

## 4. Read the program
```
PUSH_INP ; PUSH_KS ; XOR        t = in[i] ^ ks[i]
PUSH_IMM 0x4d ; MUL             t = (t * 0x4d) & 0xff
PUSH_PREV ; XOR                 t ^= prev            (OLD prev consumed here)
PUSH_IDX ; ADD                  t = (t + i) & 0xff
ROL 3                           t = rol(t, 3)
PUSH_IMM 0x3b ; XOR             t ^= 0x3b
SETPREV_INP                     prev = in[i]         (feedback, INPUT-keyed)
OUT                             out[i] = t
```

Forward cipher:

```
out[i] = rol((((in[i] ^ ks[i]) * 0x4d) ^ prev_i) + i, 3) ^ 0x3b
prev_0 = 0x5a ,  prev_{i+1} = in[i]
```

**The feedback is keyed on the plaintext, not the ciphertext.** `prev_i` is
therefore not present anywhere in `target[]`, which kills byte-independent
attack: guessing all 256 values at every position in parallel yields one correct
character (position 0, where the seed is known) and noise thereafter.

Be precise about what this does *not* buy, though — reviewers refuted the
stronger claim I originally made here:

- The transform is bijective in `prev` as well as in `c`, so the chain runs
  **both directions**. A single known trailing byte — and the `THJCC{...}` format
  guarantees a trailing `}` — peels the whole flag right-to-left without ever
  using the `0x5a` seed.
- Chain depth is only **1**: `prev_i` depends solely on `c_{i-1}`, so any one
  known byte unlocks its neighbour in O(1). The known `THJCC{` header hands you
  positions 1..6 free.
- Worse, `prev_i == c_{i-1}` is a *consistency constraint* linking adjacent
  positions, so the entire 44-byte candidate space is parameterized by `c_0`
  alone — 256 strings, of which exactly one is printable ASCII. An attacker with
  no known plaintext at all still finishes in 256 tries.

So the honest statement is "no parallel/byte-independent attack", worth about
8 bits — not "strictly sequential". Giving the feedback real depth (mixing in
`prev` *and* `prev2`, or making it a running accumulator over all prior input)
would be the fix if that property needs to carry weight.

## 5. Keystream
Deliberately **not** the glibc constants:

```
lcg = lcg * 0x6D2B79F5 + 0x9E3779B9  (mod 2^32)   seed 0x00C0FFEE
ks  = (lcg >> 24) & 0xff                           (one advance per character)
```

## 6. Invert
`0x4d` is odd, hence invertible mod 256: `0x4d⁻¹ = 0x85` (`pow(0x4d,-1,256)`).
Undo every step in reverse, carrying the feedback forward:

```
t = c ^ 0x3b          # undo ^= 0x3b
t = ror(t, 3)         # undo ROL 3
t = (t - i) & 0xff    # undo + i
t ^= prev             # undo ^= prev
t = (t * 0x85) & 0xff # undo * 0x4d      <- modular inverse
in[i] = t ^ ks[i]     # undo ^= ks
prev = in[i]          # feedback is the PLAINTEXT byte just recovered
```

Yields `THJCC{st4ck_vm_1nv_mul_1dx_f33db4ck_ch41n3d}`.
Full self-verifying script: [`solve.py`](solve.py).

## Correctness and uniqueness
Every per-position step is a bijection mod 256 (XOR ks, ×0x4d with 0x4d odd,
XOR prev, +i, rol 3, XOR 0x3b), and the feedback is a deterministic function of
already-determined plaintext. So exactly one input of length 44 is accepted —
verified by enumerating all 256 candidates at each of the 44 positions.

## Design history (why it is the way it is)
Three rounds of independent blind-solve review, each of which found something
real. Recorded here because the mistakes are more instructive than the design.

An earlier build set `prev` from the **output** byte via `SETPREV` (peek). That
was a mistake: since the program exits on first mismatch, `prev_i` was simply
`target[i-1]` — a known constant — so each position became independently
brute-forceable with 256 guesses and the advertised "chaining" defense was
worthless. An independent reviewer demonstrated the full flag recovered that way
with zero algebraic inversion. Switching to `SETPREV_INP` (opcode 0x32) fixed it:
the same attack now yields one correct character and then garbage.

Two earlier reviewers also rated the pre-hardening version "medium" rather than
"hard", noting the whole VM inlines into one function that a single `objdump -d`
pass exposes, and that the XOR obfuscation cost a *dynamic* solver nothing —
a gdb breakpoint dumped both plaintext arrays in about 30 seconds. The ptrace
anti-debug closes that path.

The third round then found a genuine **memory-safety bug**: the VM had no bounds
check on `ip`. On the traced path the garbage bytecode happens to contain a
`PUSH_KS`, which advances the LCG and overwrites the four bytes at `0x20054` —
destroying the `0xff` that would otherwise have halted the interpreter. `ip` then
walked the padding, `target[]`, `.bss` and off the end of the RW mapping,
segfaulting at `load_base+0x21000`. Reviewers reproduced it 3/3 under `strace`
and 3/3 under gdb with ASLR enabled, so the advertised "silently rejects" was
only true under gdb's ASLR-off default. Fixed with an `ip`/`sp` bound at the top
of the dispatch loop; now verified to print `nope.` on every traced path.

**Difficulty, honestly:** rated *medium* by all five independent blind-solvers
across three rounds. `.text` is ~1.2 KB in a single function, the bytecode is 18
bytes of straight-line expression with no branches, and the dispatch table is
compiler-generated and renders cleanly in objdump. The real work is bookkeeping
(resolving 35 signed jump-table entries), not a conceptual obstacle. Points were
cut 450 → 400 → **250** to match measured difficulty rather than intended
difficulty.

Room to escalate to a genuine hard: give the feedback real depth (see §4), derive
the ROL amount from the index, compute the LCG seed from a runtime value so it
cannot be lifted from `.data`, build the handler table at runtime, put actual
control flow (branches/loops) in the bytecode, or compile `-O2` with a
non-inlined VM and opaque predicates so control flow is not one linear read.
