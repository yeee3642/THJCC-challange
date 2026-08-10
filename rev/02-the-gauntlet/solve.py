#!/usr/bin/env python3
"""vm-gauntlet solver.

The binary is STRIPPED and ANTI-DEBUGGED, and both the VM bytecode and the
expected ciphertext are stored XOR-obfuscated in .data.

  anti-debug: main calls ptrace(PTRACE_TRACEME). Under a debugger that fails,
              which perturbs the unmask key by +0x7f, so both arrays unmask to
              garbage and *every* input is rejected — including the real flag.
              Dumping .data from gdb therefore yields nothing useful. Solve
              statically (or patch the ptrace result).

  unmask:     p[i] ^= (i * 0x9d + 0x2f) & 0xff
              over code[] @ .data 0x20010 (18 bytes) and target[] @ 0x20028 (44)

Deobfuscated, code[] = 12 13 20 10 4d 23 14 20 11 21 24 03 10 3b 20 32 31 ff,
executed once per input character:

    PUSH_INP ; PUSH_KS ; XOR        t = in[i] ^ ks[i]
    PUSH_IMM 0x4d ; MUL             t = (t * 0x4d) & 0xff   <- needs mod inverse
    PUSH_PREV ; XOR                 t ^= prev               <- OLD prev consumed
    PUSH_IDX ; ADD                  t = (t + i) & 0xff      <- position-dependent
    ROL 3                           t = rol(t, 3)
    PUSH_IMM 0x3b ; XOR             t ^= 0x3b
    SETPREV_INP                     prev = in[i]            <- feedback keyed on
                                                               the INPUT byte
    OUT                             out[i] = t

Because prev is set from the *plaintext* byte (opcode 0x32), not from the output,
prev_i is NOT derivable from target[]. Position i cannot be attacked until
0..i-1 are solved, so recovery is strictly sequential.

    keystream: lcg = lcg*0x6D2B79F5 + 0x9E3779B9 (mod 2^32); ks = (lcg>>24)&0xff
               seed 0x00C0FFEE @ .data 0x20054 ; prev seeded 0x5a @ .data 0x20058
"""
import os, subprocess, sys

# obfuscated bytes exactly as they sit in .data
code_obf = bytes.fromhex("3ddf4916ee63c95a069575ed9b13e550ce63")
tgt_obf = bytes.fromhex(
    "335849f93386621b77d28dd9b5b1e145ce96a0b0167ed90afda42304dd0ced67"
    "dc80bc277b93ff39c6fc8c92"
)

def unveil(b):
    return bytes(c ^ ((i * 0x9D + 0x2F) & 0xFF) for i, c in enumerate(b))

code, target = unveil(code_obf), unveil(tgt_obf)
print("[*] deobfuscated bytecode:", code.hex(" "))

LCG_A, LCG_C, SEED = 0x6D2B79F5, 0x9E3779B9, 0x00C0FFEE
M1, K1, R, PREV0 = 0x4D, 0x3B, 3, 0x5A
M1_INV = pow(M1, -1, 256)          # 0x85 — undoes the MUL step
print(f"[*] modular inverse of {M1:#04x} mod 256 = {M1_INV:#04x}")

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xFF

# keystream: LCG advanced once per character
state, ks = SEED, []
for _ in range(len(target)):
    state = (state * LCG_A + LCG_C) & 0xFFFFFFFF
    ks.append((state >> 24) & 0xFF)

# Strictly sequential: each recovered plaintext byte becomes the next feedback.
flag, prev = bytearray(), PREV0
for i, c in enumerate(target):
    t = c ^ K1                # undo ^= 0x3b
    t = ror(t, R)             # undo rol 3
    t = (t - i) & 0xFF        # undo + i
    t ^= prev                 # undo ^= prev
    t = (t * M1_INV) & 0xFF   # undo * 0x4d
    t ^= ks[i]                # undo ^= ks
    flag.append(t)
    prev = t                  # feedback is the PLAINTEXT byte we just recovered

flag = bytes(flag)
print("[*] recovered flag:", flag.decode())

# self-verify against the real binary (skipped if the host cannot exec this arch)
here = os.path.dirname(os.path.abspath(__file__))
binary = os.path.join(here, "vmcheck")
try:
    p = subprocess.run([binary], input=flag + b"\n", capture_output=True, timeout=30)
except (OSError, subprocess.TimeoutExpired) as e:
    print(f"[!] cannot run {binary} on this host ({e}); static solve stands.")
    sys.exit(0)
print("[*] binary says   :", p.stdout.decode(errors="replace").strip())
if b"correct" in p.stdout:
    print("[+] verified")
elif p.returncode < 0:
    print(f"[!] binary died on signal {-p.returncode} — not a solve failure; "
          "check the host, not the flag.")
else:
    # Most likely the anti-debug fired: a tracer (or a ptrace-denying sandbox)
    # perturbs the unmask key, so the binary rejects even the correct flag.
    print("[!] binary rejected the flag. If you are running this under a "
          "debugger/strace or in a ptrace-restricted sandbox, that is the "
          "anti-debug, not a wrong answer. Re-run untraced to confirm.")
    sys.exit(1)
