#!/usr/bin/env python3
"""Build generator: emits the C sources for both rev challenges with
correct embedded ciphertext/target arrays derived from the real flags."""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
EASY_DIR = os.path.join(HERE, "01-baby-xor")
HARD_DIR = os.path.join(HERE, "02-the-gauntlet")

EASY_FLAG = b"THJCC{x0r_15_th3_cl4ss1c_st4rt3r}"
EASY_KEY  = b"r3v"                       # 3-byte repeating XOR key

HARD_FLAG = b"THJCC{st4ck_vm_1nv_mul_1dx_f33db4ck_ch41n3d}"

# ---------- EASY: multi-byte repeating XOR ----------
def gen_easy():
    enc = bytes(b ^ EASY_KEY[i % len(EASY_KEY)] for i, b in enumerate(EASY_FLAG))
    arr = ", ".join(f"0x{b:02x}" for b in enc)
    src = f'''#include <stdio.h>
#include <string.h>

/* baby-xor :: reverse me */
static unsigned char enc[] = {{ {arr} }};
static const char *key = "{EASY_KEY.decode()}";

int main(void) {{
    char buf[128];
    printf("license key> ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\\r\\n")] = 0;

    size_t n = strlen(buf);
    if (n != sizeof enc) {{ puts("[-] wrong length"); return 1; }}

    for (size_t i = 0; i < n; i++) {{
        if ((unsigned char)(buf[i] ^ key[i % 3]) != enc[i]) {{
            puts("[-] denied");
            return 1;
        }}
    }}
    puts("[+] access granted");
    return 0;
}}
'''
    open(os.path.join(EASY_DIR, "baby.c"), "w").write(src)
    return enc

# ---------- HARD: obfuscated stack VM + feedback stream cipher ----------
# opcodes
PUSH_IMM, PUSH_IDX, PUSH_INP, PUSH_KS, PUSH_PREV = 0x10,0x11,0x12,0x13,0x14
XOR, ADD, SUB, MUL, ROL, ROR = 0x20,0x21,0x22,0x23,0x24,0x25
SETPREV, OUT, SETPREV_INP, HALT = 0x30,0x31,0x32,0xFF

M1, K1, R, PREV0 = 0x4D, 0x3B, 3, 0x5A     # M1 must be odd (invertible mod 256)
# deliberately NOT the textbook glibc constants
LCG_A, LCG_C, LCG_SEED, LCG_MOD = 0x6D2B79F5, 0x9E3779B9, 0x00C0FFEE, (1 << 32)
# code[]/target[] are stored XOR-obfuscated with a *computed* keystream,
# so neither array is a greppable plaintext blob in the binary.
OBF_A, OBF_B = 0x9D, 0x2F

def obf(i):   return (i * OBF_A + OBF_B) & 0xFF
def rol(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF

CODE = [
    PUSH_INP,
    PUSH_KS,
    XOR,                # t = in ^ ks
    PUSH_IMM, M1,
    MUL,                # t = t * 0x4d      (needs modular inverse to undo)
    PUSH_PREV,
    XOR,                # t = t ^ prev      (consume the OLD prev first)
    PUSH_IDX,
    ADD,                # t = t + i         (position-dependent)
    ROL, R,             # t = rol(t, 3)
    PUSH_IMM, K1,
    XOR,                # t = t ^ 0x3b
    SETPREV_INP,        # prev = in[i]      <- feedback keyed on the INPUT byte,
                        #                      so position i cannot be attacked
                        #                      before 0..i-1 are solved.
    OUT,
    HALT,
]

class VM:
    """Reference emulator — kept byte-identical to the C interpreter."""
    def __init__(self):
        self.prev = PREV0
        self.state = LCG_SEED
    def next_ks(self):
        self.state = (self.state * LCG_A + LCG_C) % LCG_MOD
        return (self.state >> 24) & 0xFF
    def run_byte(self, i, inp_b):
        st = []
        ip = 0
        while True:
            op = CODE[ip]; ip += 1
            if op == PUSH_IMM: st.append(CODE[ip]); ip += 1
            elif op == PUSH_IDX: st.append(i & 0xFF)
            elif op == PUSH_INP: st.append(inp_b & 0xFF)
            elif op == PUSH_KS: st.append(self.next_ks())
            elif op == PUSH_PREV: st.append(self.prev)
            elif op == XOR: a=st.pop(); b=st.pop(); st.append((b^a)&0xFF)
            elif op == ADD: a=st.pop(); b=st.pop(); st.append((b+a)&0xFF)
            elif op == SUB: a=st.pop(); b=st.pop(); st.append((b-a)&0xFF)
            elif op == MUL: a=st.pop(); b=st.pop(); st.append((b*a)&0xFF)
            elif op == ROL: n=CODE[ip]; ip+=1; st.append(rol(st.pop(), n))
            elif op == ROR: n=CODE[ip]; ip+=1; st.append(rol(st.pop(), 8-n))
            elif op == SETPREV: self.prev = st[-1]
            elif op == SETPREV_INP: self.prev = inp_b & 0xFF
            elif op == OUT: return st.pop()
            elif op == HALT: return st.pop() if st else 0
            else: raise ValueError(f"bad op {op:#x}")

def gen_hard():
    vm = VM()
    target = bytes(vm.run_byte(i, b) for i, b in enumerate(HARD_FLAG))

    # store both arrays obfuscated
    code_o = [c ^ obf(i) for i, c in enumerate(CODE)]
    tgt_o  = [c ^ obf(i) for i, c in enumerate(target)]
    code_arr = ", ".join(f"0x{b:02x}" for b in code_o)
    tgt_arr  = ", ".join(f"0x{b:02x}" for b in tgt_o)

    src = f'''#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <errno.h>

/* the gauntlet :: a tiny stack machine guards the flag */

static unsigned char code[]   = {{ {code_arr} }};
static unsigned char target[] = {{ {tgt_arr} }};

static uint32_t lcg = 0x{LCG_SEED:08x}u;
static unsigned char prev = 0x{PREV0:02x};

/* If a debugger already holds us, PTRACE_TRACEME fails and the mask is wrong,
   so both arrays unmask to garbage and every input is silently rejected. */
static void unveil(unsigned char *p, size_t n, unsigned char adj) {{
    for (size_t i = 0; i < n; i++)
        p[i] ^= (unsigned char)(i * 0x{OBF_A:02x}u + 0x{OBF_B:02x}u + adj);
}}

static unsigned char next_ks(void) {{
    lcg = lcg * 0x{LCG_A:08x}u + 0x{LCG_C:08x}u;
    return (lcg >> 24) & 0xFF;
}}

static unsigned char rot(unsigned char x, int n) {{
    return (unsigned char)((x << n) | (x >> (8 - n)));
}}

static unsigned char step(int i, unsigned char inp_b) {{
    unsigned char st[64]; int sp = 0;
    size_t ip = 0;
    for (;;) {{
        if (ip >= sizeof code || sp < 0 || sp >= 60) return 0;
        unsigned char op = code[ip++];
        switch (op) {{
            case 0x10: st[sp++] = code[ip++]; break;
            case 0x11: st[sp++] = (unsigned char)i; break;
            case 0x12: st[sp++] = inp_b; break;
            case 0x13: st[sp++] = next_ks(); break;
            case 0x14: st[sp++] = prev; break;
            case 0x20: {{ unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b^a; break; }}
            case 0x21: {{ unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b+a; break; }}
            case 0x22: {{ unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b-a; break; }}
            case 0x23: {{ unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b*a; break; }}
            case 0x24: {{ int n=code[ip++]; st[sp-1]=rot(st[sp-1], n); break; }}
            case 0x25: {{ int n=code[ip++]; st[sp-1]=rot(st[sp-1], 8-n); break; }}
            case 0x30: prev = st[sp-1]; break;
            case 0x31: return st[--sp];
            case 0x32: prev = inp_b; break;
            case 0xFF: return sp ? st[--sp] : 0;
        }}
    }}
}}

int main(void) {{
    char buf[256];

    /* ENOSYS means the host does not implement ptrace at all (qemu-user);
       that is not a debugger, so do not punish those players. */
    errno = 0;
    long tr = ptrace(PTRACE_TRACEME, 0, 0, 0);
    unsigned char adj = (tr < 0 && errno != ENOSYS) ? 0x7f : 0x00;
    unveil(code, sizeof code, adj);
    unveil(target, sizeof target, adj);

    printf("flag> ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\\r\\n")] = 0;

    size_t n = strlen(buf);
    if (n != sizeof target) {{ puts("nope."); return 1; }}

    for (size_t i = 0; i < n; i++) {{
        if (step((int)i, (unsigned char)buf[i]) != target[i]) {{
            puts("nope.");
            return 1;
        }}
    }}
    puts("correct! that flag is the flag.");
    return 0;
}}
'''
    open(os.path.join(HARD_DIR, "vmcheck.c"), "w").write(src)
    return target

def make_dist():
    """Emit rev/dist/<chal>/ with ONLY what players may receive.

    Everything else in a challenge directory (the .c source, solve.py and
    WRITEUP.md) reveals the flag, so hand out this tree rather than the
    challenge directory itself.
    """
    import shutil
    for chal, binary in (("01-baby-xor", "baby"), ("02-the-gauntlet", "vmcheck")):
        src = os.path.join(HERE, chal)
        out = os.path.join(HERE, "dist", chal)
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out, exist_ok=True)
        src_bin = os.path.join(src, binary)
        if os.path.exists(src_bin):
            shutil.copy2(src_bin, os.path.join(out, binary))
        shutil.copy2(os.path.join(src, "README.md"),
                     os.path.join(out, "README.md"))
        print(f"rev/dist/{chal}/: {binary} + README.md")

if __name__ == "__main__":
    e = gen_easy()
    t = gen_hard()
    inv = pow(M1, -1, 256)
    print("EASY flag :", EASY_FLAG.decode())
    print("EASY enc  :", e.hex())
    print("HARD flag :", HARD_FLAG.decode())
    print("HARD tgt  :", t.hex())
    print(f"HARD inv({M1:#04x}) mod 256 = {inv:#04x}")
    print("sources written.")
    if "--dist" in sys.argv:
        make_dist()
