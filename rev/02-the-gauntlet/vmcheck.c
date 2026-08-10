#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <errno.h>

/* the gauntlet :: a tiny stack machine guards the flag */

static unsigned char code[]   = { 0x3d, 0xdf, 0x49, 0x16, 0xee, 0x63, 0xc9, 0x5a, 0x06, 0x95, 0x75, 0xed, 0x9b, 0x13, 0xe5, 0x50, 0xce, 0x63 };
static unsigned char target[] = { 0x33, 0x58, 0x49, 0xf9, 0x33, 0x86, 0x62, 0x1b, 0x77, 0xd2, 0x8d, 0xd9, 0xb5, 0xb1, 0xe1, 0x45, 0xce, 0x96, 0xa0, 0xb0, 0x16, 0x7e, 0xd9, 0x0a, 0xfd, 0xa4, 0x23, 0x04, 0xdd, 0x0c, 0xed, 0x67, 0xdc, 0x80, 0xbc, 0x27, 0x7b, 0x93, 0xff, 0x39, 0xc6, 0xfc, 0x8c, 0x92 };

static uint32_t lcg = 0x00c0ffeeu;
static unsigned char prev = 0x5a;

/* If a debugger already holds us, PTRACE_TRACEME fails and the mask is wrong,
   so both arrays unmask to garbage and every input is silently rejected. */
static void unveil(unsigned char *p, size_t n, unsigned char adj) {
    for (size_t i = 0; i < n; i++)
        p[i] ^= (unsigned char)(i * 0x9du + 0x2fu + adj);
}

static unsigned char next_ks(void) {
    lcg = lcg * 0x6d2b79f5u + 0x9e3779b9u;
    return (lcg >> 24) & 0xFF;
}

static unsigned char rot(unsigned char x, int n) {
    return (unsigned char)((x << n) | (x >> (8 - n)));
}

static unsigned char step(int i, unsigned char inp_b) {
    unsigned char st[64]; int sp = 0;
    size_t ip = 0;
    for (;;) {
        if (ip >= sizeof code || sp < 0 || sp >= 60) return 0;
        unsigned char op = code[ip++];
        switch (op) {
            case 0x10: st[sp++] = code[ip++]; break;
            case 0x11: st[sp++] = (unsigned char)i; break;
            case 0x12: st[sp++] = inp_b; break;
            case 0x13: st[sp++] = next_ks(); break;
            case 0x14: st[sp++] = prev; break;
            case 0x20: { unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b^a; break; }
            case 0x21: { unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b+a; break; }
            case 0x22: { unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b-a; break; }
            case 0x23: { unsigned char a=st[--sp], b=st[--sp]; st[sp++]=b*a; break; }
            case 0x24: { int n=code[ip++]; st[sp-1]=rot(st[sp-1], n); break; }
            case 0x25: { int n=code[ip++]; st[sp-1]=rot(st[sp-1], 8-n); break; }
            case 0x30: prev = st[sp-1]; break;
            case 0x31: return st[--sp];
            case 0x32: prev = inp_b; break;
            case 0xFF: return sp ? st[--sp] : 0;
        }
    }
}

int main(void) {
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
    buf[strcspn(buf, "\r\n")] = 0;

    size_t n = strlen(buf);
    if (n != sizeof target) { puts("nope."); return 1; }

    for (size_t i = 0; i < n; i++) {
        if (step((int)i, (unsigned char)buf[i]) != target[i]) {
            puts("nope.");
            return 1;
        }
    }
    puts("correct! that flag is the flag.");
    return 0;
}
