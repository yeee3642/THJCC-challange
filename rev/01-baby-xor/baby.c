#include <stdio.h>
#include <string.h>

/* baby-xor :: reverse me */
static unsigned char enc[] = { 0x26, 0x7b, 0x3c, 0x31, 0x70, 0x0d, 0x0a, 0x03, 0x04, 0x2d, 0x02, 0x43, 0x2d, 0x47, 0x1e, 0x41, 0x6c, 0x15, 0x1e, 0x07, 0x05, 0x01, 0x02, 0x15, 0x2d, 0x40, 0x02, 0x46, 0x41, 0x02, 0x41, 0x41, 0x0b };
static const char *key = "r3v";

int main(void) {
    char buf[128];
    printf("license key> ");
    if (!fgets(buf, sizeof buf, stdin)) return 1;
    buf[strcspn(buf, "\r\n")] = 0;

    size_t n = strlen(buf);
    if (n != sizeof enc) { puts("[-] wrong length"); return 1; }

    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)(buf[i] ^ key[i % 3]) != enc[i]) {
            puts("[-] denied");
            return 1;
        }
    }
    puts("[+] access granted");
    return 0;
}
