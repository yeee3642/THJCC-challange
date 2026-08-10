#!/usr/bin/env python3
"""baby-xor solver.

Static recovery only — no execution needed to find the flag:
  enc[]  recovered from .rodata @ 0x0b68  (objdump -s -j .rodata baby)
  key    recovered from .rodata @ 0x0b38  ("r3v")
The check is `input[i] ^ key[i%3] == enc[i]`, so the flag is `enc[i] ^ key[i%3]`.
"""
import os, subprocess, sys

enc = bytes.fromhex(
    "267b3c31700d0a03042d02432d471e416c151e07050102152d400246410241410b"
)
key = b"r3v"

flag = bytes(enc[i] ^ key[i % len(key)] for i in range(len(enc)))
print("[*] recovered flag:", flag.decode())

# self-verify against the real binary
here = os.path.dirname(os.path.abspath(__file__))
binary = os.path.join(here, "baby")
try:
    p = subprocess.run([binary], input=flag + b"\n", capture_output=True, timeout=30)
except (OSError, subprocess.TimeoutExpired) as e:
    print(f"[!] cannot run {binary} on this host ({e}); static solve stands.")
    sys.exit(0)
print("[*] binary says   :", p.stdout.decode(errors="replace").strip())
if b"granted" in p.stdout:
    print("[+] verified")
else:
    print("[!] binary rejected the flag — investigate.")
    sys.exit(1)
