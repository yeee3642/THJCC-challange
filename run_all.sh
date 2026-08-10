#!/usr/bin/env bash
# Verify every reference solution still works.
# Pass --regen to mint fresh challenge data first (this changes the committed
# output files, and with them the keys quoted in the writeups).
set -u
cd "$(dirname "$0")"

if [ "${1:-}" = "--regen" ]; then
    python3 medium/01-two-exponents/generate.py >/dev/null
    python3 hard/02-lattice-of-doom/generate.py >/dev/null
fi

fail=0
for dir in medium/*/ hard/*/; do
    name="${dir%/}"
    printf '=== %-32s ' "$name"
    if out=$(cd "$dir" && timeout 600 python3 solve.py 2>&1) \
       && flag=$(grep -o 'THJCC{[^}]*}' <<<"$out" | tail -1) \
       && [ -n "$flag" ]; then
        printf 'OK   %s\n' "$flag"
    else
        printf 'FAIL\n%s\n' "$out"
        fail=1
    fi
done

[ "$fail" -eq 0 ] && echo "all solutions verified" || echo "some solutions failed"
exit "$fail"
