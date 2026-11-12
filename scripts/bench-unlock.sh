#!/bin/sh
# Prints the measured time of one vault unlock with the default Argon2id
# parameters (256 MiB, t=3, p=4): D-001, NFR-8, P2-15. Any unlock time quoted
# in README.md or docs/ must come from this script (D-006).
#
# It runs benches/unlock.rs through criterion: one process, 256 MiB per
# unlock, about ten seconds once built. Nothing keeps running afterwards.
set -eu
cd "$(dirname "$0")/.."

if ! out=$(cargo bench --locked --bench unlock 2>&1); then
    printf '%s\n' "$out" >&2
    exit 1
fi
printf '%s\n' "$out"

# criterion prints: time:   [<low> <unit> <estimate> <unit> <high> <unit>]
line=$(printf '%s\n' "$out" | grep -m 1 'time:') || {
    echo "error: the benchmark printed no timing line" >&2
    exit 1
}
estimate=$(printf '%s\n' "$line" | sed -E 's/.*\[[^ ]+ [^ ]+ +([^ ]+ [^ ]+) .*/\1/')
echo
echo "Measured unlock time with the default Argon2id parameters (256 MiB, t=3, p=4): $estimate"
echo "(criterion's estimate over 10 samples, from scripts/bench-unlock.sh)"
