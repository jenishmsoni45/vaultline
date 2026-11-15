#!/bin/sh
# Prints what `vaultline run` adds before the child starts, with an unlocked
# agent: D-031, D-059, NFR-9, P5-2. Any `run` overhead figure quoted in
# README.md or docs/ must come from this script (D-006).
#
# It runs benches/run_overhead.rs through criterion. The bench times `true`
# spawned directly and `vaultline run -- true` through an unlocked agent, and
# this script prints the difference. It starts one agent in a temporary
# directory, unlocks it with the default Argon2id parameters (about a second),
# and stops it when it finishes; as a backstop the agent exits after five idle
# minutes. Takes about half a minute once built.
#
# Exits 0 if the overhead is at most the target below, 2 if it is more, and 1
# if the measurement failed.
set -eu
cd "$(dirname "$0")/.."

TARGET_MS=50

if ! out=$(cargo bench --locked --bench run_overhead 2>&1); then
    printf '%s\n' "$out" >&2
    exit 1
fi
printf '%s\n' "$out"

# criterion prints, for each benchmark: time:   [<low> <unit> <estimate> <unit> <high> <unit>]
# The first line is the baseline, the second is `run`. Each estimate becomes milliseconds.
times=$(printf '%s\n' "$out" | grep 'time:' | awk '
    {
        sub(/.*\[/, ""); sub(/\].*/, "")
        value = $3; unit = $4
        if (unit == "ns") scale = 0.000001
        else if (unit == "ms") scale = 1
        else if (unit == "s") scale = 1000
        else scale = 0.001   # microseconds, spelled with a mu
        printf "%.4f\n", value * scale
    }')
if [ "$(printf '%s\n' "$times" | wc -l | tr -d ' ')" -ne 2 ]; then
    echo "error: expected two timing lines from the benchmark" >&2
    exit 1
fi
baseline=$(printf '%s\n' "$times" | sed -n 1p)
with_run=$(printf '%s\n' "$times" | sed -n 2p)

echo
status=0
awk -v b="$baseline" -v r="$with_run" -v t="$TARGET_MS" 'BEGIN {
    d = r - b
    printf "Spawning the child directly:               %.2f ms\n", b
    printf "vaultline run through an unlocked agent:   %.2f ms\n", r
    printf "Overhead added by vaultline run:           %.2f ms (target: %d ms or less)\n", d, t
    exit (d <= t) ? 0 : 2
}' || status=$?
echo "(criterion's estimates of the mean, from scripts/bench-run-overhead.sh)"
exit "$status"
