#!/bin/sh
# Runs or collects every measured number the README may quote (D-006, D-058,
# P5-3). A number in README.md or docs/ that describes a measurement comes from
# the output of this script, or of one of the scripts it calls, and the README
# says which.
#
#   scripts/numbers.sh --run <run ID>        download the campaign's artifacts with gh
#   scripts/numbers.sh --campaign <dir>      use artifacts already downloaded into <dir>
#
# <dir> holds the campaign's artifacts as `gh run download <run ID> --dir <dir>`
# leaves them: one `fuzz-time-<target>` directory per target (with `seconds`,
# `cores` and `exit-status`), and a `fuzz-crashes-<target>` directory for each
# target that left crash files.
#
# What it does, in order:
#   1. unlock time:   scripts/bench-unlock.sh        (about ten seconds; 256 MiB)
#   2. run overhead:  scripts/bench-run-overhead.sh  (about half a minute; starts
#                     one agent in a temporary directory and stops it again)
#   3. fuzzing:       scripts/fuzz-cpu-hours.sh and scripts/fuzz-crashes.sh on
#                     the campaign
#   4. test counts:   `cargo test --locked` through scripts/count-tests.sh
# Nothing keeps running afterwards. The only network use is `gh run download`,
# for --run, with the GitHub login you already have.
#
# Prints one `key: value` line per number, and nothing else on standard output.
# The scripts it calls print their own output on standard error. Exits 1, with
# the reason on standard error, if any measurement fails. A run overhead above
# its target is reported on the line, and still exits 0, so the report is
# complete; the exit status of bench-run-overhead.sh is the gate for P5-2.
set -eu
cd "$(dirname "$0")/.."

usage() {
    echo "usage: $0 --run <run ID> | --campaign <directory>" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage
cleanup=""
case "$1" in
    --run)
        case "$2" in '' | *[!0-9]*) usage ;; esac
        run_id=$2
        campaign=$(mktemp -d)
        cleanup=$campaign
        trap 'rm -rf "$cleanup"' EXIT
        gh run download "$run_id" --dir "$campaign" >&2
        ;;
    --campaign)
        [ -d "$2" ] || usage
        run_id=""
        campaign=$2
        ;;
    *) usage ;;
esac

# 1. Unlock time.
unlock_out=$(sh scripts/bench-unlock.sh 2>&1) || {
    printf '%s\n' "$unlock_out" >&2
    exit 1
}
printf '%s\n' "$unlock_out" >&2
unlock=$(printf '%s\n' "$unlock_out" | sed -n 's/^Measured unlock time with .*: //p' | head -n 1)
[ -n "$unlock" ] || { echo "error: no unlock time in the bench output" >&2; exit 1; }

# 2. Run overhead. Exit status 2 means the target was missed, not that the
#    measurement failed.
overhead_status=0
overhead_out=$(sh scripts/bench-run-overhead.sh 2>&1) || overhead_status=$?
printf '%s\n' "$overhead_out" >&2
if [ "$overhead_status" -ne 0 ] && [ "$overhead_status" -ne 2 ]; then
    echo "error: the run-overhead measurement failed" >&2
    exit 1
fi
overhead=$(printf '%s\n' "$overhead_out" | sed -n 's/^Overhead added by vaultline run: *//p' | head -n 1)
[ -n "$overhead" ] || { echo "error: no overhead in the bench output" >&2; exit 1; }

# 3. Fuzzing. The CPU-hours come from fuzz-cpu-hours.sh, which only reads
#    `seconds` and `cores`; the targets, clean exits and crash files come from
#    fuzz-crashes.sh.
times="$campaign/times"
rm -rf "$times"
mkdir -p "$times"
for dir in "$campaign"/fuzz-time-*/; do
    [ -d "$dir" ] || continue
    target=$(basename "$dir")
    target=${target#fuzz-time-}
    mkdir -p "$times/$target"
    cp "$dir/seconds" "$dir/cores" "$times/$target/" 2>/dev/null || {
        echo "error: $dir lacks seconds or cores" >&2
        exit 1
    }
done
cpu=$(sh scripts/fuzz-cpu-hours.sh "$times") || exit 1
printf '%s\n' "$cpu" >&2
cpu_total=$(printf '%s\n' "$cpu" | sed -n 's/^total: //p')
[ -n "$cpu_total" ] || { echo "error: no total from fuzz-cpu-hours.sh" >&2; exit 1; }
found=$(sh scripts/fuzz-crashes.sh "$campaign") || exit 1
targets=$(printf '%s\n' "$found" | sed -n 's/^targets: //p')
clean=$(printf '%s\n' "$found" | sed -n 's/^clean: //p')
crashes=$(printf '%s\n' "$found" | sed -n 's/^crashes: //p')

# 4. Test counts, summed over every test binary and the doc tests.
tests_out=$(cargo test --locked 2>&1) || {
    printf '%s\n' "$tests_out" >&2
    echo "error: cargo test failed, so there is no test count" >&2
    exit 1
}
counts=$(printf '%s\n' "$tests_out" | sh scripts/count-tests.sh) || exit 1

echo "unlock time, default Argon2id parameters (scripts/bench-unlock.sh): $unlock"
echo "run overhead, unlocked agent (scripts/bench-run-overhead.sh): $overhead"
[ -z "$run_id" ] || echo "fuzz campaign run: $run_id"
echo "fuzz targets run: $targets, finished without a crash: $clean"
echo "fuzz CPU-hours (scripts/fuzz-cpu-hours.sh): $cpu_total"
echo "fuzz crashes found: $crashes"
echo "tests (scripts/count-tests.sh over cargo test, this machine): $counts"
