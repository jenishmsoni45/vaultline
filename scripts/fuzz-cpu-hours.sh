#!/bin/sh
# Adds up the CPU-hours of a fuzz campaign (docs/design.md section 12.6, D-006,
# D-052).
#
#   scripts/fuzz-cpu-hours.sh <directory>
#
# <directory> holds one sub-directory per fuzz target. Each has two files that
# the campaign job wrote: `seconds`, how long the fuzzer really ran, measured
# with `date`, and `cores`, what `nproc` said on the runner. A target's
# CPU-hours are seconds x cores / 3600. libFuzzer runs as one process, so this
# counts the cores the runner offered, which is an upper bound on what the
# fuzzer used.
#
# Prints one line per target, then the total, and nothing else on standard
# output. Exits 1, saying why on standard error, if there is nothing to add up
# or a file isn't a whole number. This is the only place a CPU-hours figure
# comes from, so a figure in the README names this script.

set -eu

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
    echo "usage: $0 <directory with one sub-directory per target>" >&2
    exit 1
fi

# Reads a file that must hold one whole number.
number() {
    value=$(cat "$1" 2>/dev/null) || {
        echo "error: cannot read $1" >&2
        return 1
    }
    case "$value" in
        '' | *[!0-9]*)
            echo "error: $1 doesn't hold a whole number" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$value"
}

lines=""
count=0
for dir in "$1"/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    # Artifacts are downloaded as fuzz-time-<target>.
    target=${name#fuzz-time-}
    seconds=$(number "$dir/seconds")
    cores=$(number "$dir/cores")
    lines="$lines$target $seconds $cores
"
    count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
    echo "error: no target directories in $1" >&2
    exit 1
fi

printf '%s' "$lines" | awk '
    NF == 3 {
        hours = $2 * $3 / 3600
        total += hours
        printf "%s: %d s on %d cores = %.2f CPU-hours\n", $1, $2, $3, hours
    }
    END { printf "total: %.2f CPU-hours\n", total }
'
