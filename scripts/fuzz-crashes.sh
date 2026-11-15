#!/bin/sh
# Counts what a fuzz campaign found (D-006, D-058, P5-1).
#
#   scripts/fuzz-crashes.sh <directory>
#
# <directory> holds the campaign's artifacts as `gh run download <run ID> --dir
# <directory>` leaves them: a `fuzz-time-<target>` directory per target, whose
# `exit-status` file holds the fuzzer's exit status, and a
# `fuzz-crashes-<target>` directory for each target that left files.
#
# Prints exactly three lines on standard output:
#   targets: <how many targets ran>
#   clean: <how many of them exited with status 0>
#   crashes: <crash, oom, timeout and leak files left by all targets>
# Exits 1, saying why on standard error, if there are no targets or a target
# has no readable exit status: a missing status is never counted as clean.

set -eu

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
    echo "usage: $0 <directory with the campaign's artifacts>" >&2
    exit 1
fi

targets=0
clean=0
for dir in "$1"/fuzz-time-*/; do
    [ -d "$dir" ] || continue
    status=$(cat "$dir/exit-status" 2>/dev/null) || {
        echo "error: cannot read ${dir}exit-status" >&2
        exit 1
    }
    targets=$((targets + 1))
    if [ "$status" = "0" ]; then
        clean=$((clean + 1))
    fi
done
if [ "$targets" -eq 0 ]; then
    echo "error: no fuzz-time-<target> directories in $1" >&2
    exit 1
fi

crashes=0
for dir in "$1"/fuzz-crashes-*/; do
    [ -d "$dir" ] || continue
    for file in "$dir"*; do
        case "$(basename "$file")" in
            crash-* | oom-* | timeout-* | leak-*)
                if [ -f "$file" ]; then crashes=$((crashes + 1)); fi
                ;;
        esac
    done
done

echo "targets: $targets"
echo "clean: $clean"
echo "crashes: $crashes"
