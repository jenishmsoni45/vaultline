#!/bin/sh
# Adds up the results of every test binary in the output of `cargo test`
# (D-006, P5-3).
#
#   cargo test --locked 2>&1 | scripts/count-tests.sh
#
# Reads the `test result:` lines on standard input and prints one line,
# `passed=<n> failed=<n> ignored=<n>`. Exits 1, saying why on standard error,
# if there are no such lines: no count is better than a made-up zero.

set -eu

awk '
    /^test result: / {
        seen = 1
        for (i = 1; i < NF; i++) {
            if ($(i + 1) == "passed;") passed += $i
            if ($(i + 1) == "failed;") failed += $i
            if ($(i + 1) == "ignored;") ignored += $i
        }
    }
    END {
        if (!seen) {
            print "error: no \"test result:\" lines in the input" > "/dev/stderr"
            exit 1
        }
        printf "passed=%d failed=%d ignored=%d\n", passed, failed, ignored
    }
'
