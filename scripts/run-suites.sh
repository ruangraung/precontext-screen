#!/usr/bin/env bash
# Runs the precontext-screen suites. Both are scripts, not pytest: each prints
# "N/N checks passed" and exits non-zero on failure.
#
# The hook suite is stdlib-only and runs anywhere. The end-to-end proof imports the
# host agent's own modules and reaches the network, so it only runs when explicitly
# requested (HOST_E2E=1) and with the interpreter the agent uses.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
FAILED=0

run() {
    local label="$1"; shift
    echo "== $label =="
    if "$@"; then
        echo "-- $label: pass"
    else
        echo "-- $label: FAIL"
        FAILED=1
    fi
    echo
}

run "hook suite" python3 tests/test_precontext_screen.py

if [ "${HOST_E2E:-0}" = "1" ]; then
    run "end-to-end proof" python3 tests/e2e_precontext_screen.py
else
    echo "== end-to-end proof: skipped (set HOST_E2E=1 with the host interpreter to run it) =="
    echo
fi

if [ $FAILED -ne 0 ]; then
    echo "one or more suites failed"
    exit 1
fi

echo "all requested suites passed"
