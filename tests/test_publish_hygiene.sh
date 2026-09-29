#!/usr/bin/env bash
# Checks that scripts/publish-hygiene.sh refuses what it should and passes what it should.
# Every canary here is synthetic, so this suite carries no personal terms and can be published.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GATE="$ROOT/scripts/publish-hygiene.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/publish-hygiene-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

total=0
passed=0
report() {
    total=$((total + 1))
    if [ "$1" = ok ]; then
        passed=$((passed + 1))
        echo "  PASS  $2"
    else
        echo "  FAIL  $2"
    fi
}

sandbox() {  # sandbox <name> <contents> -> path to a throwaway repo with one tracked file
    local d="$WORK/$1"
    mkdir -p "$d"
    git -C "$d" init -q
    printf '%s\n' "$2" > "$d/tracked.txt"
    git -C "$d" add tracked.txt
    printf '%s' "$d"
}

run_gate() {  # run_gate <dir> [VAR=value ...] -> sets OUT and CODE
    local d="$1"
    shift
    OUT=$(cd "$d" && env "$@" bash "$GATE" 2>&1)
    CODE=$?
}

CANARY_A='canary-token-alpha'
CANARY_B='canary-token-beta'

printf '%s\n' "$CANARY_A" > "$WORK/a.pats"

# A clean tree passes, and the run reports patterns rather than proving nothing.
d=$(sandbox clean 'nothing of interest here')
run_gate "$d" HYGIENE_PATTERNS_FILE="$WORK/a.pats"
if [ "$CODE" -eq 0 ] && printf '%s' "$OUT" | grep -q "passed: scanned"; then
    report ok "a clean tree passes and the run reports its pattern count"
else
    report fail "a clean tree should pass (exit $CODE)"
fi

# A pattern from the local file is caught, alongside the builtins. This is also the weld check:
# bare concatenation of the sources would fuse a builtin onto this pattern and lose the match.
d=$(sandbox localfile "a line containing $CANARY_A in it")
run_gate "$d" HYGIENE_PATTERNS_FILE="$WORK/a.pats"
if [ "$CODE" -eq 1 ] && printf '%s' "$OUT" | grep -q "$CANARY_A"; then
    report ok "a pattern from the local file is caught with the builtins loaded"
else
    report fail "a local-file pattern should be caught (exit $CODE)"
fi

# The env source is caught too.
d=$(sandbox env "a line containing $CANARY_A in it")
run_gate "$d" HYGIENE_PATTERNS_FILE=/dev/null HYGIENE_PATTERNS="$CANARY_A"
if [ "$CODE" -eq 1 ] && printf '%s' "$OUT" | grep -q "$CANARY_A"; then
    report ok "a pattern from HYGIENE_PATTERNS is caught"
else
    report fail "an env pattern should be caught (exit $CODE)"
fi

# Both sources at once: two distinct canaries must produce two findings, not one fused match.
d=$(sandbox both "$CANARY_A and $CANARY_B on one line")
run_gate "$d" HYGIENE_PATTERNS_FILE="$WORK/a.pats" HYGIENE_PATTERNS="$CANARY_B"
findings=$(printf '%s\n' "$OUT" | grep -c '^FAIL' || true)
if [ "$CODE" -eq 1 ] && [ "$findings" -eq 2 ]; then
    report ok "both sources stay separate: two canaries, two findings"
else
    report fail "both sources should report separately (exit $CODE, $findings finding(s))"
fi

# An emptied rule set fails closed. The builtin block is stripped from a copy to simulate the
# edit that would remove it, because otherwise the shipped shapes always keep the count above zero.
STRIPPED="$WORK/no-builtins.sh"
inblock=0
: > "$STRIPPED"
while IFS= read -r line; do
    if [ "$inblock" = 1 ]; then
        case "$line" in PATTERNS) printf 'PATTERNS\n' >> "$STRIPPED"; inblock=0 ;; esac
        continue
    fi
    printf '%s\n' "$line" >> "$STRIPPED"
    case "$line" in *"BUILTIN_FAIL <<'PATTERNS'"*) inblock=1 ;; esac
done < "$GATE"
OUT=$(cd "$d" && env HYGIENE_PATTERNS_FILE=/dev/null HYGIENE_PATTERNS='' bash "$STRIPPED" 2>&1)
CODE=$?
if [ "$CODE" -eq 1 ] && printf '%s' "$OUT" | grep -q "0 FAIL patterns loaded"; then
    report ok "an emptied rule set fails closed instead of reporting a clean tree"
else
    report fail "an emptied rule set should fail closed (exit $CODE)"
fi

# The gate passes on this repository. Catches a pattern that starts matching its own source.
run_gate "$ROOT"
if [ "$CODE" -eq 0 ]; then
    report ok "the gate passes on this repository (no pattern matches its own definition)"
else
    report fail "the gate should pass on this repository (exit $CODE)"
fi

echo
echo "$passed/$total checks passed"
[ "$passed" -eq "$total" ] || exit 1
