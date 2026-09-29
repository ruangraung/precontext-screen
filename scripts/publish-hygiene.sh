#!/usr/bin/env bash
# Refuses machine-specific identity or infrastructure in this repository's tracked files. The
# repo is meant to be published, and a reviewer remembering the do-not list is not a gate.
#
# Patterns come from three sources: the generic shapes below (shipped, so CI has them),
# scripts/hygiene-patterns.local.txt (untracked and gitignored, absent in CI by design, because
# a published repo should not carry the list of terms it protects), and $HYGIENE_PATTERNS.
# Every run prints what each source contributed. Exit 1 on a finding or an empty rule set.
set -uo pipefail

# No pattern may match its own definition: this file is scanned like any other. The third stays
# narrow because a bare absolute-home match also hits a fixture's example home.
read -r -d '' BUILTIN_FAIL <<'PATTERNS' || true
\b100\.(6[4-9]|[7-9][0-9]|1[0-2][0-9])\.[0-9]{1,3}\.[0-9]{1,3}\b
[A-Za-z0-9-]+\.internal\b
/(home|Users)/[A-Za-z0-9._-]+/\.hermes
PATTERNS

# Reported, never fatal. Personal entries belong in the local patterns file as "WARN <regex>".
BUILTIN_WARN=""

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)

PATTERNS_FILE="${HYGIENE_PATTERNS_FILE:-}"
if [ -z "$PATTERNS_FILE" ] && [ -n "$REPO_ROOT" ]; then
    PATTERNS_FILE="$REPO_ROOT/scripts/hygiene-patterns.local.txt"
fi

LOCAL_FAIL=''
LOCAL_WARN=''
LOCAL_FAIL_N=0
LOCAL_WARN_N=0
if [ -n "$PATTERNS_FILE" ] && [ -f "$PATTERNS_FILE" ]; then
    while IFS= read -r raw || [ -n "$raw" ]; do
        line="${raw%$'\r'}"
        case "$line" in '' | '#'*) continue ;; esac
        case "$line" in
            'WARN '*)
                LOCAL_WARN="${LOCAL_WARN}${line#WARN }"$'\n'
                LOCAL_WARN_N=$((LOCAL_WARN_N + 1))
                ;;
            *)
                LOCAL_FAIL="${LOCAL_FAIL}${line}"$'\n'
                LOCAL_FAIL_N=$((LOCAL_FAIL_N + 1))
                ;;
        esac
    done < "$PATTERNS_FILE"
fi

ENV_FAIL=''
ENV_FAIL_N=0
if [ -n "${HYGIENE_PATTERNS:-}" ]; then
    while IFS= read -r raw || [ -n "$raw" ]; do
        case "$raw" in '' | '#'*) continue ;; esac
        ENV_FAIL="${ENV_FAIL}${raw}"$'\n'
        ENV_FAIL_N=$((ENV_FAIL_N + 1))
    done <<< "$HYGIENE_PATTERNS"
fi

count_patterns() { printf '%s\n' "$1" | grep -c . || true; }

BUILTIN_FAIL_N=$(count_patterns "$BUILTIN_FAIL")
BUILTIN_WARN_N=$(count_patterns "$BUILTIN_WARN")
# printf, not bare concatenation: `read -d ''` trims the trailing newline off the builtin
# block, so joining the sources directly welds its last pattern onto the first local one.
FAIL_PATTERNS=$(printf '%s\n%s\n%s\n' "$BUILTIN_FAIL" "$LOCAL_FAIL" "$ENV_FAIL")
WARN_PATTERNS=$(printf '%s\n%s\n' "$BUILTIN_WARN" "$LOCAL_WARN")
FAIL_N=$(count_patterns "$FAIL_PATTERNS")
WARN_N=$(count_patterns "$WARN_PATTERNS")

echo "publish-hygiene: pattern sources"
printf '  %-8s %2d fail, %2d warn  (shipped with the repo)\n' builtin "$BUILTIN_FAIL_N" "$BUILTIN_WARN_N"
if [ -n "$PATTERNS_FILE" ] && [ -f "$PATTERNS_FILE" ]; then
    printf '  %-8s %2d fail, %2d warn  (%s)\n' file "$LOCAL_FAIL_N" "$LOCAL_WARN_N" "$PATTERNS_FILE"
else
    printf '  %-8s %2d fail, %2d warn  (absent: %s)\n' file 0 0 "${PATTERNS_FILE:-<unset>}"
fi
printf '  %-8s %2d fail, %2d warn  (HYGIENE_PATTERNS)\n' env "$ENV_FAIL_N" 0
echo

# Fail closed: an empty rule set proves nothing about the tree.
if [ "$FAIL_N" -eq 0 ]; then
    echo "publish-hygiene FAILED (fail closed): 0 FAIL patterns loaded, so this run proves nothing."
    exit 1
fi

if [ -z "$REPO_ROOT" ]; then
    echo "not a git repository; nothing to scan"
    exit 0
fi

TRACKED=$(git ls-files)
TRACKED_COUNT=$(printf '%s\n' "$TRACKED" | grep -c . || true)
UNTRACKED_COUNT=$(git ls-files --others --exclude-standard | grep -c . || true)

# Fail closed: 0 tracked files means nothing was scanned, which is not the same as a clean tree.
if [ "$TRACKED_COUNT" -eq 0 ] && [ "$UNTRACKED_COUNT" -gt 0 ]; then
    echo "publish-hygiene FAILED (fail closed): 0 tracked files but $UNTRACKED_COUNT untracked file(s) present."
    echo "There is nothing to scan, so there is nothing to trust. Stage or commit the tree first."
    exit 1
fi

fails=0
warns=0
scanned=0
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ -f "$file" ] || continue
    grep -Iq . "$file" 2>/dev/null || continue   # skip binaries
    scanned=$((scanned + 1))

    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        hits=$(grep -InE -i -- "$pat" "$file" 2>/dev/null | head -3)
        if [ -n "$hits" ]; then
            if [ $fails -eq 0 ]; then
                echo "publish-hygiene: findings"
                echo
            fi
            echo "FAIL  $file  (pattern: $pat)"
            printf '%s\n' "$hits" | sed 's/^/        /'
            fails=$((fails + 1))
        fi
    done <<< "$FAIL_PATTERNS"

    while IFS= read -r pat; do
        [ -z "$pat" ] && continue
        if grep -InE -i -q -- "$pat" "$file" 2>/dev/null; then
            echo "WARN  $file  (pattern: $pat)"
            warns=$((warns + 1))
        fi
    done <<< "$WARN_PATTERNS"
done <<< "$TRACKED"

if [ $fails -gt 0 ]; then
    echo
    echo "publish-hygiene FAILED: $fails finding(s) across $scanned scanned file(s), $warns warning(s)."
    echo "Genericize the offending lines (config plus a generic example) before this tree is"
    echo "published. If a pattern matched a term that belongs only on your machine, move that"
    echo "pattern into scripts/hygiene-patterns.local.txt rather than leaving the term in the tree."
    exit 1
fi

echo "publish-hygiene passed: scanned $scanned file(s) against $FAIL_N fail pattern(s) and $WARN_N warn pattern(s), $warns warning(s)."
exit 0
