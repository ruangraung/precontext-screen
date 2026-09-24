#!/usr/bin/env bash
# publish-hygiene.sh — refuses to let machine-specific identity or infrastructure
# reach this repository's tracked files.
#
# This repo is meant to be published. Its value is that a stranger can clone it and
# run it without inheriting anything about the machine it was written on. A reviewer
# remembering the do-not list is not a gate; this script does not forget, and it runs
# on every push instead of every time someone remembers.
#
# Scope: TRACKED files only (`git ls-files`). Local notes under .pi/ are untracked by
# design and are never scanned, which is what lets this repo carry internal notes at
# all. This script excludes itself, because it necessarily contains every pattern it
# searches for.
#
# Exit 0 = clean. Exit 1 = at least one FAIL pattern is present.
set -uo pipefail

# FAIL: identity or infrastructure. These never belong in a published tree.
read -r -d '' FAIL_PATTERNS <<'PATTERNS' || true
example-private-notes
example-build-host
example-memory-store
example-username
100\.(6[4-9]|[7-9][0-9]|1[0-2][0-9])\.[0-9]{1,3}\.[0-9]{1,3}
PATTERNS

# WARN: internal flavour. Not a leak, but a reader does not need it, so it is
# reported without failing the build.
read -r -d '' WARN_PATTERNS <<'PATTERNS' || true
example-llm-provider

PATTERNS

SELF='scripts/publish-hygiene.sh'
fails=0
warns=0

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "not a git repository; nothing to scan"
    exit 0
fi

TRACKED=$(git ls-files)
TRACKED_COUNT=$(printf '%s\n' "$TRACKED" | grep -c . || true)
UNTRACKED_COUNT=$(git ls-files --others --exclude-standard | grep -c . || true)

# Fail closed on a vacuous pass. A gate that reports success because it had nothing
# to look at is worse than no gate: it launders an unscanned tree as a clean one.
# (This actually happened while wiring the repo: nothing was committed yet, so the
# first run scanned zero files and printed "passed". The denominator below is the
# structural fix; this guard is the loud one.)
if [ "$TRACKED_COUNT" -eq 0 ] && [ "$UNTRACKED_COUNT" -gt 0 ]; then
    echo "publish-hygiene FAILED (fail closed): 0 tracked files but $UNTRACKED_COUNT untracked file(s) present."
    echo "There is nothing to scan, so there is nothing to trust. Stage or commit the tree first."
    exit 1
fi

scanned=0
while IFS= read -r file; do
    [ -z "$file" ] && continue
    [ "$file" = "$SELF" ] && continue
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
    echo "Genericize the offending lines (config plus a generic example) before this tree is published."
    exit 1
fi

echo "publish-hygiene passed: scanned $scanned file(s), no identity or infrastructure leaks, $warns warning(s)."
exit 0
