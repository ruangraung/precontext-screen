#!/usr/bin/env python3
"""Exercise the alert digest the cron job runs: every written record must deliver.

The digest reads only what the plugin wrote. A record is a JSON line whose fields
can carry any character the classifier call saw, including the Unicode line
separators json.dumps leaves raw, so the reader frames lines on the newline the
writer appends and nothing else. A line that still fails to parse is reported
rather than dropped, so a lost record is visible in the job log.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from contextlib import redirect_stderr
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DIGEST = REPO / "tools" / "alert-digest.py"
TMP_DIR = Path("/tmp/precontext-screen-test")
TMP_ALERTS = TMP_DIR / "alerts.jsonl"
TMP_CURSOR = TMP_DIR / "alerts-cursor.json"

GOOD = {
    "ts": "2026-11-24T00:00:00+00:00",
    "tool": "web_extract",
    "source": "https://example.com/ordinary",
    "sha256": "deadbeefdeadbeef",
    "chars": 5000,
    "screened_chars": 5000,
    "overrides": 0.95,
    "addressed_to_ai": 0.9,
    "severity": 1.5,
    "latency_ms": 900,
    "session_id": "test-1",
    "home": "",
}
SEPARATOR_SOURCE = "https://evil.example/separators" + chr(0x2028) + "page"


def load():
    spec = importlib.util.spec_from_file_location("alert_digest_under_test", DIGEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ALERTS = TMP_ALERTS
    module.CURSOR = TMP_CURSOR
    return module


def write_alerts(records) -> None:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    TMP_ALERTS.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
        encoding="utf-8",
    )


def main() -> int:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    for stale in (TMP_ALERTS, TMP_CURSOR):
        stale.unlink(missing_ok=True)

    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    mod = load()

    # 1. a record whose source carries a Unicode line separator still delivers
    write_alerts([GOOD, {**GOOD, "source": SEPARATOR_SOURCE, "sha256": "cafebabecafebabe"}])
    records = mod._load()
    by_hash = {record.get("sha256"): record for record in records}
    separator_survives = "cafebabecafebabe" in by_hash
    check(
        "a record carrying a line separator is not dropped",
        separator_survives and len(records) == 2,
        f"{len(records)} of 2 records loaded",
    )
    delivered = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = delivered
    try:
        exit_all = mod.main(["--all"])
    finally:
        sys.stdout = saved_stdout
    check(
        "the digest prints the separator record like any other",
        exit_all == 0 and "cafebabecafebabe"[:8] in delivered.getvalue(),
        f"exit {exit_all}",
    )

    # 2. a line that still fails to parse is reported, not silently dropped
    TMP_ALERTS.write_text(
        json.dumps(GOOD, ensure_ascii=False) + "\n{not a json line\n",
        encoding="utf-8",
    )
    captured = io.StringIO()
    with redirect_stderr(captured):
        parsed = mod._load()
    check(
        "a malformed line is reported and does not block the rest",
        len(parsed) == 1 and "malformed" in captured.getvalue(),
        f"{len(parsed)} parsed, stderr: {captured.getvalue().strip()[:40]!r}",
    )

    # 3. the cursor keeps a second run silent
    write_alerts([GOOD])
    TMP_CURSOR.unlink(missing_ok=True)
    first = io.StringIO()
    sys.stdout = first
    try:
        mod.main([])
    finally:
        sys.stdout = saved_stdout
    second = io.StringIO()
    sys.stdout = second
    try:
        silent = mod.main([])
    finally:
        sys.stdout = saved_stdout
    check(
        "delivered alerts do not repeat on the next run",
        silent == 0 and first.getvalue() and not second.getvalue(),
        f"first {len(first.getvalue())} chars, second {len(second.getvalue())} chars",
    )

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
