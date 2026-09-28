#!/usr/bin/env python3
"""Delivery for precontext-screen: print any NEW injection flags, and nothing when there are none.

Runs as a ``no_agent`` Hermes cron job, so the printed text is delivered verbatim to
Telegram and a silent run costs zero tokens. The cursor is a line count, so an interrupted
run re-delivers rather than losing an alert.

Deliberately reads only the alert records the plugin wrote: timestamp, tool, source, the
Jev signals, a content hash, the profile home. Never the screened content itself.

The same page fetched by two profiles is ONE incident, not two — profile homes are separate
processes, so the digest collapses identical content hashes into one line naming every
profile that reported it.

Usage:
    python3 alert-digest.py            # print new flags since the cursor
    python3 alert-digest.py --all      # print everything, ignoring the cursor
    python3 alert-digest.py --status   # one line: totals + cursor position
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


def _shared_dir() -> Path:
    """Where the plugin writes its alerts and where this job reads them.

    The plugin resolves this in one more step than the digest does: a checkout writes
    beside the client it ships, while a host install writes to the default below. This job
    runs on the host, so it has no checkout to look beside and JEV_STATE_DIR is the only
    override it honours. Pointing that at a checkout's screen directory is what lets a
    clone deliver its own alerts without touching the host queue.
    """
    override = os.environ.get("JEV_STATE_DIR")
    return Path(override) if override else Path.home() / ".hermes" / "scripts" / "jev"


SHARED = _shared_dir()
ALERTS = SHARED / "alerts.jsonl"
CURSOR = SHARED / "alerts-cursor.json"
MAX_LINES = 12


def _read_cursor() -> int:
    try:
        data = json.loads(CURSOR.read_text(encoding="utf-8"))
        return int(data.get("delivered", 0))
    except Exception:
        return 0


def _write_cursor(delivered: int) -> None:
    try:
        CURSOR.write_text(
            json.dumps(
                {
                    "delivered": delivered,
                    "updated": datetime.now(UTC).isoformat(timespec="seconds"),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        CURSOR.chmod(0o600)
    except Exception:
        pass


def _load() -> list[dict]:
    try:
        lines = ALERTS.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except Exception:
        return []
    out: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def _home_label(home: str) -> str:
    """Absolute profile home -> something readable inside a chat message."""
    if not home:
        return "unknown profile"
    parts = Path(home).parts
    if "profiles" in parts:
        index = parts.index("profiles")
        if index + 1 < len(parts):
            return f"profile {parts[index + 1]}"
    return "default profile"


def _collapse(records: list[dict]) -> list[dict]:
    """One entry per distinct content hash, carrying every profile that reported it."""
    grouped: list[dict] = []
    seen: dict[str, dict] = {}
    for record in records:
        key = record.get("sha256") or f"unhashed-{len(grouped)}-{record.get('ts', '')}"
        if key in seen:
            label = _home_label(record.get("home") or "")
            if label not in seen[key]["homes"]:
                seen[key]["homes"].append(label)
            continue
        entry = dict(record)
        entry["homes"] = [_home_label(record.get("home") or "")]
        seen[key] = entry
        grouped.append(entry)
    return grouped


def _fmt_ts(iso: str) -> str:
    """UTC iso -> local wall clock for the configured zone (default Asia/Jakarta)."""
    try:
        stamp = datetime.fromisoformat(iso)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=UTC)
        return stamp.astimezone().strftime("%d %b %Y %H:%M")
    except Exception:
        return iso


def _score(value) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "?"


def _line(index: int, record: dict) -> str:
    tool = record.get("tool") or "?"
    source = record.get("source") or "(no url in the call)"
    sha = record.get("sha256") or "?"
    parts = [
        f"{index}. {_fmt_ts(record.get('ts', ''))} · {tool} · "
        f"overrides {_score(record.get('overrides'))} "
        f"addressed-to-ai {_score(record.get('addressed_to_ai'))}",
        f"   {source}",
        f"   flagged before acting, then handed to the agent as data "
        f"(sha {sha}, {record.get('chars', '?')} chars)",
    ]
    homes = record.get("homes") or (
        [_home_label(record.get("home") or "")] if record.get("home") else []
    )
    if homes:
        label = "seen by" if len(homes) > 1 else "profile"
        parts.append(f"   {label}: {', '.join(homes)}")
    return "\n".join(parts)


def main(argv: list[str]) -> int:
    if "--status" in argv:
        records = _load()
        delivered = _read_cursor()
        pending = max(0, len(records) - delivered)
        print(
            f"precontext-screen alerts: {len(records)} total, {delivered} delivered, {pending} pending"
        )
        print(f"({len(_collapse(records))} distinct page(s) among them)")
        print(f"file: {ALERTS}")
        return 0

    show_all = "--all" in argv
    records = _load()
    start = 0 if show_all else _read_cursor()
    fresh = records[start:]
    if not fresh:
        return 0  # silence: nothing new, nothing delivered, no tokens spent

    grouped = _collapse(fresh)
    hidden = max(0, len(grouped) - MAX_LINES)
    shown = grouped[-MAX_LINES:]
    noun = "page" if len(grouped) == 1 else "pages"
    header = f"🛡️ Injection screen: {len(grouped)} flagged {noun} since last check"
    if len(fresh) != len(grouped):
        header += f" ({len(fresh)} reports — one page can be seen by both profiles)"
    if show_all:
        header = f"🛡️ Injection screen: {len(grouped)} flagged {noun} on file"
    body = [header, ""]
    for i, record in enumerate(shown, start=1):
        body.append(_line(i, record))
        body.append("")
    if hidden:
        body.append(f"(+{hidden} earlier flag(s) not shown)")
        body.append("")
    body.append(
        "No instruction on any of them was followed. Detail: ~/.hermes/scripts/jev/alerts.jsonl"
    )
    print("\n".join(body))
    _write_cursor(len(records))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
