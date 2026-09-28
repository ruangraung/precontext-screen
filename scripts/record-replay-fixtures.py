#!/usr/bin/env python3
"""record-replay-fixtures.py: capture the two answers the offline path replays.

The hook suite screens the same two texts on every run. Where the classifier cannot be
reached, the client answers those exact payloads from a recording instead, which is what
lets the suite run as a gate on a machine with no key. This script makes that recording.

The recording is keyed on the payload digest, which covers the text and the questions, so
re-run this after changing either one, otherwise the fixture describes an older prompt.
Needs the real key, and sends exactly two requests:

    python3 scripts/record-replay-fixtures.py

Writes tests/fixtures/classifier/replay.json. The send log for those two calls lands in
screen/send-log.jsonl, which is ignored.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path) -> Any:
    """Load one module by path, the same way the adapter loads the client."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    client = load("jev_client", ROOT / "screen" / "jev.py")
    adapter = load("precontext_adapter", ROOT / "adapters" / "hermes" / "__init__.py")
    suite = load("hook_suite", ROOT / "tests" / "test_precontext_screen.py")

    responses: dict[str, dict] = {}
    for label, text in (("benign", suite.BENIGN), ("hostile", suite.HOSTILE)):
        report = client.ask(
            task_class="web_hazard",
            state=adapter._slice(text),
            questions=adapter.QUESTIONS,
            dry_run=False,
            timeout=30.0,
        )
        answers = report["answers"]
        responses[report["payload_sha256"]] = {
            "answers": answers,
            "usage": report["usage"],
            "model": report["model"],
            "source": f"the hook suite's {label} text",
        }
        overrides = (answers.get("overrides_or_conceals") or {}).get("noul")
        print(
            f"recorded {label}: digest={report['payload_sha256'][:16]} "
            f"model={report['model']} overrides_or_conceals={overrides}"
        )

    target = ROOT / "tests" / "fixtures" / "classifier" / "replay.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "note": (
                    "Recorded answers for the hook suite's two fixture texts. Replayed only "
                    "when JEV_OFFLINE is set or no key resolves, and only for an exact "
                    "payload-digest match."
                ),
                "recorded": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "endpoint": client.ENDPOINT,
                "responses": responses,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
