#!/usr/bin/env python3
"""End-to-end proof: real Hermes plugin discovery -> real web_extract -> real hook.

No LLM involved. This walks the production path a live agent session walks:
``model_tools.handle_function_call`` executes the tool and then calls
``_apply_transform_tool_result_hook``, which is where precontext-screen registers. If a banner
comes back from here, it comes back in a real session too.

Run with the Hermes venv interpreter (the one the agent actually uses):
    venv/bin/python e2e_precontext_screen.py [hostile_url] [benign_url]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import ModuleType

HERMES = Path.home() / ".hermes"
sys.path.insert(0, str(HERMES / "hermes-agent"))
os.environ.setdefault("HERMES_HOME", str(HERMES))

import model_tools  # noqa: E402  (import has the plugin-discovery side effect)

SCRATCH = Path("/tmp/precontext-screen-test")


def redirect_runtime_state() -> ModuleType | None:
    """Point the discovered plugin's runtime writes at a scratch directory.

    Discovery has already imported the plugin by the time this runs, so the module is
    patched in place. This script walks the production path on purpose, but an alert it
    produces is a test artifact: it must not land in the queue a digest job delivers from,
    where it would read as a real injection.
    """
    SCRATCH.mkdir(parents=True, exist_ok=True)
    for stale in (SCRATCH / "alerts.jsonl", SCRATCH / "screen-log.jsonl"):
        stale.unlink(missing_ok=True)
    for candidate in list(sys.modules.values()):
        if getattr(candidate, "ALERTS_FILE", None) is None:
            continue
        if getattr(candidate, "_on_transform_tool_result", None) is None:
            continue
        candidate.ALERTS_FILE = SCRATCH / "alerts.jsonl"
        candidate.SCREEN_LOG = SCRATCH / "screen-log.jsonl"
        return candidate
    return None


# A public page that really does carry injection payloads (a well-known security payload
# list), and an ordinary documentation page. Both are third-party content, i.e. exactly
# the input this hook exists to screen.
DEFAULTS = (
    "https://swisskyrepo.github.io/PayloadsAllTheThings/Prompt%20Injection",
    "https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_grid_layout",
)


def main() -> int:
    from hermes_cli.lifecycle import has_hook

    plugin = redirect_runtime_state()
    if plugin is None:
        print(
            "refusing to run: the discovered plugin module was not found, so this run would "
            "write its alert into the live queue",
            file=sys.stderr,
        )
        return 1

    hostile_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULTS[0]
    benign_url = sys.argv[2] if len(sys.argv) > 2 else DEFAULTS[1]

    print(f"plugin under test: {plugin.__file__}")
    print(f"alert writes redirected to: {SCRATCH}")
    print(f"listener registered for transform_tool_result: {has_hook('transform_tool_result')}")
    print(f"hostile arm: {hostile_url}")
    print(f"benign  arm: {benign_url}")
    print()

    results: list[tuple[str, bool, str]] = []

    hostile = model_tools.handle_function_call(
        "web_extract", {"urls": [hostile_url]}, task_id="e2e-screen"
    )
    hostile_flagged = "<INJECTION-SCREEN" in hostile
    results.append(
        (
            "hostile page: banner appended to the tool result",
            hostile_flagged,
            f"{len(hostile)} chars returned",
        )
    )
    if hostile_flagged:
        marker = hostile.find("<INJECTION-SCREEN")
        print("--- what the agent would receive, from the marker on ---")
        print(hostile[marker:][:1200])
        print("--- end ---")
        print()

    benign = model_tools.handle_function_call(
        "web_extract", {"urls": [benign_url]}, task_id="e2e-screen"
    )
    benign_clean = "<INJECTION-SCREEN" not in benign
    results.append(("benign page: result untouched", benign_clean, f"{len(benign)} chars returned"))

    queued = SCRATCH / "alerts.jsonl"
    print(
        f"alert records written to {queued}: {len(queued.read_text().splitlines()) if queued.exists() else 0}"
    )

    failed = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}  [{detail}]")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
