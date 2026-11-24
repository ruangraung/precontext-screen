#!/usr/bin/env python3
"""Hold the README's contract prose to the suites and the client it describes.

Documentation drift is a gate failure here, not a review comment. The adapter contract
cannot regain a length floor the hook removed, the testing section cannot describe a check
the suites do not register, and the one hardcoded figure the testing section carries, the
client selftest's count, is compared against the selftest's own printed total every run.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    readme = README.read_text(encoding="utf-8")
    # Prose fragments are matched wrap-agnostic: the file's authored prose is
    # line-wrapped, so a fragment must match across a line break as a reader reads it.
    flat = " ".join(readme.split())

    # 1. the adapter contract screens every non-empty string result, with no floor
    claims_all = "Every non-empty string result is screened" in readme
    floor_reintroduced = (
        re.search(r"[Ff]loor \([0-9]+ characters|[0-9]+ characters here", readme) is not None
    )
    check(
        "the adapter contract has no length floor",
        claims_all and not floor_reintroduced,
        "floor sentence present"
        if floor_reintroduced
        else "all-results claim missing"
        if not claims_all
        else "",
    )

    # 2. every check the testing section describes is registered in a suite source
    hook_pairs = [
        (
            "a tiny result reaches the screener",
            "tiny result reaches the screener",
            "tests/test_precontext_screen.py",
        ),
        (
            "unscreened tools are skipped",
            "unscreened tool skipped",
            "tests/test_precontext_screen.py",
        ),
        (
            "a missing client fails open",
            "client missing -> fails open",
            "tests/test_precontext_screen.py",
        ),
        (
            "the banner names the plugin exactly as its manifest does",
            "banner names the plugin as the manifest does",
            "tests/test_precontext_screen.py",
        ),
        (
            "a page that fits the class byte cap is judged whole",
            "a 6,000-character page is judged whole",
            "tests/test_screen_coverage.py",
        ),
        (
            "an over-cap page fills the cap",
            "an over-cap page fills the class cap",
            "tests/test_screen_coverage.py",
        ),
        (
            "a partly judged page is logged partial",
            "a partly judged page is logged partial",
            "tests/test_screen_coverage.py",
        ),
        (
            "a crafted answer field cannot speak inside the banner",
            "a crafted answer field cannot speak inside the banner",
            "tests/test_screen_coverage.py",
        ),
    ]
    for readme_fragment, suite_fragment, suite_file in hook_pairs:
        prose = readme_fragment in flat
        registered = suite_fragment in (REPO / suite_file).read_text(encoding="utf-8")
        check(
            f"described check is registered: {readme_fragment[:44]}",
            prose and registered,
            f"prose={prose} registered={registered} in {suite_file}",
        )

    # 3. the one hardcoded figure agrees with the client selftest's printed total
    figure = re.search(r"selftest\s+# ([0-9]+) checks", readme)
    run = subprocess.run(
        [sys.executable, str(REPO / "screen" / "jev.py"), "selftest"],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": ""},
    )
    printed = re.search(r"([0-9]+)/[0-9]+ checks passed", run.stdout)
    figure_honest = (
        figure is not None and printed is not None and figure.group(1) == printed.group(1)
    )
    check(
        "the selftest figure matches the selftest's printed total",
        figure_honest,
        f"readme says {figure.group(1) if figure else 'no figure'}, selftest prints {printed.group(1) if printed else 'nothing'}",
    )

    # 4. no other hardcoded suite count remains in the testing section
    figures = re.findall(r"# ([0-9]+) checks", readme)
    lone_figure = figures == [printed.group(1)] if printed else not figures
    check(
        "no hardcoded suite counts beside the selftest figure",
        lone_figure,
        f"figures found: {figures}",
    )

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
