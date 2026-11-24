#!/usr/bin/env python3
"""Exercise the egress client's redaction: what leaves this machine never carries a credential.

The public profile is what untrusted text travels under, so the checks pin its
behaviour: quoted-key credentials and bare long hex are redacted, while the
digests and ordinary prose the pipeline itself writes stay untouched.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLIENT = REPO / "screen" / "jev.py"


def load():
    spec = importlib.util.spec_from_file_location("jev_client_under_test", CLIENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, bool(ok), detail))

    client = load()

    # 1. a credential in JSON-quoted keys is redacted
    quoted_json = '{"password": "hunter2secret", "api_key" : "october-rain-token"}'
    redacted, _ = client.redact(quoted_json, "public")
    check(
        "a JSON-quoted credential is redacted",
        "hunter2secret" not in redacted and "october-rain-token" not in redacted,
        f"redacted: {redacted[:60]!r}",
    )
    check(
        "the quoted-key redaction names what it removed",
        "<redacted>" in redacted,
        f"redacted: {redacted[:60]!r}",
    )

    # 2. a bare long hex value is redacted
    bare_hex = "renew before token a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 expires"
    redacted_hex, _ = client.redact(bare_hex, "public")
    check(
        "a bare 32-hex token is redacted",
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" not in redacted_hex,
        f"redacted: {redacted_hex[:60]!r}",
    )

    # 3. controls: the shapes the pipeline itself writes stay untouched
    unquoted = "password=hunter2secret"
    redacted_plain, _ = client.redact(unquoted, "public")
    check(
        "an unquoted credential is still redacted",
        "hunter2secret" not in redacted_plain,
        f"redacted: {redacted_plain!r}",
    )
    digest_line = "sha256: deadbeefdeadbeef verdict clean"
    redacted_digest, _ = client.redact(digest_line, "public")
    check(
        "short hex digests stay untouched",
        "deadbeefdeadbeef" in redacted_digest,
        f"redacted: {redacted_digest!r}",
    )
    prose = "See https://example.com/guide for the CSS grid layout notes."
    redacted_prose, _ = client.redact(prose, "public")
    check(
        "ordinary prose is untouched",
        redacted_prose == prose,
        f"redacted: {redacted_prose!r}",
    )

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
