#!/usr/bin/env python3
"""jev.py — the only thing on this box that talks to api.typesafe.ai.

Design rule: the egress gate is the product, the model call is incidental. Every
request passes a task class declared in TASKS; a class that is not declared is
refused. Nothing here is ever wired into the agent's model path, and no caller
may bypass this module to reach the API.

Safe by default: without --live the CLI builds, redacts, guards and reports the
payload but sends nothing. --live is the single, explicit switch.

Offline tests (no network, no key needed):  python3 jev.py selftest
Key presence, booleans only:               python3 jev.py key-check
Preview a real payload:                    python3 jev.py ask --class <c> --state-file <f> --questions-file <f>
Send it:                                   python3 jev.py ask --class <c> ... --live
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ENDPOINT = os.environ.get("TYPESAFE_ENDPOINT") or "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = os.environ.get("TYPESAFE_MODEL") or "jev-latest"
KEY_NAME = "TYPESAFE_API_KEY"
BWS_CACHE = Path.home() / ".hermes" / "cache" / "bws_cache.json"
HOME_DIR = Path(__file__).resolve().parent
LOG_PATH = HOME_DIR / "send-log.jsonl"

# --- egress policy -----------------------------------------------------------
# The maintenance point of this module. Each class names what it is allowed to
# send. "public" redacts only secrets-shaped strings, because the input is
# already public. "internal" additionally strips anything that identifies this
# box or the people on it.
TASKS: dict[str, dict] = {
    "oss_triage": {
        "sends": "public GitHub text: issue bodies, commit messages, changelogs, PR diffs",
        "redaction": "public",
        "max_bytes": 40_000,
        "truncate": False,
    },
    "web_hazard": {
        "sends": "untrusted third-party page/feed text we scraped",
        "redaction": "public",
        "max_bytes": 20_000,
        "truncate": True,
    },
    "cron_triage": {
        "sends": "output of our own watchdog scripts",
        "redaction": "internal",
        "max_bytes": 8_000,
        "truncate": False,
    },
    "skill_route": {
        "sends": "the current user turn plus the public Hermes skill index",
        "redaction": "internal",
        "max_bytes": 12_000,
        "truncate": False,
    },
}

# Refused outright, regardless of class: strings whose presence means the caller
# is about to ship something that belongs in no third-party model, ever.
#
# The built-in list is deliberately short and generic. A hard refusal on a string
# that turns up in ordinary public text (an issue body that mentions API_KEY, say)
# would refuse legitimate work, so the class-specific policy belongs in the
# per-class "redaction" field, not here. Your own names go in the config file
# below, which is merged with these defaults.
#
# The key headers are assembled from two pieces on purpose: a source file that
# argues about credential literals should not itself contain a complete one.
DEFAULT_PRIVATE_MARKERS = (
    "-----BEGIN " "OPENSSH PRIVATE KEY-----",
    "-----BEGIN " "RSA PRIVATE KEY-----",
    "-----BEGIN " "EC PRIVATE KEY-----",
    "-----BEGIN " "PGP PRIVATE KEY BLOCK-----",
    "BWS_ACCESS_TOKEN",
    "TYPESAFE_API_KEY",
)

# Strings that identify your host, your domains or the people on it. Added to
# redaction for the "internal" profile so internal text can travel without
# carrying your layout. Empty by default, because only you know these.
DEFAULT_INTERNAL_MARKERS: tuple[str, ...] = ()

# Optional config: one JSON object whose keys are both lists of strings.
#   {"refuse": ["acme-vault", "ACME_API_KEY"], "internal": ["example.com", "@me"]}
# A missing or malformed file is not an error. The defaults apply, the gate is
# exactly as strict as before, and nothing raises: a bad config must never be
# able to break a caller that is already screening untrusted text.
CONFIG_PATH = Path(
    os.environ.get("JEV_MARKERS_CONFIG")
    or (Path.home() / ".config" / "precontext-screen" / "markers.json")
)


def load_marker_config(path: Path | None = None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Read the optional refuse/internal marker lists. Returns empty on any failure."""
    target = CONFIG_PATH if path is None else path
    try:
        blob = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return (), ()
    if not isinstance(blob, dict):
        return (), ()
    found: list[tuple[str, ...]] = []
    for key in ("refuse", "internal"):
        values = blob.get(key)
        if isinstance(values, list):
            found.append(tuple(str(v) for v in values if isinstance(v, str) and v))
        else:
            found.append(())
    return found[0], found[1]


_CONFIG_REFUSE, _CONFIG_INTERNAL = load_marker_config()
PRIVATE_MARKERS = DEFAULT_PRIVATE_MARKERS + _CONFIG_REFUSE
OUR_MARKERS = DEFAULT_INTERNAL_MARKERS + _CONFIG_INTERNAL

_SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<private-key>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "<jwt>"),
    (re.compile(r"\b(?:sk|pk|ghp|gho|ghs|github_pat|xox[baprs]|bws|AIza)[-_A-Za-z0-9]{16,}\b"), "<token>"),
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b(\s*[:=]\s*)\S+"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer <redacted>"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
)

_INTERNAL_PATTERNS = (
    (re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s\"'`,;)]*)?"), "/<path>"),
    (re.compile(r"(?<![\w/.])/(?:etc|var|opt|srv|root|run|usr|tmp)(?:/[^\s\"'`,;)]*)?"), "/<path>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{7,40}\b(?=\s|$|[^\w-])"), "<hash>"),
    (re.compile(r"\+?\d[\d\s().-]{7,}\d"), "<phone>"),
    (re.compile(r"(?<![A-Za-z0-9_])@[A-Za-z0-9][A-Za-z0-9_-]{2,}"), "@user"),
)


class PolicyError(Exception):
    """Raised when a payload is not allowed to leave this machine."""


class TransportError(Exception):
    """Raised when the API could not be reached or returned an unusable body."""


# --- secrets ------------------------------------------------------------------
def load_key() -> str | None:
    """Env first, then the Bitwarden cache the gateway writes.

    Cron and short-lived agent processes do not inherit the gateway's env, and a
    cron process cannot call bws itself (the access token is consumed at startup),
    so reading the cache is the supported second path. Value is never logged.
    """
    key = os.environ.get(KEY_NAME)
    if key:
        return key
    try:
        blob = json.loads(BWS_CACHE.read_text())
    except (OSError, ValueError):
        return None
    secrets_map = blob.get("secrets") if isinstance(blob, dict) else None
    if isinstance(secrets_map, dict):
        value = secrets_map.get(KEY_NAME)
        if isinstance(value, str) and value:
            return value
    return None


def key_state() -> dict:
    """Booleans and lengths only — never the value, not even partially."""
    env_key = os.environ.get(KEY_NAME)
    cached = load_key() if not env_key else None
    return {
        "env": bool(env_key),
        "env_len": len(env_key) if env_key else 0,
        "bws_cache": BWS_CACHE.exists(),
        "resolved": bool(env_key or cached),
        "source": "env" if env_key else ("bws_cache" if cached else "none"),
    }


# --- gate ---------------------------------------------------------------------
def redact(text: str, profile: str,
           our_markers: tuple[str, ...] | None = None) -> tuple[str, dict[str, int]]:
    """Redact for one profile. our_markers defaults to the configured set."""
    counts: dict[str, int] = {}
    markers = OUR_MARKERS if our_markers is None else our_markers
    patterns = _SECRET_PATTERNS + (_INTERNAL_PATTERNS if profile == "internal" else ())
    for pattern, replacement in patterns:
        text, hits = pattern.subn(replacement, text)
        if hits:
            counts[pattern.pattern[:28]] = counts.get(pattern.pattern[:28], 0) + hits
    if profile == "internal":
        for marker in markers:
            if marker in text:
                text, hits = re.subn(re.escape(marker), "<ours>", text)
                counts[f"ours:{marker}"] = hits
    return text, counts


def guard(task_class: str, state: str,
          private_markers: tuple[str, ...] | None = None) -> tuple[str, dict[str, int]]:
    """Redact, then decide whether the result is allowed to leave."""
    refused = PRIVATE_MARKERS if private_markers is None else private_markers
    if task_class not in TASKS:
        raise PolicyError(
            f"task class {task_class!r} is not declared; declared: {', '.join(sorted(TASKS))}"
        )
    spec = TASKS[task_class]
    for marker in refused:
        if marker in state:
            raise PolicyError(
                f"payload contains private marker {marker!r} — refusing to send under any class"
            )
    cleaned, counts = redact(state, spec["redaction"])
    size = len(cleaned.encode())
    if size > spec["max_bytes"]:
        if not spec["truncate"]:
            raise PolicyError(
                f"{size} bytes exceeds {spec['max_bytes']} for class {task_class!r}; "
                "shrink the input rather than raising the cap"
            )
        clipped = cleaned.encode()[: spec["max_bytes"]].decode(errors="ignore")
        cleaned = clipped + f"\n[...truncated by jev.py at {spec['max_bytes']} bytes]"
        counts["truncated"] = 1
    return cleaned, counts


def build_payload(state: str, questions: dict, model: str = DEFAULT_MODEL) -> dict:
    if not isinstance(questions, dict) or not questions:
        raise PolicyError("questions must be a non-empty dict of question-id -> definition")
    return {"state": state, "model": model, "questions": questions}


# --- transport ----------------------------------------------------------------
def _post(payload: dict, key: str, timeout: float = 60.0) -> tuple[int, dict, float]:
    """One HTTP call. Retries 429/5xx twice with backoff; never retries 4xx."""
    body = json.dumps(payload).encode()
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    last: Exception | None = None
    for attempt in range(3):
        started = time.monotonic()
        try:
            req = urllib.request.Request(ENDPOINT, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode()
                return resp.status, json.loads(raw), (time.monotonic() - started) * 1000
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="ignore")[:400]
            if exc.code in (429, 500, 502, 503, 504) and attempt < 2:
                last = TransportError(f"HTTP {exc.code}: {detail}")
                time.sleep(2**attempt)
                continue
            raise TransportError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            last = exc
            if attempt < 2:
                time.sleep(2**attempt)
                continue
            raise TransportError(f"{type(exc).__name__}: {exc}") from exc
    raise TransportError(f"exhausted retries: {last}")


def log_call(record: dict) -> None:
    """Append one line per call. Payloads are never written, only their digest."""
    allowed = {
        "ts", "task_class", "model", "payload_sha256", "bytes_sent", "http_status",
        "latency_ms", "input_tokens", "output_tokens", "answers", "ok", "error",
    }
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a") as handle:
        handle.write(json.dumps({k: v for k, v in record.items() if k in allowed}) + "\n")
    os.chmod(LOG_PATH, 0o600)


def ask(
    task_class: str,
    state: str,
    questions: dict,
    model: str = DEFAULT_MODEL,
    dry_run: bool = True,
    timeout: float = 60.0,
) -> dict:
    cleaned, counts = guard(task_class, state)
    payload = build_payload(cleaned, questions, model)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    report = {
        "task_class": task_class,
        "model": model,
        "sends": TASKS[task_class]["sends"],
        "redactions": counts,
        "bytes_sent": len(json.dumps(payload).encode()),
        "payload_sha256": digest,
        "payload": payload,
        "dry_run": dry_run,
    }
    if dry_run:
        return report

    key = load_key()
    if not key:
        raise PolicyError(f"{KEY_NAME} is not in the environment and not in {BWS_CACHE}")
    status, body, latency = _post(payload, key, timeout)
    answers = body.get("answers", {})
    usage = body.get("usage", {})
    log_call({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "task_class": task_class,
        "model": body.get("model", model),
        "payload_sha256": digest,
        "bytes_sent": report["bytes_sent"],
        "http_status": status,
        "latency_ms": round(latency, 1),
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "answers": answers,
        "ok": True,
    })
    report.update({"latency_ms": round(latency, 1), "answers": answers, "usage": usage,
                   "model": body.get("model", model)})
    return report


# --- offline tests ------------------------------------------------------------
def selftest() -> int:
    """Prove the gate works without touching the network. No key required."""
    results: list[tuple[str, bool, str]] = []

    def check(name: str, condition: bool, note: str = "") -> None:
        results.append((name, bool(condition), note))

    # 1. redaction of secrets in the public profile
    FAKE_KEY = "sk-test" + "0" * 18  # assembled: no token-shaped literal in the source

    dirty = f"key {FAKE_KEY} token and mail bob@example.com"
    clean, counts = redact(dirty, "public")
    check("public redaction kills tokens", FAKE_KEY not in clean)
    check("public redaction kills emails", "bob@example.com" not in clean)
    check("public redaction counts hits", len(counts) >= 2, str(counts))

    # 2. internal profile strips paths, addresses and the configured markers
    internal = "gateway vault.acme.test at /home/example/projects and 203.0.113.9"
    clean_i, counts_i = redact(internal, "internal", our_markers=("vault.acme.test",))
    for needle in ("vault.acme.test", "/home/example", "203.0.113.9"):
        check(f"internal redaction kills {needle[:18]}", needle not in clean_i)
    check("internal flags configured markers",
          any(k.startswith("ours:") for k in counts_i), str(counts_i))

    # 3. public profile must NOT mangle legitimate public data
    public_text = "github.com/NousResearch/hermes-agent PR #114422 by @ruangraung"
    clean_p, _ = redact(public_text, "public")
    check("public text survives public profile", "github.com" in clean_p and "#114422" in clean_p)

    # 4. undeclared class is refused
    try:
        guard("definitely_not_a_class", "hello")
        check("undeclared class refused", False)
    except PolicyError:
        check("undeclared class refused", True)

    # 5. private markers refused even under a declared class, both from the
    # built-in defaults (private_markers=None) and from an injected set
    for marker, extra in (("BWS_ACCESS_TOKEN", None), ("acme-vault", ("acme-vault",))):
        try:
            guard("web_hazard", f"innocent text mentioning {marker}", private_markers=extra)
            check(f"refused payload with {marker}", False)
        except PolicyError:
            check(f"refused payload with {marker}", True)

    # 5b. a private key block is refused, not redacted and sent
    try:
        guard("web_hazard", "here is the key: " + "-----BEGIN " "OPENSSH PRIVATE KEY-----")
        check("refused payload with a private key block", False)
    except PolicyError:
        check("refused payload with a private key block", True)

    # 5c. the optional marker config is read, and a bad one degrades to empty
    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "markers.json"
        good.write_text(json.dumps({"refuse": ["my-vault"], "internal": ["acme.test"]}))
        refuse, internal_markers = load_marker_config(good)
        check("config markers load",
              refuse == ("my-vault",) and internal_markers == ("acme.test",),
              f"{refuse} {internal_markers}")
        broken = Path(tmp) / "broken.json"
        broken.write_text("{not json")
        refuse_b, internal_b = load_marker_config(broken)
        check("malformed config degrades to empty",
              refuse_b == () and internal_b == (), str(refuse_b))

    # 6. oversize refused where truncate is off, truncated where it is on
    try:
        guard("cron_triage", "x" * 9_000)
        check("oversize refused (cron_triage)", False)
    except PolicyError:
        check("oversize refused (cron_triage)", True)
    big, _ = guard("web_hazard", "y" * 25_000)
    check("oversize truncated (web_hazard)", "truncated by jev.py" in big and len(big) < 25_000)

    # 7. payload shape matches the published contract
    payload = build_payload("some state", {"q": {"type": "noul", "instructions": "Is it true?"}})
    check("payload has state/model/questions",
          set(payload) == {"state", "model", "questions"}, str(sorted(payload)))
    check("payload model defaults to jev-latest", payload["model"] == "jev-latest", payload["model"])

    # 8. empty question set refused
    try:
        build_payload("state", {})
        check("empty questions refused", False)
    except PolicyError:
        check("empty questions refused", True)

    # 9. dry-run performs NO network call (transport poisoned)
    global _post
    original = _post

    def poisoned(*_a, **_k):  # noqa: ANN002, ANN003
        raise AssertionError("network call attempted during dry-run")

    _post = poisoned
    try:
        report = ask("oss_triage", "public text only", {"q": {"type": "noul", "instructions": "?"}})
        check("dry-run sends nothing", report["dry_run"] is True)
        check("dry-run returns the payload for review", "payload" in report)
    except AssertionError:
        check("dry-run sends nothing", False, "transport was reached")
    finally:
        _post = original

    # 10. the log writer drops anything not on the allow-list
    probe_log = HOME_DIR / "selftest-log.jsonl"
    global LOG_PATH
    real_log = LOG_PATH
    LOG_PATH = probe_log
    try:
        log_call({"ts": "now", "task_class": "oss_triage", "payload": {"state": "LEAK"}, "ok": True})
        written = probe_log.read_text()
        check("log never stores payloads", "LEAK" not in written, written.strip()[:80])
        check("log stores the allow-listed fields", '"task_class"' in written)
    finally:
        LOG_PATH = real_log
        probe_log.unlink(missing_ok=True)

    # 11. key loader understands both shapes and never needs the real key
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp) / "cache.json"
        fake.write_text(json.dumps({"secrets": {KEY_NAME: "x" * 20}}))
        global BWS_CACHE
        real_cache = BWS_CACHE
        BWS_CACHE = fake
        try:
            os.environ.pop(KEY_NAME, None)
            check("cache fallback resolves a key", bool(load_key()))
        finally:
            BWS_CACHE = real_cache

    passed = sum(1 for _, ok, _ in results if ok)
    for name, ok, note in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"   ({note})" if note and not ok else ""))
    print(f"\n  {passed}/{len(results)} checks passed")
    return 0 if passed == len(results) else 1


# --- CLI ----------------------------------------------------------------------
def _load(path_or_inline: str | None, inline_args: list[str]) -> str | None:
    if inline_args:
        return " ".join(inline_args)
    if path_or_inline:
        candidate = Path(path_or_inline)
        if candidate.exists():
            return candidate.read_text()
        return path_or_inline
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gated client for api.typesafe.ai (dry-run by default)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest", help="offline tests of the gate; sends nothing")
    sub.add_parser("key-check", help="report key presence as booleans")
    sub.add_parser("policy", help="print the declared task classes")

    askp = sub.add_parser("ask", help="build a request (sends nothing without --live)")
    askp.add_argument("--class", dest="task_class", required=True)
    askp.add_argument("--state-file", help="file with the state, or the state itself")
    askp.add_argument("--state", nargs=argparse.REMAINDER, help="state inline")
    askp.add_argument("--questions-file", required=True, help="JSON file with the questions dict")
    askp.add_argument("--model", default=DEFAULT_MODEL)
    askp.add_argument("--timeout", type=float, default=60.0)
    askp.add_argument("--live", action="store_true", help="actually send it")
    askp.add_argument("--answers-only", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "key-check":
        print(json.dumps(key_state(), indent=2))
        return 0
    if args.cmd == "policy":
        for name, spec in TASKS.items():
            print(f"{name:14} sends: {spec['sends']}")
            print(f"{'':14} redaction={spec['redaction']} max_bytes={spec['max_bytes']} truncate={spec['truncate']}")
        print("\nRefused outright if the payload contains any of:")
        for marker in PRIVATE_MARKERS:
            print(f"  - {marker}")
        state = "present" if CONFIG_PATH.exists() else "absent, defaults only"
        print(f"\nMarker config: {CONFIG_PATH} ({state})")
        if _CONFIG_INTERNAL:
            print(f"Internal markers from config: {', '.join(_CONFIG_INTERNAL)}")
        return 0

    state = _load(args.state_file, args.state)
    if not state:
        parser.error("provide --state-file or --state")
    try:
        questions = json.loads(Path(args.questions_file).read_text())
    except (OSError, ValueError) as exc:
        parser.error(f"could not read questions: {exc}")

    try:
        report = ask(args.task_class, state, questions, args.model, dry_run=not args.live,
                     timeout=args.timeout)
    except (PolicyError, TransportError) as exc:
        print(f"REFUSED/FAILED: {exc}", file=sys.stderr)
        return 2

    if args.answers_only and "answers" in report:
        print(json.dumps(report["answers"], indent=2))
        return 0
    print(json.dumps(report, indent=2)[:6000])
    if report.get("dry_run"):
        print("\n(DRY RUN — nothing was sent. Add --live to send.)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
