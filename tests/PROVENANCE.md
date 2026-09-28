# Tests

Recovered 2026-09-23 from `/tmp`, where both suites had been sitting since 2026-09-19. `/tmp`
on the machine that wrote them is tmpfs, so they were one reboot from being gone.

| File | What it is |
|---|---|
| `test_jev_screen.py` | The hook suite. Registers 16 checks against the hook path a live session calls (`_on_transform_tool_result`): a benign passage passes through byte-identical, an injection is flagged and replaced by the banner, repeat content is served from cache without a second alert, noise is not screened, a missing client fails open, the queued alert carries a verdict and no page content, and the offline path answers recorded content only. Alert and screen-log paths are redirected to `/tmp/jev-screen-test/` so a run can never land in a live queue. |
| `e2e_jev_screen.py` | End-to-end proof through production discovery: imports `model_tools`, so plugin discovery fires exactly as it does in a live session, then calls `web_extract` for real against a hostile public page and an ordinary documentation page. Two checks: the banner is appended to the hostile result, and the benign result is untouched. |
| `fixtures/hostile.html`, `fixtures/benign.html` | The two pages the end-to-end run fetched, kept as offline fixtures. The script itself defaults to live URLs. |
| `fixtures/classifier/replay.json` | Recorded classifier answers for the hook suite's two texts, keyed by payload digest. Replayed only when `JEV_OFFLINE` is set or no key resolves, and only for an exact digest match, so an unseen payload still fails instead of receiving a canned verdict. Re-record with `python3 scripts/record-replay-fixtures.py`. |
| `fixtures/probe/web_hazard.jsonl` | The authored corpus the probe harness grades: 12 passages, 6 benign and 6 hostile, labels true by construction. This is the corpus behind the published N=12 figure. |
| `fixtures/probe/skill_roster.json` | An invented roster for the probe harness's `skill_route` arm. No published figure was measured against it. |

## Running them

- `test_jev_screen.py` is stdlib only and runs under any `python3`. It loads the adapter in
  this checkout by default, so a clone tests what it ships. To test an installed copy
  instead: `JEV_PLUGIN_PATH=~/.hermes/plugins/jev-screen/__init__.py python3 tests/test_jev_screen.py`
- Screening reaches the classifier when a key is present and replays the recording in
  `fixtures/classifier/replay.json` when it is not, so the suite is a gate on a machine with
  no key. Force the offline path with `JEV_OFFLINE=1`.
- `e2e_jev_screen.py` must run under the interpreter the agent uses:
  `~/.hermes/hermes-agent/venv/bin/python e2e_jev_screen.py`, with `HOST_E2E=1` through
  `scripts/run-suites.sh`. It imports the host's own modules, so it cannot run in CI.
- Neither suite is pytest. Both are scripts that print `N/N checks passed` and exit non-zero
  on failure.

## Why a `tests/` directory

The adapter's loader reads `plugin.yaml` and `__init__.py` and ignores the rest, so the
suites can live beside the code they exercise without being discovered as plugin content.
Keeping them here is what let publication start from a working copy instead of a rewrite.