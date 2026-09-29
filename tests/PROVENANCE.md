# Tests

Recovered 2026-09-23 from `/tmp`, where both suites had been sitting since 2026-09-19. `/tmp`
on the machine that wrote them is tmpfs, so they were one reboot from being gone.

| File | What it is |
|---|---|
| `test_precontext_screen.py` | The hook suite. Registers 17 checks against the hook path a live session calls (`_on_transform_tool_result`): a benign passage passes through byte-identical, an injection is flagged and replaced by the banner, repeat content is served from cache without a second alert, noise is not screened, a missing client fails open, the queued alert carries a verdict and no page content, the offline path answers recorded content only, and the banner names the plugin exactly as its manifest does. Alert and screen-log paths are redirected to `/tmp/precontext-screen-test/` so a run can never land in a live queue. |
| `e2e_precontext_screen.py` | End-to-end proof through production discovery: imports `model_tools`, so plugin discovery fires exactly as it does in a live session, then calls `web_extract` for real against a hostile public page and an ordinary documentation page. Two checks: the banner is appended to the hostile result, and the benign result is untouched. Because the run walks the production path, it patches the discovered plugin's alert and screen-log paths to `/tmp/precontext-screen-test/` before the first call and refuses to start if that module cannot be found, so it cannot leave a test alert in a live queue. |
| `test_publish_hygiene.sh` | The gate's own suite, six checks, all canaries synthetic so it carries no personal terms and is safe to publish: a clean tree passes, a pattern from the local file is caught with the builtins loaded, an env pattern is caught, two sources stay separate rather than fusing into one pattern, an emptied rule set fails closed, and the gate passes on this repository (no pattern matches its own definition). |
| `fixtures/hostile.html`, `fixtures/benign.html` | Authored stand-in pages with invented content, kept as the hook suite's offline fixtures. They are **not** what the end-to-end run fetches: `e2e_precontext_screen.py` pulls live public URLs by default, the PayloadsAllTheThings prompt-injection page for the hostile arm and an MDN documentation page for the benign one. Authored fixtures need no third-party attribution, which is why these are the ones kept in the tree. |
| `fixtures/classifier/replay.json` | Recorded classifier answers for the hook suite's two texts, keyed by payload digest. Replayed only when `JEV_OFFLINE` is set or no key resolves, and only for an exact digest match, so an unseen payload still fails instead of receiving a canned verdict. Re-record with `python3 scripts/record-replay-fixtures.py`. |
| `fixtures/probe/web_hazard.jsonl` | The authored corpus the probe harness grades: 12 passages, 6 benign and 6 hostile, labels true by construction. This is the corpus behind the published N=12 figure. |
| `fixtures/probe/skill_roster.json` | An invented roster for the probe harness's `skill_route` arm. No published figure was measured against it. |

## Running them

- `test_precontext_screen.py` is stdlib only and runs under any `python3`. It loads the
  adapter in this checkout by default, so a clone tests what it ships. To test an installed
  copy instead:
  `JEV_PLUGIN_PATH=~/.hermes/plugins/<plugin-name>/__init__.py python3 tests/test_precontext_screen.py`
- Screening reaches the classifier when a key is present and replays the recording in
  `fixtures/classifier/replay.json` when it is not, so the suite is a gate on a machine with
  no key. Force the offline path with `JEV_OFFLINE=1`.
- `e2e_precontext_screen.py` must run under the interpreter the agent uses:
  `~/.hermes/hermes-agent/venv/bin/python e2e_precontext_screen.py`, with `HOST_E2E=1` through
  `scripts/run-suites.sh`. It imports the host's own modules, so it cannot run in CI.
- Neither suite is pytest. Both are scripts that print `N/N checks passed` and exit non-zero
  on failure.

## Why a `tests/` directory

The adapter's loader reads `plugin.yaml` and `__init__.py` and ignores the rest, so the
suites can live beside the code they exercise without being discovered as plugin content.
Keeping them here is what let publication start from a working copy instead of a rewrite.