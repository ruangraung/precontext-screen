# jev-screen tests

Recovered 2026-09-23 from `/tmp`, where both suites had been sitting since 2026-09-19. `/tmp` on this host is tmpfs, so they were one reboot from being gone.

| File | Lines | What it is |
|---|---|---|
| `test_jev_screen.py` | 129 | The hook suite. Registers 14 checks against the real hook path (`_on_transform_tool_result`) with real Jev calls. Alert and screen-log paths are redirected to `/tmp/jev-screen-test/` so a test run can never land in the live queue the digest job delivers. |
| `e2e_jev_screen.py` | 69 | End-to-end proof through production discovery: imports `model_tools`, so plugin discovery fires exactly as it does in a live session, then calls `web_extract` for real against a hostile public page and an ordinary documentation page. Two checks: banner appended to the hostile result, benign result untouched. |
| `fixtures/hostile.html`, `fixtures/benign.html` | | The two pages the end-to-end run fetched, kept as offline fixtures. The script itself defaults to live URLs. |

## Running them

- `e2e_jev_screen.py` must run under the interpreter the agent uses: `~/.hermes/hermes-agent/venv/bin/python e2e_jev_screen.py`. It reaches the network, so it makes real Jev calls.
- `test_jev_screen.py` is stdlib only and runs under any `python3`. It loads the plugin by absolute path (`~/.hermes/plugins/jev-screen/__init__.py`) and makes real Jev calls too, so it is not an offline test.

Neither suite is pytest. Both are scripts that print `N/N checks passed` and exit non-zero on failure. `test_jev_screen.py` registers exactly 14 checks, which is where the recorded "14/14" comes from.

## Why a `tests/` subdirectory here

The plugin loader reads `plugin.yaml` and `__init__.py` and ignores the rest, verified by `hermes plugins show jev-screen` reporting `Status: enabled` with this directory present. Keeping the suites next to the code they exercise means step 3 of the publication (wire CI, relocate both suites) starts from a working copy instead of a rewrite.
