# Semgrep Guardian vs. SecureCoder — Assessment

Source examined: [`semgrep/semgrep@develop:cli/src/semgrep/mcp/`](https://github.com/semgrep/semgrep/tree/develop/cli/src/semgrep/mcp) (README + `server.py` + `hooks/*.py`, read directly from the repo, not just the README).

## What Semgrep Guardian actually is

**Stack**: Python, `FastMCP`, `pydantic`, `httpx`, `opentelemetry` — plus it shells out to the compiled `semgrep` CLI binary itself. Not zero-dependency; installing it means installing Python's Semgrep package *and* the semgrep binary.

**MCP tools** (`server.py`, 1459 lines): `semgrep_scan` / `semgrep_scan_cli` / `semgrep_scan_rpc` / `semgrep_scan_core` (local scan variants), `semgrep_scan_remote` (send code to Semgrep's SaaS), `semgrep_scan_sca` / `semgrep_scan_supply_chain` (dependency vulns), `semgrep_scan_with_custom_rule`, `write_custom_semgrep_rule`, `get_abstract_syntax_tree`, `semgrep_rule_schema` / `get_semgrep_rule_yaml`, `get_supported_languages`, `semgrep_whoami`, `get_deployment_slug`. Far broader tool surface than SecureCoder's 4 tools — notably it lets the *agent* author and test new Semgrep rules live (`write_custom_semgrep_rule` + `get_abstract_syntax_tree`).

**Hooks** (`hooks/`, distinct from the MCP tools):
- `post_tool.py` — PostToolUse hook for Claude Code/Windsurf. Scans the just-written file and returns `{"decision": "block", "reason": [...]}` — this is a **real hard block** enforced by Claude Code's hook protocol, not advisory text.
- **Gate**: if `SEMGREP_APP_TOKEN` is unset, the hook prints a warning and `sys.exit(2)` — **it refuses to scan at all**. The enforcement hook only works if you're logged into Semgrep's AppSec Platform.
- `stop.py` — Cursor-only workaround (Cursor's `afterFileEdit` hook can't return output, so they batch edited files and scan at session-`Stop` instead).
- `inject_secure_defaults.py` — UserPromptSubmit hook that fetches `tldrsec/awesome-secure-defaults`'s README from GitHub over the network (24h cache, static fallback), and injects a generic "prefer these secure-by-default libraries" blurb into context before generation.
- Every hook is wrapped in OpenTelemetry spans that phone home scan/agent/git metadata (`attach_agent_info`, `attach_git_info`, `attach_scan_metrics`).

**Rules/config**: `config="auto"` for interactive MCP scans (Semgrep's registry, ~10k rules, requires `SEMGREP_SEND_METRICS` to stay on unless you pass an explicit config), `config="hooks"` for the hook path (a distinct, presumably faster, server-selected ruleset). Supply Chain and Secrets are separate scan modes. Org-wide policy comes from `SEMGREP_APP_TOKEN` + the AppSec Platform.

**Retry/loop semantics**: no server-tracked session state, no soft/hard attempt limits, no resolved/introduced/persisting diffing. The README's own description is "regenerate until clean or you dismiss it" — open-ended, bounded only by the agent's own judgment or the human manually overriding.

## Side-by-side

| Axis | Semgrep Guardian | SecureCoder (this repo) |
|---|---|---|
| Dependencies | Python + FastMCP + pydantic + httpx + otel + semgrep binary | Zero npm deps, Node stdlib only; analyzers picked up if on PATH |
| PostToolUse enforcement | Hard `decision:"block"` via hook JSON | Advisory only — findings injected as context, hook always exits 0 (`bin/run-sast`) |
| Enforcement requires | `SEMGREP_APP_TOKEN` (login) or the hook no-ops | Nothing — fully local/offline |
| Retry loop bound | None — open-ended "until clean or dismissed" | Server-tracked session with soft/hard limits, resolved/introduced/persisting diffing, explicit verdicts (`mcp-server/lib/retry.js`) |
| Deep semantic analysis | No dataflow engine; relies on rule breadth (10k+ rules) | CodeQL (security-extended dataflow queries) as `deep:true` |
| Secrets scanning | Built-in mode | Not present |
| Supply-chain / dependency vuln scanning | Built-in mode | Not present |
| Custom rule authoring by the agent | `write_custom_semgrep_rule` + AST tool | Not present |
| Prompt-time nudge | Live-fetched generic library list (network call every 24h) | Local heuristic, task-specific constraint injection by code category (`enricher.js`) — more targeted, fully offline |
| Remote/hosted scanning | Yes, `semgrep_scan_remote` / `SEMGREP_IS_HOSTED` — code leaves the machine | No — everything runs locally |
| Multi-client | Claude Code, Cursor, Windsurf, VS Code, Kiro | Claude Code only |
| Telemetry | OpenTelemetry spans on every hook call | None |
| Setup friction | Plugin marketplace + CLI install + (for real enforcement) an account/token | `claude --plugin-dir`, Node ≥18, analyzers auto-detected |

## Assessment

Semgrep Guardian's actual "guardian" enforcement (the hard block) is commercially gated behind an AppSec Platform login — without a token it degrades to context-injection via the MCP tools only, same category as what this project already does. Its real strengths are things this project doesn't have at all: secrets scanning, supply-chain/SCA scanning, and agent-authored custom rules. Its weaknesses relative to this project: heavier dependency chain, telemetry by default, no bounded retry loop (real risk of Claude regenerating in circles), and a design that nudges users toward their SaaS for the parts that actually matter (enforcement, org policy).

**Don't do a direct integration.** It would mean pulling in a Python runtime + several PyPI deps + the semgrep binary and re-plumbing hooks around it, contradicting the zero-dep/local-first design this project deliberately committed to, and its best feature (hard-block enforcement) is paywalled behind login.

### Novelties worth stealing (cheap, no new hard dependency)

1. **Optional hard-block mode** — `bin/run-sast` currently always `exit 0`. Add a config flag (e.g. `.securecoder.json: { "hook_mode": "block" | "advisory" }`) that, when set, emits Claude Code's `{"decision":"block","reason":...}` JSON on HIGH-severity findings instead of exit 0. Small, self-contained change, no new deps.
2. **Secrets scanning as a new fast guardian** — `semgrep` is already an adapter; add `--config=p/secrets` (or a small regex-based guardian like the syntax ones) as another entry in `analyzers`. No new binary needed if semgrep is already on PATH.
3. **Supply-chain/dependency scanning** — new guardian shelling to `semgrep --config=p/supply-chain` (free, local, no token) or a lockfile-vuln tool (`osv-scanner`) as an optional analyzer, same pattern as `codeql.js` / `syntax.js`.
4. Everything else (agent-authored custom rules, remote scanning, telemetry, live GitHub-fetched prompt context) is either lower-value or actively conflicts with this project's local-first / zero-dep / no-telemetry stance — skip.

### Keep, don't touch

The session-based soft/hard retry-limit bookkeeping in `retry.js` — it's strictly more disciplined than Semgrep's open-ended "regenerate until clean or dismissed," and prevents infinite-loop remediation.

## Next steps

1. Decide whether hard-block is even wanted as an opt-in — it's a UX tradeoff (interrupts Claude mid-task vs. advisory nudge); worth a quick decision before building it.
2. Prototype secrets + supply-chain guardians behind the existing `analyzers` / `deep_analyzers` config knobs — smallest, highest-value addition, reuses the existing semgrep adapter.
3. Skip AST/custom-rule authoring for now; revisit only if false-negative patterns recur often enough in practice to justify agent-authored rules.
