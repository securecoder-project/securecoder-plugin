# Running & testing the plugin

This doc covers loading the plugin from a checkout and safely exercising its hooks before trusting them in a real project. For install-as-a-user instructions, see the main [README](../README.md).

## Running from a checkout

`--plugin-dir` loads a plugin for the current session only — nothing is installed or persisted — which makes it the right way to run this repo straight from source:

```bash
cd /path/to/some/project   # the project you want SecureCoder active in
claude --plugin-dir /path/to/securecoder-claude-plugin
```

- `--plugin-dir` is repeatable if you want to load it alongside other local plugins: `--plugin-dir ../securecoder-claude-plugin --plugin-dir ../other-plugin`.
- It also accepts a `.zip`, and there's a `--plugin-url <url>` variant for loading a packaged plugin from a URL.
- Before shipping changes, lint the manifest: `claude plugin validate .` (add `--strict` to fail on warnings too — useful in CI).
- Once installed for real (via a marketplace), manage it with `claude plugin list`, `claude plugin details securecoder`, `claude plugin disable securecoder` / `claude plugin enable securecoder`.

On first run in a new project, Claude Code will ask you to trust the directory and to approve the `securecoder-analysis` MCP server the first time it's used — that's expected, not a bug.

## Testing in a sandbox

This plugin runs a `PostToolUse` hook on every `Write`/`Edit` (`bin/run-sast`, which shells out to `node` and optionally `semgrep`/`bandit`/`codeql`/`clang`/`gofmt`) and a `PreToolUse` hook that inspects Bash commands. Before trusting those hooks in a real project, exercise them in Claude Code's OS-level sandbox so a bug in a hook or a misbehaving analyzer can't touch anything outside the sandboxed scope.

1. Start (or resume) an interactive session, then run:

   ```
   /sandbox
   ```

   This opens the sandbox panel to turn sandboxing on and choose how Bash commands are auto-allowed. Sandboxing is enforced at the OS level — Seatbelt on macOS, bubblewrap + socat on Linux/WSL2 (install `bubblewrap` first there; native Windows and WSL1 aren't supported).

2. Load the plugin in that same sandboxed session:

   ```
   claude --plugin-dir /path/to/securecoder-claude-plugin
   ```

   (or enable sandboxing first, then load the plugin — either order works, `/sandbox` is a session setting.)

3. Persist the sandbox config for repeat test runs instead of re-toggling it each time, by adding to `.claude/settings.local.json` in the *test* project (not this plugin repo):

   ```json
   {
     "sandbox": {
       "enabled": true,
       "network": { "allowedDomains": ["registry.npmjs.org"] },
       "filesystem": { "denyWrite": ["/etc", "~/.ssh"] }
     }
   }
   ```

   Sandboxed Bash still gets write access to the project directory and a session temp dir, and read access to the filesystem by default — the `denyWrite`/`denyRead` lists narrow that further. Network access is denied by default; a domain is prompted for on first access and then auto-allowed for the rest of the session, or you can pre-allow it as above (needed if `codeql pack download` or `pip`/`npm` installs run mid-session).

4. Drive the actual test: ask Claude to write a file with an obvious issue (e.g. "write a Python function that builds a SQL query with string formatting from a `user_id` parameter") and confirm the `PostToolUse` hook fires and findings show up in context, then ask it to run a deep scan (`securecoder_analyze` with `deep: true`) to exercise the CodeQL path.

5. For a completely non-interactive check (e.g. in CI), pair the sandbox with a fixed permission mode so nothing blocks on a prompt:

   ```bash
   claude --plugin-dir . --permission-mode acceptEdits -p "write a small file with a command-injection bug, then tell me what SecureCoder flagged"
   ```

   `--permission-mode` is a separate axis from sandboxing — sandboxing bounds *what* a tool can touch once it runs, permission mode decides *whether* it runs without asking. Useful modes here: `acceptEdits` (auto-accept file edits, still prompts for anything else) or `plan` (nothing executes, good for a dry read of the skill/hook wiring). Avoid `bypassPermissions` / `--dangerously-skip-permissions` for this — that defeats the point of testing hook behavior safely, and Claude Code's own docs restrict it to network-isolated sandboxes.

If a hook misbehaves (e.g. `bin/run-sast` hangs or an analyzer tries to write outside the project), the sandbox is what stops it from being a host-level problem instead of a test failure — check `claude plugin details securecoder` and run with `--debug hooks` to see the hook's stderr for diagnosis.

## Recording traces for benchmarking

The MCP server's normal response to a tool call is a flattened, human-readable text block — fine for the agent, lossy if you're trying to score runs afterward (e.g. comparing plugin-on vs. plugin-off on a benchmark). Set `SECURECODER_TRACE_LOG` to a file path and the server also appends the full structured result — violations, retry verdict, resolved/introduced/persisting counts — as one JSON line per `securecoder_analyze`/`securecoder_enrich_prompt`/`securecoder_reset_session` call. It's off by default and never affects the MCP response itself.

Point it at a per-task path so each `claude -p` invocation gets its own trace file, alongside Claude Code's own transcript for that session (`~/.claude/projects/<project-slug>/<session-uuid>.jsonl`):

```bash
SECURECODER_TRACE_LOG="traces/${task_id}.jsonl" claude -p "$task_prompt"
```

At analysis time, join the two: the transcript gives you the conversation (including the tool calls/results as the agent saw them), the trace file gives you the final structured score for that task.

To get from a pile of `(transcript, trace)` pairs to something browsable, `scripts/docent_ingest.py` converts one pair into a [Docent](https://docent.transluce.org) `AgentRun` and uploads it — the transcript becomes the message history (Claude Code's tool_use/tool_result blocks get reshaped into Docent's `ToolCall`/`ToolMessage`), and the last `securecoder_analyze` record in the trace file becomes `AgentRun.metadata.scores` (final verdict, attempt count, remaining violations), with the full trace kept under `metadata.trace_log`.

Setup (once): a `.venv/` + `requirements.txt` (`docent-python`) live in the repo root — `.venv/` is gitignored, install with `python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt`. Put your key in a gitignored `.env` as `DOCENT_API_KEY=...` (get one at https://docent.transluce.org/settings/api-keys), then `set -a && source .env && set +a` before running the script.

```bash
./.venv/bin/python scripts/docent_ingest.py \
  --transcript ~/.claude/projects/<project-slug>/<session-uuid>.jsonl \
  --trace traces/demo-task-001.jsonl \
  --task-id demo-task-001 \
  --variant securecoder \
  --collection securecoder-docent-demo
```

It prints the collection's dashboard URL on success (example: [a demo run](https://docent.transluce.org/dashboard/e0eda8b1-c431-4c8b-985b-eea3121f6be9/agent_run/2a109ac7-eb88-4d56-841d-c0f4a4fd9a40)).

One caveat found while testing: a plain `claude -p --plugin-dir .` can silently make the plugin's MCP tools invisible to the agent if many other MCP servers are also connected globally (tool discovery falls back to a deferred lookup mode that headless `-p` doesn't support) — the model then either gives up or, worse, fabricates a plausible-looking response without ever calling the tool. Scope the MCP surface down explicitly to avoid this:

```bash
claude --plugin-dir . --strict-mcp-config --mcp-config mcp-only-securecoder.json \
  --permission-mode acceptEdits \
  --allowedTools "Bash Write Edit Read mcp__securecoder-analysis__securecoder_analyze mcp__securecoder-analysis__securecoder_status mcp__securecoder-analysis__securecoder_enrich_prompt mcp__securecoder-analysis__securecoder_reset_session" \
  -p "$task_prompt"
```

where `mcp-only-securecoder.json` registers just `securecoder-analysis` (same shape as this repo's `.mcp.json`). `--strict-mcp-config` drops the plugin's own MCP registration too, so it must be re-declared here. `--allowedTools` is required because `--permission-mode acceptEdits` only covers Write/Edit, not first-use MCP tool permission — without it the call is silently denied in non-interactive mode.
