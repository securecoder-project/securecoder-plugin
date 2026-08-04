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
