# SecureCoder: installation and usage guide

Step-by-step setup for every supported coding agent, what you get in each one, and how to verify
it works. For a shorter overview see the [README](README.md); for working on the plugin itself see
[DEVELOPMENT.md](DEVELOPMENT.md).

- [Before you start](#before-you-start)
- [Install](#install)
  - [Claude Code](#claude-code) · [Codex](#codex) · [Cursor](#cursor) · [VS Code](#vs-code-github-copilot) · [OpenCode](#opencode) · [Other Agent Plugins clients](#other-agent-plugins-clients)
- [Verify the install](#verify-the-install)
- [Usage](#usage)
- [Configuration](#configuration)
- [Updating and uninstalling](#updating-and-uninstalling)
- [Troubleshooting](#troubleshooting)

---

## Before you start

**Required:** Node.js 18 or newer. Nothing else: the plugin has no npm dependencies, and no
`npm install` step.

**Recommended:** the analyzers. SecureCoder works without them but finds much less.

| Tool | Covers | Install |
| --- | --- | --- |
| `semgrep` | OWASP rules, most languages | `brew install semgrep` or `pipx install semgrep` |
| `bandit` | Python | `brew install bandit` or `pipx install bandit` |
| `codeql` | Deep analysis, on demand | `brew install codeql` or [codeql-action releases](https://github.com/github/codeql-action/releases) |
| `python3`, `node`, `gofmt`, `clang` | Syntax hard-reject checks per language | usually already present |

After installing, run `/securecoder doctor` (or `node <plugin>/bin/securecoder doctor`) to see
what was found, with an install command for anything missing.

**Repository access.** While this repository is private, every marketplace command below needs
git credentials that can read it: either an SSH key (use the `git@github.com:…` URL) or a
credential helper / `gh auth login` for the `https` form. Collaborators need repo access. Once the
repository is public, the same commands work for everyone with no extra setup.

**Which install method applies where:**

| Agent | Method | Automatic scanning |
| --- | --- | --- |
| Claude Code | Marketplace | Yes |
| Codex | Marketplace | Yes, after you trust the hooks |
| Cursor | Local clone | Yes |
| VS Code (Copilot) | Install from source, or a local path setting | No (tools only) |
| OpenCode | Local clone plus a loader file | Yes |
| Copilot CLI, Kiro, other Agent Plugins clients | Client's plugin directory | No (tools only) |

---

## Install

### Claude Code

```
/plugin marketplace add parsakaz/securecoder-claude-plugin
/plugin install securecoder@securecoder
```

`securecoder@securecoder` is `<plugin>@<marketplace>`; both are named `securecoder`. For SSH
instead of https, use the full URL:

```
/plugin marketplace add git@github.com:parsakaz/securecoder-claude-plugin.git
```

A marketplace name maps to exactly one source, so pick one form. To switch later, run
`/plugin marketplace remove securecoder` first.

Command-line equivalent, including a project-scoped install that your team gets automatically:

```bash
claude plugin marketplace add parsakaz/securecoder-claude-plugin
claude plugin install securecoder@securecoder              # scope: user (default)
claude plugin install securecoder@securecoder -s project   # committed to .claude/settings.json
claude plugin list
```

To try it for one session without installing anything:

```bash
claude --plugin-dir /path/to/securecoder-claude-plugin
```

### Codex

```bash
codex plugin marketplace add parsakaz/securecoder-claude-plugin
codex plugin add securecoder@securecoder
codex plugin list      # expect: installed, enabled
codex mcp list         # expect: securecoder-analysis, enabled
```

Then start `codex` and **approve the hooks under `/hooks`**. Codex will not run hooks until you
trust them, so the post-edit scan, the shell guard, and the per-prompt security constraints all
stay silent until you do.

**If the plugin view says "No plugin hooks"**, this build of Codex is not loading plugin-bundled
hooks. Install them as your own Codex hooks instead, which every build supports:

```bash
node /path/to/securecoder/bin/securecoder install-hooks codex              # ~/.codex/hooks.json
node /path/to/securecoder/bin/securecoder install-hooks codex --scope project   # <repo>/.codex/hooks.json
```

That writes the same three hooks (post-edit scan, shell guard, per-prompt constraints) with
absolute paths, leaving any hooks you already have alone. Restart Codex and approve them under
`/hooks`. If a later Codex release starts loading the plugin's own hooks, remove these so the scan
does not run twice:

```bash
node /path/to/securecoder/bin/securecoder uninstall-hooks codex
```

**If you installed hooks with SecureCoder 0.2.0**, run `install-hooks codex` again and approve
the hooks once more under `/hooks`. The 0.2.0 entries used a form Codex does not run, so they
never reached the hook script; reinstalling replaces them, and Codex asks again because it trusts
hooks per entry.

Prefer this git-backed install over a local directory: Codex copies a local marketplace folder
wholesale into `~/.codex/plugins/cache/`, including untracked and gitignored files such as `.env`.
A clone only ever contains committed files.

### Cursor

Cursor installs individual plugins from a local folder (repo-URL installs are a team-marketplace
feature), so clone into its local plugins directory:

```bash
mkdir -p ~/.cursor/plugins/local
git clone git@github.com:parsakaz/securecoder-claude-plugin.git ~/.cursor/plugins/local/securecoder
```

Restart Cursor and look under **Customize → Plugins**. Cursor reads either
`.cursor-plugin/plugin.json` (skills, agents, hooks, MCP) or the root `plugin.json` (skills and
MCP) and picks one automatically: if the hooks and the remediator agent show up, it chose the
Cursor manifest.

The `cursor-agent` CLI does not support plugins in older builds; use the Cursor app.

### VS Code (GitHub Copilot)

Command Palette → **Chat: Install Plugin From Source**, then paste:

```
https://github.com/parsakaz/securecoder-claude-plugin
```

Or point VS Code at a local checkout in your user `settings.json`
(**Preferences: Open User Settings (JSON)**):

```json
{
  "chat.pluginLocations": {
    "/path/to/securecoder-claude-plugin": true
  }
}
```

Reload the window, then check **Extensions → Agent Plugins - Installed** and
**Chat: Configure Skills**.

VS Code reads the root `plugin.json`, so you get the `secure-codegen` skill and the MCP tools.
Automatic post-edit scanning does **not** run: VS Code looks for plugin hooks at
`com.github.copilot/hooks/hooks.json`, which this plugin does not ship. Ask Copilot to run
`securecoder_analyze`, or use the CLI.

### OpenCode

OpenCode loads JavaScript plugins from a plugins folder. Clone the repository, then write a
one-line loader that re-exports the adapter:

```bash
git clone git@github.com:parsakaz/securecoder-claude-plugin.git ~/.local/share/securecoder
mkdir -p ~/.config/opencode/plugins
printf 'export * from "%s";\nexport { default } from "%s";\n' \
  ~/.local/share/securecoder/opencode/index.js ~/.local/share/securecoder/opencode/index.js \
  > ~/.config/opencode/plugins/securecoder.js
```

For a single project, write the same file to `.opencode/plugins/securecoder.js` in that project.

The plugin registers the MCP server, the `/securecoder` and `/secure-codegen` commands, and the
`@securecoder-remediator` subagent. Anything you already defined under those names is left alone.

### Other Agent Plugins clients

Copilot CLI, Kiro, and other [Agent Plugins 1.0](https://agent-plugins.org) clients install from
the repository URL through their own plugin directory, and read the root `plugin.json`,
`mcp.json`, and `skills/`. That gives you the skills and the MCP tools; hooks are client-specific
and not part of the standard.

---

## Verify the install

Three checks, in increasing depth.

**1. Is it loaded?**

| Agent | Check |
| --- | --- |
| Claude Code | `/securecoder doctor`, or `claude plugin list` |
| Codex | `codex plugin list` and `codex mcp list`; `/hooks` shows the hooks as trusted |
| Cursor | **Customize → Plugins** lists SecureCoder |
| VS Code | **Extensions → Agent Plugins - Installed** |
| OpenCode | `opencode mcp list` shows `securecoder-analysis connected` |

**2. Does the analysis work?** From any terminal:

```bash
node /path/to/securecoder/bin/securecoder doctor
node /path/to/securecoder/bin/securecoder scan path/to/file.py
```

In Claude Code the CLI is already on `PATH`, so plain `securecoder doctor` works.

**3. Does the agent get findings?** In a scratch git repository, ask the agent to write this file
**and explicitly tell it not to fix the bug** — otherwise a capable model writes the safe version
and nothing triggers:

```python
import os

def archive(target_dir):
    os.system(f"tar czf backup.tgz {target_dir}")
```

Expected: a HIGH finding (bandit `B605`, plus semgrep if installed) appears in the agent's context
right after the write, on every agent that supports hooks. Then try:

- `/securecoder status` (Claude Code, Cursor, OpenCode) or `$securecoder:securecoder status` (Codex)
- "run a deep SecureCoder analysis on app.py" to exercise CodeQL
- `/securecoder mode enforce`, then write the file again: in Claude Code and Codex the turn is
  blocked until the finding is addressed

---

## Usage

### What happens without you doing anything

1. **Before code is written.** On Claude Code and Codex, a hook adds SecureCoder's core
   secure-coding constraints to every prompt: parameterized queries, no shell interpolation, safe
   parsers and crypto, secrets kept out of source. Your signatures and documented behavior stay as
   asked. When the prompt mentions known weakness classes (SQL injection, path traversal, …), it
   adds one line for each, at most six. On Cursor, OpenCode, VS Code, and the other clients no
   hook can add context to a prompt, so there the constraints reach the model only when it loads
   the `secure-codegen` skill, which activates on security-relevant work. Claude Code does not run
   the hook for subagent prompts.
2. **After every edit.** The post-edit hook runs the fast analyzers (syntax, semgrep, bandit) on
   the files just written and hands findings to the agent. A file that does not parse must be
   fixed. In advisory mode every other finding is a hint: the agent is told to fix what is a real,
   exploitable issue and to say why it dismisses the rest.
3. **When findings appear.** The agent deals with them, or delegates to the
   `securecoder-remediator` agent, which loops fix → re-analyze until the code is clean, every
   remaining finding has been dismissed with a reason, or the retry limits advise stopping, then
   reports.
4. **Before risky shell commands.** The shell guard flags remote scripts piped into a shell,
   disabled TLS verification, world-writable permissions, broad `rm -rf`, and inline credentials.

### The `/securecoder` command

Invoked as `/securecoder` in Claude Code, Cursor, and OpenCode, and `$securecoder:securecoder` in
Codex. With no arguments it prints a dashboard of every setting, where each value comes from, and
which analyzers are installed, then offers an interactive menu.

| Command | Effect |
| --- | --- |
| `/securecoder` · `status` | Dashboard and menu |
| `on` · `off` | Master switch. Inside a project, `off` needs `--scope user` (see [Configuration](#configuration)) |
| `mode advisory` · `mode enforce` | **advisory** (default): findings are added to the agent's context. **enforce**: findings at or above the threshold block the turn until addressed, and flagged shell commands need approval |
| `severity low\|medium\|high` | Minimum severity reported; hard rejects always are |
| `analyzers syntax,semgrep` · `analyzers +bandit -semgrep` | Fast analyzer set |
| `deep on\|off` | Allow CodeQL deep analysis |
| `ruleset p/security-audit` | Semgrep ruleset: registry id, `auto`, or a local rules path |
| `limits 5 10` | Remediation soft and hard retry limits: the attempts at which `securecoder_analyze` advises the agent to review progress and to stop |
| `exclude add 'generated/'` · `exclude remove …` · `exclude list` | Paths to skip |
| `hooks post-edit off` · `hooks shell-guard off` · `hooks user-prompt off` | Turn one hook off |
| `scan [paths] [--deep]` | Scan files (default: changed since `HEAD`) and offer fixes |
| `doctor` | Analyzer and config check with install hints |
| `init` | Write a starter `.securecoder.json` for the team |
| `reset [key]` | Remove overrides |
| `keys` · `help` | Every setting with allowed values and defaults |

Add `--scope user|project|local` to any change to control where it is saved.

### Asking for things directly

Plain requests work too, and are the main interface in VS Code and other tool-only clients:

- "scan the files I changed and fix the security findings"
- "run a deep SecureCoder analysis on src/auth.py"
- "use the securecoder-remediator agent on this file"

### MCP tools

| Tool | Purpose |
| --- | --- |
| `securecoder_analyze` | Analyze files; `deep: true` adds CodeQL. Feedback lists `MUST FIX` (a file does not parse) and `WEIGH THESE` (hints to weigh). Reuse one `session` id across a fix loop for progress tracking and a retry verdict |
| `securecoder_enrich_prompt` | Add four contract-preservation constraints to a code-generation prompt, plus a CWE checklist when the task matches known weakness classes |
| `securecoder_reset_session` | Reset a remediation session's attempt counter |
| `securecoder_status` | Settings dashboard |
| `securecoder_config` | Read settings: `show`, `doctor`, `keys`, `get` (read-only by design) |

Tool names are namespaced per client. In Claude Code they are
`mcp__plugin_securecoder_securecoder-analysis__<tool>`.

With a `session` id, `securecoder_analyze` returns one of five verdicts: `clean`, `hard_reject`
(a file does not parse; this takes precedence over both retry limits), `continue`, `meta_review`
(soft limit reached: check whether the loop is still making progress), or `hard_limit_exhausted`
(stop and report). At the hard limit it also names an earlier attempt that had fewer findings, if
there was one. All of this is advice to the agent: SecureCoder keeps no earlier file contents, does
not run the loop, and cannot stop it.

### The CLI

```bash
securecoder status                              # dashboard (Claude Code puts bin/ on PATH)
securecoder doctor                              # analyzers and config, with install hints
securecoder scan src/auth.py                    # exit code 1 if findings exist
securecoder scan --deep                         # CodeQL over files changed since HEAD
securecoder config set mode enforce
securecoder config add exclude_patterns 'vendor/'
securecoder config keys                         # every setting, allowed values, defaults
securecoder install-hooks codex                  # hooks into ~/.codex/hooks.json (see Codex install)
securecoder uninstall-hooks codex
```

Elsewhere, run it as `node /path/to/securecoder/bin/securecoder …`. The CLI is the only supported
way to write settings: agents can read settings over MCP but cannot change them there. An agent
that can write files could still edit a project config file by hand, which is why `enabled` and
`mode` cannot be lowered from one (see [Configuration](#configuration)). `securecoder scan` is
also handy in CI or a pre-commit hook.

---

## Configuration

Settings resolve from four places, lowest priority first:

| Scope | File | Use for |
| --- | --- | --- |
| default | built in | — |
| **user** | `~/.config/securecoder/config.json` (`%APPDATA%\securecoder\config.json` on Windows) | Your defaults everywhere, and executable paths |
| **project** | `.securecoder.json` | Team settings, committed |
| **local** | `.securecoder.local.json` | Your personal overrides in one repo; `securecoder config gitignore` ignores it, along with the `.securecoder/` error log |
| **environment** | `SECURECODER_*` and `*_BIN` variables | CI, one-off runs; beats every file |

Inside a project, writes default to `local`; outside one, to `user`. The dashboard tags every
value with its source, and any change that lowers protection is flagged with `⚠`.

**`enabled` and `mode` have a floor.** A file inside the repository (project or local scope) can
raise these two settings but not lower them below what your user config and the defaults give. A
lower value in such a file is ignored, with a warning on the dashboard and in `doctor` that names
the key and the scope, and the CLI refuses to write one (exit code 2). In practice:

- `/securecoder off` or `securecoder config set enabled off` inside a project is refused. Use
  `--scope user`, which turns SecureCoder off in all your projects, or set
  `SECURECODER_ENABLED=off` for one run.
- `mode advisory` is refused the same way when your user config says `enforce`; use `--scope user`
  or `SECURECODER_MODE=advisory`. If only the project file set `enforce`, your local file may
  still set `advisory`.
- Every other setting stays under project control, including `severity_threshold`, `analyzers`,
  `exclude_patterns`, and the `hooks.*` toggles.

Common settings (`securecoder config keys` lists them all):

| Key | Default | Environment override |
| --- | --- | --- |
| `enabled` | `on` | `SECURECODER_ENABLED` |
| `mode` | `advisory` | `SECURECODER_MODE` |
| `severity_threshold` | `LOW` | `SECURECODER_SEVERITY` |
| `analyzers` | `syntax, semgrep, bandit` | |
| `deep_analyzers` | `codeql` | |
| `semgrep_config` | `p/owasp-top-ten` | |
| `exclude_patterns` | `tests/`, `*.test.js`, `*.test.ts`, `*.spec.*`, `migrations/`, `node_modules/`, `__pycache__/` | |
| `retry.soft_limit` / `retry.hard_limit` | `7` / `14` | |
| `hooks.post_edit` / `hooks.shell_guard` / `hooks.user_prompt` | `on` / `on` / `on` | `SECURECODER_POST_EDIT` / `SECURECODER_SHELL_GUARD` / `SECURECODER_USER_PROMPT` |
| `codeql.timeout_seconds` | `600` | |
| `bins.*`, `codeql.binary` *(user scope only)* | `semgrep`, `bandit`, `python3`, … | `SEMGREP_BIN`, `BANDIT_BIN`, `CODEQL_BIN`, `PYTHON_BIN`, … |
| `trace_log` *(user scope only)* | unset | `SECURECODER_TRACE_LOG` |

[`examples/securecoder.json`](examples/securecoder.json) is a complete project file; copy it to
`.securecoder.json` or run `securecoder config init`.

**A different project file for one run.** `SECURECODER_CONFIG` names the file to read as the
project config, for example `SECURECODER_CONFIG=ci/securecoder.json securecoder scan`. A relative
path is resolved against the project root. The file replaces `.securecoder.json` for that run;
user config, `.securecoder.local.json`, and the other environment variables apply as usual. It is
still project scope, so the trust boundary below and the `enabled` / `mode` floor apply to it
exactly as they do to `.securecoder.json`.

**`mode` and the retry limits are independent.** `mode` decides what the hooks return: context in
advisory mode, a blocking decision (or an approval prompt for a flagged shell command) in enforce
mode. The harness acts on that. `retry.soft_limit` and `retry.hard_limit` only shape the verdict
that `securecoder_analyze` returns to the agent during a fix loop. A verdict is advice: the agent
may ignore it, and SecureCoder does not own the loop.

**Trust boundary.** Settings that choose which programs run (`bins.*`, `codeql.binary`,
`language_overrides.python.extra_args`) or where files are written (`trace_log`) are honored only
from user config or environment variables. A cloned repository cannot make the post-edit hook run
an arbitrary program through a committed `.securecoder.json`; `securecoder doctor` lists any keys
that were ignored for this reason. See [SECURITY.md](SECURITY.md).

**Hook error log.** Hooks fail open, so a broken hook looks the same as a clean file. Each fault
is therefore appended as one JSON line to `.securecoder/errors.log` in the project (capped at
64 KiB, newest entries kept), and `securecoder doctor` reports the count and the most recent
entry. `securecoder config gitignore` keeps the directory out of git. See
[Troubleshooting](#troubleshooting) for what to do when `doctor` reports it.

**Privacy.** All analysis is local. The one exception is semgrep downloading registry rulesets
such as the default `p/owasp-top-ten`; point `semgrep_config` at a local rules path to stay
offline.

---

## Updating and uninstalling

| Agent | Update | Uninstall |
| --- | --- | --- |
| Claude Code | `/plugin marketplace update securecoder` | `/plugin uninstall securecoder@securecoder` |
| Codex | `codex plugin marketplace upgrade` | `codex plugin remove securecoder` |
| Cursor | `git -C ~/.cursor/plugins/local/securecoder pull`, restart | delete that folder, restart |
| VS Code | reinstall from source, or `git pull` the local path | remove the `chat.pluginLocations` entry, or uninstall from the Extensions view |
| OpenCode | `git -C ~/.local/share/securecoder pull` | delete `~/.config/opencode/plugins/securecoder.js` |

To switch it off without uninstalling, use `/securecoder off --scope user` (or `securecoder config
set enabled off --scope user`), which leaves everything installed but idle in all your projects.
For one session, start the agent with `SECURECODER_ENABLED=off` instead. Without `--scope user`
the command is refused inside a project; see [Configuration](#configuration).

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Installed, but the agent has no `securecoder_*` tools | The installed copy predates 0.2.0, or the install is stale. Update the marketplace and reinstall, then confirm `securecoder --version` and the version in `plugin list` are both 0.3.0. |
| Codex plugin view says "No plugin hooks" | That build does not load plugin-bundled hooks. Run `securecoder install-hooks codex`, restart Codex, and approve them under `/hooks`. Remove them with `uninstall-hooks codex` if plugin hooks start working, to avoid scanning twice. |
| Codex hooks installed with 0.2.0 never fire | The entries `install-hooks codex` wrote in 0.2.0 used a form Codex does not run. Run `securecoder install-hooks codex` again, restart Codex, and approve the hooks under `/hooks` once more. |
| Nothing happens after the agent writes a file | Is it on? `/securecoder status` shows `enabled` and `hooks.post_edit`. In Codex, hooks need approval under `/hooks`. In VS Code, hooks are not supported yet. Also check the path is not covered by `exclude_patterns`, and run `securecoder doctor` to see whether the hook has been failing. |
| `doctor` reports "hook errors logged in `.securecoder/errors.log`" | A hook hit a fault and failed open, so some edits may not have been scanned. The line under the warning shows the most recent entry: time, event, analyzer if one failed, and the error. Fix the cause (a crashing analyzer, a semgrep ruleset that cannot be downloaded, an unreadable file, a stale install), then delete the file; the warning stays until you do. The file holds one JSON line per fault and is capped at 64 KiB. It cannot show a hook that was never invoked, and an analyzer that is not installed is skipped without an entry; the list at the top of `doctor` shows what is installed. |
| `/securecoder off` or `config set enabled off` is refused | Inside a project the default scope is `local`, and a file inside the repository cannot turn SecureCoder off. Add `--scope user` (all your projects) or set `SECURECODER_ENABLED=off` for one run. The same applies to `mode advisory` when your user config says `enforce`. |
| Warning: `Ignoring "enabled" = off from project config` | The project or local config file tries to turn SecureCoder off or lower `mode`. That value is ignored by design. Remove it from the file, or set it in user config or the environment if you mean it. |
| No findings on code you know is vulnerable | Probably no analyzer installed: `/securecoder doctor`. The syntax guardians alone only catch code that does not parse. Also check `severity_threshold`. |
| Findings appear but the agent ignores them | `advisory` mode only informs, and it presents everything except parse errors as hints the agent may dismiss with a reason. Use `/securecoder mode enforce` to block the turn until they are addressed (Claude Code and Codex). |
| The agent keeps patching past the retry limit | The limits produce a verdict in the `securecoder_analyze` result, not a block. The agent is expected to follow it, but SecureCoder does not run the loop and cannot stop it. |
| MCP server fails with "Connection closed" | Usually a leftover project-level MCP entry pointing at a plugin path. Remove `securecoder-analysis` from the project's `.claude/settings.json` / `.mcp.json`; the plugin registers its own server. |
| Settings changes seem to have no effect | A higher-precedence scope is winning. The dashboard's Source column shows which, and the CLI prints a `Note:` line when it happens. Environment variables beat every file. For `enabled` and `mode`, a weakening value in a project or local file is ignored; the dashboard lists it under Warnings. |
| Analyzer paths in `.securecoder.json` are ignored | By design: `bins.*` and `codeql.binary` are honored only from user config or environment variables. Run `securecoder config set bins.semgrep /path --scope user`. |
| Marketplace add fails with a permissions or not-found error | The repository is private: use the `git@github.com:…` SSH URL, or authenticate https (`gh auth login`). |
| Marketplace add fails saying the source differs | That marketplace name is already registered with a different URL. `/plugin marketplace remove securecoder`, then add again. |
| CodeQL runs forever | It builds a database; that is minutes, not seconds. Use it deliberately (`--deep`, or `deep: true`), and raise or lower `codeql.timeout_seconds` (per CodeQL step, default 600). |
| Post-edit scans feel slow | semgrep dominates. Narrow `semgrep_config`, or drop semgrep from `analyzers` and rely on `scan --deep` at review time. |
| Headless `claude -p` never calls the tools | With many MCP servers configured, tool discovery can be deferred. Scope it: `--strict-mcp-config` plus `--allowedTools "… mcp__plugin_securecoder_securecoder-analysis__securecoder_analyze"`. See DEVELOPMENT.md. |
| `jq` errors | Old versions shelled out to `jq`. Hooks have been pure Node since 0.2.0; update the plugin. |

Still stuck? Run `securecoder doctor`, then open an issue with its output and your agent and
version: <https://github.com/parsakaz/securecoder-claude-plugin/issues>. For anything with
security impact, follow [SECURITY.md](SECURITY.md) instead.
