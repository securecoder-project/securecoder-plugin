# SecureCoder

**Security-aware code generation for coding agents.** SecureCoder adds security constraints before your agent writes code, scans every file it edits with static analyzers, and runs a guided fix-and-recheck loop when it finds problems. It works in **Claude Code, Codex, Cursor, and OpenCode**, and brings its skills and MCP tools to GitHub Copilot, VS Code, and Kiro through the [Agent Plugins](https://agent-plugins.org) standard.

An [ATHENE](https://www.athene-center.de/) project by the Software Technology Group (STG) at TU Darmstadt. Analysis runs through a zero-dependency Node MCP server ported from the [SecureCoder](https://securecoder-project.github.io/) research engine.

[![CI](https://github.com/parsakaz/securecoder-claude-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/parsakaz/securecoder-claude-plugin/actions/workflows/ci.yml)

---

## What it does

1. **Before generation.** The `secure-codegen` skill and the `securecoder_enrich_prompt` tool add contract-preserving security constraints: parameterized queries, no shell interpolation, safe crypto, while keeping your function signatures and requested algorithms exactly as asked.
2. **After every edit.** A hook runs the fast guardians (syntax hard-reject checks, [semgrep](https://semgrep.dev), [bandit](https://bandit.readthedocs.io)) on the files the agent just wrote and hands the findings back to the agent. [CodeQL](https://codeql.github.com) deep analysis runs on demand.
3. **When findings appear.** The `securecoder-remediator` agent fixes them and re-analyzes until the code is clean or the retry policy says stop, then reports what changed.
4. **Before risky shell commands.** A small, high-signal shell guard flags remote scripts piped into a shell, disabled TLS verification, `chmod 777`, broad `rm -rf`, and inline credentials.

Everything is configurable from one command: **`/securecoder`**.

## Harness support

| | Claude Code | Codex | Cursor | OpenCode | Copilot / VS Code / Kiro |
| --- | :---: | :---: | :---: | :---: | :---: |
| MCP tools (`securecoder_analyze`, …) | ✓ | ✓ | ✓ | ✓ | ✓ |
| `secure-codegen` skill | ✓ | ✓ | ✓ | ✓ (command) | ✓ |
| `/securecoder` settings | `/securecoder` | `$securecoder:securecoder` | ✓ | `/securecoder` | ✓ (skill) |
| Post-edit scan | ✓ | ✓ | ✓ | ✓ | – |
| Enforce mode blocks until fixed | ✓ | ✓ | context only¹ | context only¹ | – |
| Shell guard | ✓ | ✓ | ✓ | ✓ (enforce blocks) | – |
| Remediator agent | ✓ | via skill + MCP | ✓ | ✓ (subagent) | – |

¹ Cursor and OpenCode have no "block after a tool ran" hook. In enforce mode, SecureCoder adds stronger instructions to the agent context instead.

## Requirements

| Requirement | Why | Install |
| --- | --- | --- |
| **Node.js 18+** | Runs the MCP server, hooks, and CLI (no `npm install` needed) | [nodejs.org](https://nodejs.org) |
| `semgrep` *(recommended)* | OWASP rules for most languages | `brew install semgrep` or `pipx install semgrep` |
| `bandit` *(recommended)* | Python security checks | `brew install bandit` or `pipx install bandit` |
| `codeql` *(optional)* | Deep analysis on demand | `brew install codeql` or [releases](https://github.com/github/codeql-action/releases) |
| `python3`, `gofmt`, `clang` *(optional)* | Syntax hard-reject checks per language | usually already installed |

Missing analyzers are skipped. Run **`/securecoder doctor`** to see what's installed, with an install command for each missing tool.

---

## Install

### Claude Code

```shell
/plugin marketplace add parsakaz/securecoder-claude-plugin
/plugin install securecoder@securecoder
```

Try it for one session without installing: `claude --plugin-dir /path/to/securecoder-claude-plugin`.

### Codex

```shell
codex plugin marketplace add parsakaz/securecoder-claude-plugin
codex plugin add securecoder@securecoder
```

Then start Codex and approve SecureCoder's hooks under `/hooks`. Codex requires you to trust plugin hooks before they run. You can also install from `/plugins` in the Codex app or TUI.

### Cursor

Load a checkout as a local plugin, then restart Cursor. It appears under **Customize**:

```shell
git clone https://github.com/parsakaz/securecoder-claude-plugin ~/.cursor/plugins/local/securecoder
```

Teams can also distribute it through a Cursor team marketplace, which supports this repository's `.cursor-plugin/` layout.

### OpenCode

Clone the repository, then add a one-line loader to your global (or project `.opencode/`) plugins folder:

```shell
git clone https://github.com/parsakaz/securecoder-claude-plugin ~/.local/share/securecoder
mkdir -p ~/.config/opencode/plugins
printf 'export * from "%s";\nexport { default } from "%s";\n' \
  ~/.local/share/securecoder/opencode/index.js ~/.local/share/securecoder/opencode/index.js \
  > ~/.config/opencode/plugins/securecoder.js
```

See [`opencode/README.md`](opencode/README.md) for details.

### VS Code (GitHub Copilot)

Run **Chat: Install Plugin From Source** from the Command Palette and paste the repository URL, or point VS Code at a local checkout in your user `settings.json`:

```json
{
  "chat.pluginLocations": {
    "/path/to/securecoder-claude-plugin": true
  }
}
```

Reload the window and check **Extensions → Agent Plugins - Installed**.

### Kiro and other Agent Plugins clients

Install from the repository URL through your client's plugin directory. These clients read the root `plugin.json`, `mcp.json`, and `skills/`, which give you the skills and the MCP tools.

---

## `/securecoder`

Run it with no arguments to get a dashboard of every setting, where each value comes from, and which analyzers are installed, followed by an interactive menu. Or pass a subcommand:

| Command | What it does |
| --- | --- |
| `/securecoder` · `status` | Dashboard and interactive menu |
| `on` · `off` | Turn SecureCoder on or off |
| `mode advisory` · `mode enforce` | **advisory** (default): findings go to the agent as context. **enforce**: findings at or above the threshold block the agent until fixed, and flagged shell commands need your approval |
| `severity low\|medium\|high` | Minimum severity to report (hard rejects are always reported) |
| `analyzers syntax,semgrep` · `analyzers +bandit -semgrep` | Choose the fast analyzers |
| `deep on\|off` | Allow CodeQL deep analysis |
| `ruleset p/security-audit` | Semgrep ruleset (registry id, `auto`, or a local rules path) |
| `limits 5 10` | Remediation soft/hard retry limits |
| `exclude add 'generated/'` · `exclude remove …` · `exclude list` | Paths to skip |
| `hooks post-edit off` · `hooks shell-guard off` | Toggle each hook |
| `scan [paths] [--deep]` | Scan files (default: changed since `HEAD`) and offer fixes |
| `doctor` | Check analyzers and config, with install commands |
| `init` | Write a starter `.securecoder.json` for your team |
| `reset [key]` | Remove overrides |
| `keys` · `help` | Every setting with allowed values and defaults |

Add `--scope user|project|local` to choose where a change is saved:

| Scope | File | Use for |
| --- | --- | --- |
| `local` *(default inside a project)* | `.securecoder.local.json` | Your personal overrides in this repo (gitignore it with `securecoder config gitignore`) |
| `project` | `.securecoder.json` | Team settings, committed |
| `user` *(default elsewhere)* | `~/.config/securecoder/config.json` | Defaults for all your projects, and executable paths |

Precedence: **default < user < project < local < environment variables.** The dashboard shows the source of every value, and SecureCoder warns you whenever a change lowers protection.

The same operations work from a terminal:

```shell
securecoder status                          # Claude Code puts bin/ on PATH;
securecoder config set mode enforce         # elsewhere: node <plugin>/bin/securecoder …
securecoder config add exclude_patterns 'vendor/'
securecoder scan --deep src/auth.py
```

## Configuration reference

`securecoder config keys` prints the full list. The most common settings:

| Key | Default | Env override |
| --- | --- | --- |
| `enabled` | `on` | `SECURECODER_ENABLED` |
| `mode` | `advisory` | `SECURECODER_MODE` |
| `severity_threshold` | `LOW` | `SECURECODER_SEVERITY` |
| `analyzers` | `syntax, semgrep, bandit` | |
| `deep_analyzers` | `codeql` | |
| `semgrep_config` | `p/owasp-top-ten` | |
| `exclude_patterns` | `tests/`, `*.test.js`, `*.test.ts`, `*.spec.*`, `migrations/`, `node_modules/`, `__pycache__/` | |
| `retry.soft_limit` / `retry.hard_limit` | `7` / `14` | |
| `hooks.post_edit` / `hooks.shell_guard` | `on` / `on` | `SECURECODER_POST_EDIT` / `SECURECODER_SHELL_GUARD` |
| `codeql.languages`, `.threads`, `.ram_mb`, `.timeout_seconds` | all detected, `1`, `2048`, `600` | |
| `bins.*`, `codeql.binary` *(user scope only)* | `semgrep`, `bandit`, `python3`, … | `SEMGREP_BIN`, `BANDIT_BIN`, `CODEQL_BIN`, `PYTHON_BIN`, … |
| `trace_log` *(user scope only)* | unset | `SECURECODER_TRACE_LOG` |

See [`examples/securecoder.json`](examples/securecoder.json) for a complete project file.

## Security and privacy

- All analysis runs locally. The only network access is semgrep downloading registry rulesets such as the default `p/owasp-top-ten`; point `semgrep_config` at local rules to stay offline.
- Repository config files are treated as untrusted. They can't choose which programs SecureCoder runs: `bins.*`, `codeql.binary`, and `trace_log` are honored only from user config or the environment.
- Agents can read settings through MCP but can't change them there. Changes go through `/securecoder` or the CLI, which run under your harness's normal command approval.
- Hooks fail open: an analyzer crash never blocks your agent.

Details and vulnerability reporting: [SECURITY.md](SECURITY.md).

## Repository layout

```
.claude-plugin/          Claude Code manifest (MCP inline) and marketplace
.agents/plugins/         Codex marketplace
.cursor-plugin/          Cursor manifest and MCP config
plugin.json, mcp.json    Agent Plugins 1.0 manifest (Codex, Copilot, VS Code, Kiro)
skills/                  secure-codegen, securecoder (settings front end)
agents/                  securecoder-remediator
hooks/                   hooks.json (Claude Code + Codex), cursor.json, securecoder-hook.js
opencode/                OpenCode plugin
bin/securecoder          CLI
mcp-server/              MCP server and the guardian pipeline (lib/)
test/, scripts/          Test suite and manifest checks
dev/benchmark/           Docent trace ingestion for research benchmarks
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for running from a checkout, testing in a sandbox, the test suite, releasing, and recording benchmark traces.

## License

[MIT](LICENSE)
