# Changelog

All notable changes to SecureCoder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-15

### Added

- **Multi-harness support.** One repository now installs into Claude Code, Codex, Cursor, and
  OpenCode. GitHub Copilot, VS Code, and Kiro get skills and MCP through the
  [Agent Plugins 1.0](https://agent-plugins.org) root manifest (`plugin.json`, `mcp.json`).
  - Codex: `plugin.json` (`extensions."com.openai"` hooks and interface metadata), shared
    `hooks/hooks.json` with `apply_patch` support, `.agents/plugins/marketplace.json`.
  - Cursor: `.cursor-plugin/plugin.json`, `hooks/cursor.json` (`postToolUse`, `beforeShellExecution`).
  - OpenCode: native plugin (`opencode/index.js`) that registers the MCP server, the
    `/securecoder` and `/secure-codegen` commands, and the remediator subagent, and appends
    findings to edit tool results.
- **`/securecoder` settings command.** A dashboard shows every effective setting with its source
  and the analyzers installed. Subcommands cover on/off, advisory or enforce mode, severity
  threshold, analyzers, deep CodeQL, semgrep ruleset, exclusions, retry limits, hook toggles,
  `scan`, `doctor`, `init`, and `reset`, plus an interactive menu. Codex invokes it as `$securecoder:securecoder`.
- **`securecoder` CLI** (`bin/securecoder`, on PATH in Claude Code): `status`, `doctor`, `scan`,
  and `config show|keys|get|set|add|remove|unset|reset|init|gitignore|path`, with `--json`
  output and meaningful exit codes.
- **Scoped settings** with precedence default < user (`~/.config/securecoder/config.json`) <
  project (`.securecoder.json`) < local (`.securecoder.local.json`) < environment. Values are
  validated, writes are atomic, and changes that reduce protection are flagged.
- **Enforce mode.** Findings at or above the threshold block the turn until they are addressed,
  and flagged shell commands require approval.
- MCP server: read-only `securecoder_config` tool, tool annotations, `structuredContent` for
  analysis results, MCP roots support for workspace detection, protocol version negotiation, and
  server `instructions`.
- `securecoder install-hooks codex` / `uninstall-hooks codex`: installs the post-edit and
  shell-guard hooks into `~/.codex/hooks.json` or `<repo>/.codex/hooks.json` for Codex builds that
  do not load plugin-bundled hooks. Merging is idempotent and leaves your own hooks untouched.
- Test suite (`npm test`, zero dependencies), manifest consistency checker, and CI on Linux,
  macOS, and Windows.

### Changed

- The post-edit hook now returns findings as `additionalContext`. Before, the hook printed plain
  stdout, which Claude Code does not show to the model, so findings never reached the agent.
- The shell guard now flags high-risk patterns (piping a download into a shell, disabled TLS
  verification, world-writable permissions, broad `rm -rf`, inline credentials) instead of
  warning on every `$(…)` and `eval`, and its output reaches the agent.
- Findings reported by several analyzers for the same line and CWE are grouped into one entry.
- `severity_threshold` is now applied; it was documented before but ignored. The default is `LOW`,
  which reports everything as before.
- Hooks are written in Node and no longer need `jq` or bash.
- `securecoder-remediator` now uses the plugin-scoped MCP tool names (the old names did not resolve
  for plugin servers) and inherits the session model. It absorbed the `security-reviewer` agent.
- The Claude Code MCP server is declared inline in `.claude-plugin/plugin.json`.
- One version (0.2.0) across all manifests, the MCP server, and `package.json`.

### Removed

- `settings.json` at the plugin root. It set `securecoder-remediator` as the main-session agent for
  every user who enabled the plugin.
- Root `.mcp.json`. It also registered a broken project-scoped server for anyone working in this
  repository.
- `agents/security-reviewer.md` (merged into `securecoder-remediator`), `scripts/run-sast`,
  `scripts/check-bash-command`, and `mcp-server/cli.js` (replaced by `bin/securecoder` and
  `hooks/securecoder-hook.js`).

### Security

- Settings that choose executables (`bins.*`, `codeql.binary`, `language_overrides.python.extra_args`)
  or output files (`trace_log`) are honored only from user config or environment variables. A
  cloned repository can no longer make the post-edit hook run an arbitrary program through a
  committed `.securecoder.json`.
- The MCP configuration tool is read-only. Settings change only through the user-invoked
  `/securecoder` command or the CLI, which go through the harness's normal command approval.

## [0.1.0] - 2026-08-17

- Initial Claude Code plugin: prompt enrichment, post-write SAST hook, remediation agent, and the
  zero-dependency MCP server ported from the SecureCoder Kotlin engine.

[0.2.0]: https://github.com/parsakaz/securecoder-claude-plugin/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/parsakaz/securecoder-claude-plugin/releases/tag/v0.1.0
