# Changelog

All notable changes to SecureCoder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-11

### Added

- **Security constraints on every prompt, on Claude Code and Codex.** A `UserPromptSubmit` hook
  adds SecureCoder's core secure-coding constraints to each prompt, so they reach the model whether
  or not it loads the `secure-codegen` skill. The skill carries the same block word for word. When
  the prompt mentions known weakness classes, the hook adds one line for each, at most six; the
  whole addition stays within 2,000 characters. New setting `hooks.user_prompt` (default on,
  `SECURECODER_USER_PROMPT`, `/securecoder hooks user-prompt on|off`).
  - Claude Code: yes, except for subagent prompts, which do not run the hook.
  - Codex: yes, once the hook is approved under `/hooks`. On builds that do not load plugin hooks,
    run `securecoder install-hooks codex` first.
  - Cursor and OpenCode: no. Cursor's prompt hook can only allow or block, and OpenCode has no
    documented per-prompt hook. Copilot, VS Code, and Kiro have no hooks at all. On all of these the
    constraints come from the `secure-codegen` skill, as before.
- **CWE knowledge base.** A catalog of 18 weakness classes
  (`mcp-server/lib/security-knowledge-base.json`), each with four checklist fields: how to detect
  it, a behavior-preserving repair, its common false positives, and what the repair must preserve.
  Entries are picked by a fixed keyword and language match on the task text, with no model call.
  The per-prompt hook uses a one-line form and `securecoder_enrich_prompt` returns the full
  checklist. There is no new MCP tool and no new setting for it.

### Changed

- **Analyzer findings are hints to weigh, not orders.** Remediation feedback from
  `securecoder_analyze` is split into `MUST FIX` (hard rejects: a file does not parse) and
  `WEIGH THESE` (everything else): fix what is a real, exploitable issue that can be fixed without
  changing documented behavior, and dismiss the rest with a reason. The post-edit hook uses the
  same wording in advisory mode. Enforce mode is unchanged and still blocks on findings at or above
  the threshold.
- `securecoder-remediator` can veto a finding with a stated reason and reports one of three
  statuses: `CLEAN`, `DONE_WITH_VETOES`, or `PARTIAL`. The `continue` verdict now allows stopping
  when every remaining finding has been dismissed with a reason.
- The remediator and the `secure-codegen` skill follow three conservative rules: no finding whose
  sink is absent from the code, exploitable issues rather than hardening opportunities, and a fix
  that would change documented behavior is a note, not a finding.
- At the hard retry limit, the verdict names the earlier attempt with the fewest findings when one
  is strictly better than the current state ("Attempt N had X finding(s); the current state has Y.
  Consider reverting…"), and `structuredContent.retry.best` carries it. This is advice only:
  SecureCoder keeps no earlier file contents and cannot apply the revert. Attempts with a hard
  reject are never named.
- `securecoder_enrich_prompt` returns the same four contract-preservation constraints for every
  task, plus the CWE checklist when the task matches catalog entries. The hints that depended on
  how the task was phrased (pure C, Go, synchronous JavaScript, hashes returned as strings,
  temporary files, archive extraction) are gone.
- `securecoder config set enabled off` and `securecoder config set mode advisory` are refused with
  exit code 2 when written to project or local scope and the value would weaken the setting (see
  Security). Inside a project that is the default scope, so `/securecoder off` now needs
  `--scope user`, which applies to all your projects, or `SECURECODER_ENABLED=off` for one run.
- `securecoder config gitignore` adds `.securecoder/` as well as `.securecoder.local.json`.
- `securecoder config init` no longer writes `mode` into the starter project file, where a value
  below your user config would only be ignored with a warning.
- `securecoder install-hooks codex` installs three hooks (post-edit scan, shell guard, per-prompt
  constraints).
- Each remediation session keeps its last four attempts instead of the whole history. The attempt
  count is unaffected.
- `scripts/check-manifests.js` fails when `hooks/hooks.json` and the entries `install-hooks` writes
  disagree on events or matchers.

### Removed

- CodeQL crash-signature recovery and the query-pack fallback retry. A CodeQL failure now degrades
  that analyzer only: the other analyzers still run, and the failure is listed with the result. A
  project CodeQL cannot build is still skipped quietly.
- Settings `codeql.languages`, `codeql.query_packs`, `codeql.threads`, and `codeql.ram_mb`. A
  config file that still sets one gets a warning naming the key and otherwise works as before;
  remove the key at your convenience, since the warning is kept for this release only.
  `codeql.timeout_seconds` and `codeql.binary` stay.
- Dead code: `proc.available()` and two feedback hints for rule ids this plugin never produces.

### Fixed

- The MCP server crashed when a client declared the `roots` capability and then answered
  `roots/list` with an error or not at all. A tool call arriving in that window failed too. The
  server now logs the failure once and finds the project from the environment, absolute file paths,
  or the working directory.
- A semgrep or bandit run that crashed, timed out, printed something other than its JSON report,
  or could not download its ruleset was read as "no findings". It is now reported as that
  analyzer's failure: in the scan output, in `securecoder_analyze`, and in the hook error trail.
  An analyzer that is not installed is still skipped quietly.
- A project or local config path that is not a regular file (a FIFO, a link to a device) or is
  larger than 1 MiB could hang or exhaust memory in every hook. It is now ignored with a warning.
- A CodeQL failure is reported with its cause on the first line, instead of a line that ended at
  the command.
- `securecoder install-hooks codex` wrote each hook as `command: "node"` plus an `args` array.
  Codex command hooks have no `args` field, so those entries ran bare `node` and never reached the
  hook script. Each entry is now one command string. If you installed hooks with 0.2.0, run
  `securecoder install-hooks codex` again and approve the hooks under `/hooks`; Codex trusts hooks
  per entry, and the entries changed.

### Security

- **A repository file can no longer switch SecureCoder off.** `enabled` and `mode` may be
  strengthened by `.securecoder.json` or `.securecoder.local.json` but not weakened below what the
  defaults and your user config give. A weakening value is ignored with a warning, shown on the
  dashboard and in `doctor`, that names the key and the scope. A local file may still undo
  strengthening that the project file added. Only these two keys are covered:
  `severity_threshold`, `analyzers`, `exclude_patterns`, and the `hooks.*` toggles remain under
  project control, so a repository file can still narrow or switch off the post-edit scan through
  those.
- **Hook failures leave a trail.** Hooks still fail open, but each fault (an empty or non-JSON
  payload, an unknown event, an exception, or an analyzer that failed during a post-edit scan)
  appends one JSON line to `.securecoder/errors.log` in the project. The file is capped at 64 KiB
  and keeps the newest entries. `securecoder doctor` and the `securecoder_config` doctor action
  report the count and the most recent entry. Two limits: the trail cannot show a hook that was
  never invoked, and an analyzer that is not installed is skipped without an entry (`doctor` lists
  what is installed).

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

[0.3.0]: https://github.com/securecoder-project/securecoder-plugin/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/securecoder-project/securecoder-plugin/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/securecoder-project/securecoder-plugin/releases/tag/v0.1.0
