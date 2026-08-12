# SecureCoder — Claude Code Plugin

A Claude Code plugin that wraps your coding sessions with a security pipeline. It enriches prompts with OWASP constraints before Claude generates code, runs SAST on every file write, and drops you into a guided remediation loop when violations are found. Analysis is handled by a **zero-dependency Node MCP server** ported from the [SecureCoder](https://github.com/STG-TuDA/SecureCoder) Kotlin engine.

---

## Requirements

| Requirement | Why | Install |
|---|---|---|
| **Node ≥ 18** | Runs the MCP server (no npm install needed) | ships with most systems; [nodejs.org](https://nodejs.org) otherwise |
| **jq** | Parses hook payloads | ships with macOS; else `brew install jq` |
| `semgrep` *(optional)* | Fast OWASP/SAST rules | `pip install semgrep` |
| `bandit` *(optional)* | Python-specific checks | `pip install bandit` |
| `codeql` *(optional)* | Deep security analysis | [GitHub CodeQL](https://github.com/github/codeql-cli-binaries/releases) |

The plugin works without any optional tools — it degrades gracefully. Check what's available by asking Claude to call `securecoder_status`.

---

## Install

From this repository (also serves as its own marketplace):

```shell
/plugin marketplace add STG-TuDA/securecoder-claude-plugin
/plugin install securecoder@securecoder-plugin
```

After review by Anthropic, from the community marketplace:

```shell
/plugin marketplace add anthropics/claude-plugins-community
/plugin install securecoder@claude-community
```

**Try it first** (one session, no install):

```bash
claude --plugin-dir /path/to/securecoder-claude-plugin
```

---

## How it works

Three things happen automatically once the plugin is active:

1. **Before Claude writes code** — the `securecoder_enrich_prompt` tool appends security constraints to the generation prompt (no-injection, parameterized queries, safe crypto, etc.).
2. **After every file write** — a hook runs the fast guardian pipeline (syntax check → semgrep → bandit) and surfaces findings inline.
3. **When violations appear** — the `securecoder-remediator` agent takes over: it calls `securecoder_analyze`, explains each finding with remediation guidance, applies fixes, and re-analyzes until the session is clean or a retry limit is reached.

For a deep scan (CodeQL), ask Claude: *"run a deep SecureCoder analysis on \<file\>"*.

---

## Usage

**Automatic** — just use Claude Code normally. The skill and hooks fire without any extra steps.

**Explicit secure generation:**

```
/securecoder:secure-codegen [optional security context, e.g. "PCI-DSS scope"]
```

---

## Configuration

Place `.securecoder.json` at your repo root. All keys are optional:

```json
{
  "analyzers": ["syntax", "semgrep", "bandit"],
  "deep_analyzers": ["codeql"],
  "semgrep_config": "p/owasp-top-ten",
  "exclude_patterns": ["tests/", "node_modules/"],
  "retry": { "soft_limit": 7, "hard_limit": 14 }
}
```

Environment overrides are available for every binary path (`CODEQL_BIN`, `SEMGREP_BIN`, `BANDIT_BIN`, …) and for the config file location (`SECURECODER_CONFIG`).

For benchmarking or CI, set `SECURECODER_TRACE_LOG=/path/to/output.jsonl` — every analysis call appends a structured JSON line with violation counts and retry verdicts.

Full config reference and all defaults: [`mcp-server/lib/config.js`](mcp-server/lib/config.js).

---

## Layout

```
securecoder-claude-plugin/
├── .claude-plugin/
│   ├── plugin.json              # plugin manifest
│   └── marketplace.json         # lets this repo serve as its own marketplace
├── .mcp.json                    # registers the securecoder-analysis MCP server
├── mcp-server/
│   ├── index.js                 # MCP stdio server (zero dependencies)
│   ├── cli.js                   # same pipeline as CLI, used by the SAST hook
│   └── lib/                     # guardian pipeline (CodeQL, semgrep, bandit, feedback)
├── agents/
│   └── securecoder-remediator.md
├── hooks/
│   └── hooks.json               # PostToolUse (SAST) + PreToolUse (shell safety check)
├── bin/
│   ├── run-sast                 # hook adapter → mcp-server/cli.js
│   └── check-bash-command       # PreToolUse hook: warns on unsafe shell patterns
├── .securecoder.json            # example project config
└── docs/
    └── DEVELOPMENT.md           # running from a checkout, CI runs, trace recording
```

---

## Further reading

- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — local dev setup, sandboxed hook testing, non-interactive CI runs, trace recording for benchmarks.

---

## License

MIT
