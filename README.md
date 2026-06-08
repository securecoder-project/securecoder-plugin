# SecureCoder — Claude Code Plugin

Security-aware code generation pipeline for Claude Code. Combines prompt-level constraint injection, post-write SAST feedback, and an iterative remediation agent into a single installable plugin.

## What it does

```
User asks Claude to write code
        │
        ▼
┌─────────────────────────┐
│  secure-codegen SKILL   │  ← auto-invoked on any code generation task
│  - threat model inline  │
│  - constraint injection │
│  - SECURITY: comments   │
│  - self-review checklist│
└────────────┬────────────┘
             │ Claude writes file
             ▼
┌─────────────────────────┐
│  PostToolUse HOOK       │  ← fires automatically after Write/Edit
│  bin/run-sast <file>    │
│  (bandit / semgrep /    │
│   your custom analyzer) │
└────────────┬────────────┘
             │ findings → injected into Claude context
             ▼
┌─────────────────────────┐
│  securecoder-remediator │  ← agent, own context window
│  AGENT                  │  triage → patch → re-run → loop (max 5)
│                         │  emits REMEDIATION REPORT
└─────────────────────────┘
```

## Installation

```bash
# From a local directory (dev/testing)
claude --plugin-dir ./securecoder-plugin

# After publishing to a marketplace
/plugin install <your-marketplace>@securecoder
```

## Usage

**Automatic**: just use Claude Code normally. The skill auto-invokes on code generation tasks, the hook fires on every file write.

**Manual / explicit pipeline**:
```
/securecoder:secure-codegen [optional: security context e.g. "PCI-DSS scope"]
```

## Connecting your analyzer

Edit `bin/run-sast`. The TOOL BLOCK section maps file extensions to analyzer calls.
For your existing Kotlin/IntelliJ pipeline, add a case for `kt|kts` that calls your CLI or MCP server.

Supported out of the box (if installed):
- Python → bandit
- JS/TS/Java/generic → semgrep

To add a custom tool, emit lines in the format:
```
[HIGH|MED|LOW] RULE_ID line N: description
```

## MCP server variant

If your analyzer backend is already an MCP server, add `.mcp.json` at the plugin root:

```json
{
  "mcpServers": {
    "securecoder-backend": {
      "command": "your-mcp-server-binary",
      "args": ["--stdio"],
      "env": {}
    }
  }
}
```

Then call it from run-sast or from the remediator agent directly via tool use.

## Plugin structure

```
securecoder-plugin/
├── .claude-plugin/
│   └── plugin.json                  # manifest + metadata
├── skills/
│   └── secure-codegen/
│       └── SKILL.md                 # constraint injection + self-review
├── agents/
│   └── securecoder-remediator.md    # iterative SAST feedback loop agent
├── hooks/
│   └── hooks.json                   # PostToolUse (SAST) + PreToolUse (shell warn)
├── bin/
│   └── run-sast                     # adapter script — plug your tools in here
├── settings.json                    # sets remediator as default agent
└── README.md
```

## Publishing

```bash
# Validate before submitting
claude plugin validate ./securecoder-plugin

# Submit to community marketplace
# → https://claude.ai/settings/plugins/submit
```
