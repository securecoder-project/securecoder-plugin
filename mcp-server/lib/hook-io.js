// Harness-neutral hook plumbing: pull edited file paths and shell commands out
// of each harness's hook payload, and shape SecureCoder's response in the
// dialect that harness understands.
//
//   Claude Code  PostToolUse Write/Edit/MultiEdit  tool_input.file_path
//   Codex        PostToolUse apply_patch           tool_input.command = "*** Begin Patch …"
//   Cursor       postToolUse Write/Edit/…          tool_input.file_path | path | target_file
//   OpenCode     tool.execute.after write/edit/…   args.filePath | args.patchText
//   Claude Code, Codex  UserPromptSubmit           prompt
//
// Claude Code and Codex share one output format (hookSpecificOutput); Cursor
// uses flat snake_case fields; the OpenCode plugin gets plain text to splice
// into the tool result.

'use strict';

const path = require('path');
const { TRIAGE_RULE } = require('./feedback');

const PATCH_FILE_LINE = /^\*\*\* (Add|Update|Delete) File: (.+?)\s*$/;
const PATCH_MOVE_LINE = /^\*\*\* Move to: (.+?)\s*$/;

// Files that exist after an apply_patch envelope is applied (adds, updates,
// and rename targets; deletions and rename sources are gone).
function patchPaths(patch) {
  if (typeof patch !== 'string' || !patch.includes('*** Begin Patch')) return [];
  const out = [];
  let current = null;
  for (const line of patch.split(/\r?\n/)) {
    const file = line.match(PATCH_FILE_LINE);
    if (file) {
      current = { op: file[1], path: file[2] };
      if (file[1] !== 'Delete') out.push(current);
      continue;
    }
    const move = line.match(PATCH_MOVE_LINE);
    if (move && current && current.op === 'Update') current.path = move[1];
  }
  return [...new Set(out.map((entry) => entry.path))];
}

function toolInput(payload) {
  const input = payload && (payload.tool_input || payload.toolInput || payload.args);
  return input && typeof input === 'object' ? input : {};
}

function extractEditedPaths(payload) {
  if (!payload || typeof payload !== 'object') return [];
  const input = toolInput(payload);
  const found = [];
  for (const value of [input.file_path, input.filePath, input.path, input.target_file, input.notebook_path, payload.file_path]) {
    if (typeof value === 'string' && value.trim()) found.push(value.trim());
  }
  for (const value of [input.command, input.patch, input.patchText, input.input]) {
    found.push(...patchPaths(value));
  }
  return [...new Set(found)];
}

function extractShellCommand(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const input = toolInput(payload);
  const command = typeof input.command === 'string' ? input.command : payload.command;
  if (typeof command !== 'string' || !command.trim() || command.includes('*** Begin Patch')) return null;
  return command;
}

// The text the user submitted (Claude Code and Codex UserPromptSubmit). For a
// slash command this is the raw "/name args", not the expanded body.
function extractPrompt(payload) {
  return payload && typeof payload === 'object' && typeof payload.prompt === 'string' ? payload.prompt : '';
}

function payloadCwd(payload, env = process.env) {
  const roots = payload && Array.isArray(payload.workspace_roots) ? payload.workspace_roots : [];
  return (payload && typeof payload.cwd === 'string' && payload.cwd)
    || env.SECURECODER_PROJECT_DIR
    || env.CLAUDE_PROJECT_DIR
    || env.CURSOR_PROJECT_DIR
    || roots[0]
    || process.cwd();
}

// Resolves candidate paths and keeps only those inside the project root, so a
// hook never analyzes (or reports on) files outside the workspace.
function resolveProjectPaths(paths, { cwd, root }) {
  const rootAbs = path.resolve(root);
  const out = [];
  for (const p of paths) {
    const abs = path.resolve(cwd, p);
    const rel = path.relative(rootAbs, abs);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) out.push(abs);
  }
  return [...new Set(out)];
}

// ── output dialects ─────────────────────────────────────────────────────────

const ENFORCE_SUFFIX = 'SecureCoder is in enforce mode: fix these findings before continuing with other work, then re-check the file (securecoder_analyze with a session id tracks progress). Do not change SecureCoder settings to silence them.';
// Advisory mode shares its triage wording with securecoder_analyze feedback
// (feedback.js): only hard rejects are an obligation, the rest are weighed.
const ADVISORY_SUFFIX = `Findings marked hard-reject (the file does not parse) must be fixed; the rest are analyzer hints, not verdicts. ${TRIAGE_RULE} For a guided fix-and-recheck loop, delegate to the securecoder-remediator agent or call securecoder_analyze with a stable session id.`;

function postEditResponse({ platform, mode, findingsText }) {
  if (!findingsText) return null;
  const context = `${findingsText}\n\n${mode === 'enforce' ? ENFORCE_SUFFIX : ADVISORY_SUFFIX}`;
  if (platform === 'cursor') return { additional_context: context };
  if (platform === 'opencode') return { text: context };
  // In enforce mode the block reason already reaches the model; repeating it as
  // additionalContext would show the same findings twice.
  if (mode === 'enforce') return { decision: 'block', reason: context };
  return { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: context } };
}

function preShellResponse({ platform, mode, hits }) {
  if (!hits || hits.length === 0) return null;
  const summary = hits.map((h) => `- ${h.title}: ${h.advice}`).join('\n');
  const context = `SecureCoder shell guard flagged this command:\n${summary}`;
  if (platform === 'opencode') return { text: context, block: mode === 'enforce' };
  if (platform === 'cursor') {
    return mode === 'enforce'
      ? { permission: 'ask', user_message: context, agent_message: context }
      : { permission: 'allow', agent_message: context };
  }
  const hookSpecificOutput = { hookEventName: 'PreToolUse', additionalContext: context };
  if (mode === 'enforce') {
    hookSpecificOutput.permissionDecision = 'ask';
    hookSpecificOutput.permissionDecisionReason = context;
  }
  return { hookSpecificOutput };
}

// Only Claude Code and Codex can add context to a submitted prompt. Cursor's
// beforeSubmitPrompt can allow or block and nothing else, and OpenCode has no
// documented per-prompt hook, so for those two there is no honest response to
// give. Codex validates this object against a closed schema, so it carries
// exactly these two keys.
function userPromptResponse({ platform, context }) {
  if (!context || platform === 'cursor' || platform === 'opencode') return null;
  return { hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: context } };
}

module.exports = {
  patchPaths,
  extractEditedPaths,
  extractShellCommand,
  extractPrompt,
  payloadCwd,
  resolveProjectPaths,
  postEditResponse,
  preShellResponse,
  userPromptResponse,
};
