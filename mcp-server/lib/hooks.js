// Hook behavior shared by every harness adapter (the command hook in
// hooks/securecoder-hook.js and the OpenCode plugin). Returns plain data;
// adapters decide how to deliver it.

'use strict';

const { analyze } = require('./analyze');
const settings = require('./settings');
const { renderFindings } = require('./report');
const { checkShellCommand } = require('./shell-guard');
const { appendError } = require('./error-log');
const { SECURITY_CONSTRAINTS, MAX_PROMPT_CONTEXT_CHARS } = require('./constraints');
const { selectEntries, renderCompact } = require('./knowledge-base');
const {
  extractEditedPaths, extractShellCommand, extractPrompt, payloadCwd, resolveProjectPaths,
  postEditResponse, preShellResponse, userPromptResponse,
} = require('./hook-io');

// Records a hook fault in the project's error trail so a hook that failed open
// still leaves something `doctor` can show. The project is found the way the
// hooks find it, which also covers a payload that never parsed. Never throws:
// adapters call this from their catch blocks.
function recordError(details) {
  try {
    const { event, error, payload = null, env = process.env } = details || {};
    return appendError(settings.findProjectRoot(payloadCwd(payload, env)), { event, error });
  } catch {
    return false;
  }
}

async function postEdit(payload, { platform = 'claude', env = process.env, log = () => {} } = {}) {
  const cwd = payloadCwd(payload, env);
  const resolved = settings.resolve(cwd, { env });
  const config = resolved.effective;
  if (!config.enabled || !config.hooks.post_edit) return { skipped: 'disabled', response: null };

  const files = resolveProjectPaths(extractEditedPaths(payload), { cwd, root: resolved.root });
  if (files.length === 0) return { skipped: 'no-project-files', response: null };

  const result = await analyze({
    filePaths: files,
    projectRoot: resolved.root,
    config,
    includeDeep: false,
    log,
  });
  for (const w of resolved.warnings) log(w);
  // analyze() isolates a guardian that rejects; without this it would surface
  // only when another analyzer happened to report findings on the same edit.
  for (const f of result.failures) appendError(resolved.root, { event: 'post-edit', analyzer: f.guardian, error: f.message });
  if (result.violations.length === 0) return { result, findingsText: null, response: null };

  const findingsText = renderFindings(result);
  return {
    result,
    mode: config.mode,
    findingsText,
    response: postEditResponse({ platform, mode: config.mode, findingsText }),
  };
}

function preShell(payload, { platform = 'claude', env = process.env } = {}) {
  const cwd = payloadCwd(payload, env);
  const config = settings.resolve(cwd, { env }).effective;
  if (!config.enabled || !config.hooks.shell_guard) return { skipped: 'disabled', hits: [], response: null };
  const command = extractShellCommand(payload);
  const hits = checkShellCommand(command);
  return {
    hits,
    mode: config.mode,
    response: preShellResponse({ platform, mode: config.mode, hits }),
  };
}

// Puts the core constraints in front of the model on every prompt, plus one
// line for each knowledge-base entry the prompt selects. This is the delivery
// that does not depend on the model deciding to load the secure-codegen skill.
// It runs on every prompt, so it reads settings and nothing else: no
// analyzers, no subprocess. A payload without a usable prompt still gets the
// constraints; it just selects no entries.
function userPrompt(payload, { platform = 'claude', env = process.env } = {}) {
  const cwd = payloadCwd(payload, env);
  const config = settings.resolve(cwd, { env }).effective;
  if (!config.enabled || !config.hooks.user_prompt) return { skipped: 'disabled', cwes: [], response: null };

  // The ceiling is enforced here and not only by the catalog's wording: if the
  // lines for a selection would not fit, the lowest-ranked ones are left out.
  const room = MAX_PROMPT_CONTEXT_CHARS - SECURITY_CONSTRAINTS.length - 2;
  const selected = selectEntries(extractPrompt(payload));
  const entries = selected.filter((_, i) => renderCompact(selected.slice(0, i + 1)).length <= room);
  const context = entries.length ? `${SECURITY_CONSTRAINTS}\n\n${renderCompact(entries)}` : SECURITY_CONSTRAINTS;
  return {
    cwes: entries.map((entry) => entry.id),
    context,
    response: userPromptResponse({ platform, context }),
  };
}

module.exports = { postEdit, preShell, userPrompt, recordError };
