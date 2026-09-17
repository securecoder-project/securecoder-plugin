// Hook behavior shared by every harness adapter (the command hook in
// hooks/securecoder-hook.js and the OpenCode plugin). Returns plain data;
// adapters decide how to deliver it.

'use strict';

const { analyze } = require('./analyze');
const settings = require('./settings');
const { renderFindings } = require('./report');
const { checkShellCommand } = require('./shell-guard');
const {
  extractEditedPaths, extractShellCommand, payloadCwd, resolveProjectPaths,
  postEditResponse, preShellResponse,
} = require('./hook-io');

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

module.exports = { postEdit, preShell };
