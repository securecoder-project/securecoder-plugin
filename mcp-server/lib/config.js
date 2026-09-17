// Effective analysis configuration for a project. Resolution (scopes,
// precedence, validation, trust boundary) lives in settings.js; this module
// keeps the small surface the guardian pipeline has always used.

'use strict';

const path = require('path');
const settings = require('./settings');

const DEFAULTS = {};
for (const [key, spec] of Object.entries(settings.SCHEMA)) {
  let cur = DEFAULTS;
  const parts = key.split('.');
  for (const part of parts.slice(0, -1)) cur = cur[part] || (cur[part] = {});
  cur[parts[parts.length - 1]] = spec.default;
}

function loadConfig(projectRoot = process.cwd(), options = {}) {
  return settings.resolve(projectRoot, { root: projectRoot, ...options }).effective;
}

function isExcluded(relPath, config) {
  const normalized = relPath.split(path.sep).join('/');
  return (config.exclude_patterns || []).some((pattern) => {
    if (pattern.endsWith('/')) return normalized.startsWith(pattern) || normalized.includes(`/${pattern}`);
    // glob-lite: '*' matches any run of characters
    const regex = new RegExp(`^${pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
    return regex.test(path.posix.basename(normalized)) || regex.test(normalized);
  });
}

module.exports = { loadConfig, isExcluded, DEFAULTS };
