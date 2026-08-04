// Loads .securecoder.json (project root or SECURECODER_CONFIG) and merges it
// over defaults. Mirrors the env-driven knobs of openai-bridge EngineFactory.

'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  // Fast analyzers: run by the PostToolUse hook and on every analyze call.
  analyzers: ['syntax', 'semgrep', 'bandit'],
  // Deep analyzers: run only when the MCP analyze tool asks for them (slow).
  deep_analyzers: ['codeql'],
  semgrep_config: 'p/owasp-top-ten',
  severity_threshold: 'HIGH',
  exclude_patterns: [
    'tests/', '*.test.js', '*.test.ts', '*.spec.*',
    'migrations/', 'node_modules/', '__pycache__/',
  ],
  retry: { soft_limit: 7, hard_limit: 14 },
  codeql: {
    binary: process.env.CODEQL_BIN || 'codeql',
    languages: null, // null = all detected
    query_packs: {}, // per-language overrides, prepended to defaults
    threads: 1,
    ram_mb: 2048,
    timeout_seconds: 600,
  },
  bins: {
    python: process.env.PYTHON_BIN || 'python3',
    node: process.env.NODE_BIN || 'node',
    gofmt: process.env.GOFMT_BIN || 'gofmt',
    clang: process.env.CLANG_BIN || 'clang',
    clangxx: process.env.CLANGXX_BIN || 'clang++',
    semgrep: process.env.SEMGREP_BIN || 'semgrep',
    bandit: process.env.BANDIT_BIN || 'bandit',
  },
};

function deepMerge(base, override) {
  const out = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    if (value && typeof value === 'object' && !Array.isArray(value) &&
        base[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      out[key] = deepMerge(base[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function loadConfig(projectRoot = process.cwd()) {
  const candidates = [
    process.env.SECURECODER_CONFIG,
    path.join(projectRoot, '.securecoder.json'),
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      const resolved = path.isAbsolute(candidate) ? candidate : path.join(projectRoot, candidate);
      if (fs.existsSync(resolved)) {
        return deepMerge(DEFAULTS, JSON.parse(fs.readFileSync(resolved, 'utf8')));
      }
    } catch {
      // Malformed config: fall through to defaults rather than break analysis.
    }
  }
  return { ...DEFAULTS };
}

function isExcluded(relPath, config) {
  return (config.exclude_patterns || []).some((pattern) => {
    if (pattern.endsWith('/')) return relPath.split(path.sep).join('/').includes(pattern.slice(0, -1) + '/') || relPath.startsWith(pattern);
    // glob-lite: '*' matches any run of characters
    const regex = new RegExp('^' + pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
    return regex.test(path.basename(relPath)) || regex.test(relPath);
  });
}

module.exports = { loadConfig, isExcluded, DEFAULTS };
