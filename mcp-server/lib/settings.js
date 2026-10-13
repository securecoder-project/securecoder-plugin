// Scoped, schema-validated SecureCoder settings.
//
// Precedence (lowest → highest): defaults < user < project < local < env.
//   user    ~/.config/securecoder/config.json   (SECURECODER_HOME / XDG_CONFIG_HOME / APPDATA)
//   project <root>/.securecoder.json            (committed, shared with the team)
//   local   <root>/.securecoder.local.json      (personal, should be gitignored)
//   env     SECURECODER_* and *_BIN variables
//
// Trust boundary: keys that choose which binaries run or where files are
// written ("trusted" keys) are honored only from user scope or env. A cloned
// repository must never be able to make the post-edit hook execute an
// arbitrary program just by committing a .securecoder.json.
//
// Kill switches: `enabled` and `mode` follow the precedence above with one
// exception. A project or local value that would weaken what defaults and user
// config give is ignored (see FLOOR_KEYS), because the agent being checked can
// write both of those files.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const SCOPES = ['user', 'project', 'local'];
const SOURCES = ['default', ...SCOPES, 'env'];
const IGNORED_FILE_KEYS = new Set(['_comment', '$schema']);

const DEFAULT_EXCLUDES = [
  'tests/', '*.test.js', '*.test.ts', '*.spec.*',
  'migrations/', 'node_modules/', '__pycache__/',
];

// Flat dotted keys → spec. `weakens(next, prev)` flags changes that reduce
// protection so every write path can surface them to the user. For FLOOR_KEYS
// it also decides which repository-scope values resolve() honors.
const SCHEMA = {
  enabled: {
    type: 'boolean', default: true, env: 'SECURECODER_ENABLED',
    description: 'Master switch for all SecureCoder hooks and automatic analysis.',
    weakens: (next) => next === false,
  },
  mode: {
    type: 'enum', values: ['advisory', 'enforce'], default: 'advisory', env: 'SECURECODER_MODE',
    description: 'What the hooks return. advisory: findings are added to the agent context. enforce: findings at or above the threshold block the turn until addressed, and risky shell commands require approval.',
    weakens: (next, prev) => prev === 'enforce' && next === 'advisory',
  },
  severity_threshold: {
    type: 'enum', values: ['LOW', 'MEDIUM', 'HIGH'], default: 'LOW', env: 'SECURECODER_SEVERITY', upper: true,
    description: 'Minimum severity reported by hooks and analysis. Hard rejects (unparseable code) are always reported.',
    weakens: (next, prev) => SCHEMA.severity_threshold.values.indexOf(next) > SCHEMA.severity_threshold.values.indexOf(prev),
  },
  analyzers: {
    type: 'set', values: ['syntax', 'semgrep', 'bandit'], default: ['syntax', 'semgrep', 'bandit'],
    description: 'Fast analyzers run after every edit and on each analysis call.',
    weakens: (next, prev) => prev.some((a) => !next.includes(a)),
  },
  deep_analyzers: {
    type: 'set', values: ['codeql'], default: ['codeql'],
    description: 'Slow analyzers run only when deep analysis is requested.',
    weakens: (next, prev) => prev.some((a) => !next.includes(a)),
  },
  semgrep_config: {
    type: 'string', default: 'p/owasp-top-ten',
    description: 'Semgrep ruleset: a registry id (p/...), "auto", or a path to local rules. Registry rulesets are downloaded from semgrep.dev.',
  },
  exclude_patterns: {
    type: 'list', default: DEFAULT_EXCLUDES,
    description: 'Paths skipped by analysis. "dir/" matches a directory anywhere; "*" matches any run of characters.',
    weakens: (next, prev) => next.some((p) => !prev.includes(p)),
  },
  'retry.soft_limit': {
    type: 'integer', min: 1, max: 100, default: 7,
    description: 'Remediation attempt from which securecoder_analyze advises the agent to review whether its fix loop is still making progress (verdict meta_review). Advice to the agent, independent of mode.',
  },
  'retry.hard_limit': {
    type: 'integer', min: 1, max: 100, default: 14,
    description: 'Remediation attempt from which securecoder_analyze advises the agent to stop and report PARTIAL (verdict hard_limit_exhausted). Advice to the agent; SecureCoder does not run the loop and cannot stop it.',
  },
  'hooks.post_edit': {
    type: 'boolean', default: true, env: 'SECURECODER_POST_EDIT',
    description: 'Run fast analyzers on every file the agent writes or edits.',
    weakens: (next) => next === false,
  },
  'hooks.shell_guard': {
    type: 'boolean', default: true, env: 'SECURECODER_SHELL_GUARD',
    description: 'Flag high-risk shell commands (curl | sh, disabled TLS verification, chmod 777, rm -rf on broad targets).',
    weakens: (next) => next === false,
  },
  'hooks.user_prompt': {
    type: 'boolean', default: true, env: 'SECURECODER_USER_PROMPT',
    description: 'Add the core secure-coding constraints, and a short checklist for the weakness classes the prompt touches, to every prompt. Works on Claude Code and Codex; Cursor and OpenCode have no per-prompt context hook.',
    weakens: (next) => next === false,
  },
  'codeql.timeout_seconds': {
    type: 'integer', min: 30, max: 14400, default: 600,
    description: 'Timeout for each CodeQL step.',
  },
  'codeql.binary': {
    type: 'string', default: 'codeql', env: 'CODEQL_BIN', trusted: true,
    description: 'CodeQL executable.',
  },
  'bins.python': { type: 'string', default: 'python3', env: 'PYTHON_BIN', trusted: true, description: 'Python interpreter for the syntax guardian.' },
  'bins.node': { type: 'string', default: 'node', env: 'NODE_BIN', trusted: true, description: 'Node executable for the syntax guardian.' },
  'bins.gofmt': { type: 'string', default: 'gofmt', env: 'GOFMT_BIN', trusted: true, description: 'gofmt executable for the syntax guardian.' },
  'bins.clang': { type: 'string', default: 'clang', env: 'CLANG_BIN', trusted: true, description: 'clang executable for the syntax guardian.' },
  'bins.clangxx': { type: 'string', default: 'clang++', env: 'CLANGXX_BIN', trusted: true, description: 'clang++ executable for the syntax guardian.' },
  'bins.semgrep': { type: 'string', default: 'semgrep', env: 'SEMGREP_BIN', trusted: true, description: 'Semgrep executable.' },
  'bins.bandit': { type: 'string', default: 'bandit', env: 'BANDIT_BIN', trusted: true, description: 'Bandit executable.' },
  'language_overrides.python.extra_args': {
    type: 'list', default: [], trusted: true,
    description: 'Extra command-line arguments passed to bandit.',
  },
  trace_log: {
    type: 'string', default: null, nullable: true, env: 'SECURECODER_TRACE_LOG', trusted: true,
    description: 'Append a structured JSON line per MCP tool call to this file (benchmarking).',
  },
};

// The two kill switches. A file inside the repository (project or local
// scope) may strengthen them but never take them below what defaults and user
// config give: an agent holding Write or Bash can create those files, so
// honoring `"enabled": false` from one would let it switch off its own
// post-edit scan. Every other key with a `weakens` predicate stays under
// project control on purpose; thresholds, analyzers and exclusions are tuning
// a team is meant to commit.
const FLOOR_KEYS = new Set(['enabled', 'mode']);

// Settings removed in 0.3.0. A config file that still carries one gets a
// warning naming it instead of the generic unknown-key one, and typing one gets
// an error that says where it went. Delete this constant and its three uses
// (flattenKeys, resolve, requireKey) in the release after 0.3.0.
const REMOVED_KEYS = new Set(['codeql.languages', 'codeql.query_packs', 'codeql.threads', 'codeql.ram_mb']);

// Short names accepted anywhere a key is typed (CLI, /securecoder).
const ALIASES = {
  severity: 'severity_threshold',
  threshold: 'severity_threshold',
  ruleset: 'semgrep_config',
  rules: 'semgrep_config',
  exclude: 'exclude_patterns',
  excludes: 'exclude_patterns',
  soft_limit: 'retry.soft_limit',
  hard_limit: 'retry.hard_limit',
  post_edit: 'hooks.post_edit',
  shell_guard: 'hooks.shell_guard',
  user_prompt: 'hooks.user_prompt',
  deep: 'deep_analyzers',
};

function canonicalKey(key) {
  const k = String(key || '').trim();
  if (SCHEMA[k]) return k;
  const normalized = k.replace(/-/g, '_');
  return ALIASES[normalized] || (SCHEMA[normalized] ? normalized : k);
}

class SettingsError extends Error {
  constructor(message, code = 'invalid') {
    super(message);
    this.name = 'SettingsError';
    this.code = code;
  }
}

// ── paths ────────────────────────────────────────────────────────────────────

function userConfigPath(env = process.env) {
  if (env.SECURECODER_HOME) return path.join(env.SECURECODER_HOME, 'config.json');
  if (process.platform === 'win32' && env.APPDATA) return path.join(env.APPDATA, 'securecoder', 'config.json');
  const base = env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(base, 'securecoder', 'config.json');
}

// Nearest ancestor holding .securecoder.json or .git; the start dir otherwise.
function findProjectRoot(startDir = process.cwd()) {
  const start = path.resolve(startDir);
  let dir = start;
  for (;;) {
    if (fs.existsSync(path.join(dir, '.securecoder.json')) || fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return start;
    dir = parent;
  }
}

function scopePaths(root, env = process.env) {
  const explicit = env.SECURECODER_CONFIG;
  return {
    user: userConfigPath(env),
    project: explicit ? path.resolve(root, explicit) : path.join(root, '.securecoder.json'),
    local: path.join(root, '.securecoder.local.json'),
  };
}

// ── nested object helpers ────────────────────────────────────────────────────

function hasPath(obj, key) {
  let cur = obj;
  for (const part of key.split('.')) {
    if (!cur || typeof cur !== 'object' || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, part)) return false;
    cur = cur[part];
  }
  return true;
}

function getPath(obj, key) {
  return key.split('.').reduce((cur, part) => (cur == null ? undefined : cur[part]), obj);
}

function setPath(obj, key, value) {
  const parts = key.split('.');
  let cur = obj;
  for (const part of parts.slice(0, -1)) {
    if (!cur[part] || typeof cur[part] !== 'object' || Array.isArray(cur[part])) cur[part] = {};
    cur = cur[part];
  }
  cur[parts[parts.length - 1]] = value;
}

// Deletes the key and prunes parents it leaves empty.
function deletePath(obj, key) {
  const parts = key.split('.');
  const trail = [obj];
  for (const part of parts.slice(0, -1)) {
    const next = trail[trail.length - 1][part];
    if (!next || typeof next !== 'object') return false;
    trail.push(next);
  }
  const leaf = trail[trail.length - 1];
  if (!Object.prototype.hasOwnProperty.call(leaf, parts[parts.length - 1])) return false;
  delete leaf[parts[parts.length - 1]];
  for (let i = trail.length - 1; i > 0; i--) {
    if (Object.keys(trail[i]).length === 0) delete trail[i - 1][parts[i - 1]];
    else break;
  }
  return true;
}

function flattenKeys(obj, prefix = '') {
  const keys = [];
  for (const [k, v] of Object.entries(obj || {})) {
    const full = prefix ? `${prefix}.${k}` : k;
    if (IGNORED_FILE_KEYS.has(full)) continue;
    // A removed key stops the descent like a known one, so an object value
    // under it is reported once, as that key, rather than leaf by leaf.
    if (SCHEMA[full] || REMOVED_KEYS.has(full)) keys.push(full);
    else if (v && typeof v === 'object' && !Array.isArray(v)) keys.push(...flattenKeys(v, full));
    else keys.push(full);
  }
  return keys;
}

// ── validation & parsing ─────────────────────────────────────────────────────

function describeAllowed(spec) {
  switch (spec.type) {
    case 'boolean': return 'on | off';
    case 'enum': return spec.values.join(' | ');
    case 'integer': return `integer ${spec.min}–${spec.max}`;
    case 'set': return `comma-separated subset of: ${spec.values.join(', ')}`;
    case 'list': return 'comma-separated list or JSON array';
    default: return spec.nullable ? 'text (or "null")' : 'text';
  }
}

// Validates an already-typed value (from a JSON file). Returns the normalized value.
function validate(key, value) {
  const spec = SCHEMA[key];
  const fail = (why) => { throw new SettingsError(`Invalid value for ${key}: ${why}. Allowed: ${describeAllowed(spec)}.`); };
  if (value === null && spec.nullable) return null;
  switch (spec.type) {
    case 'boolean':
      if (typeof value !== 'boolean') fail(`expected boolean, got ${JSON.stringify(value)}`);
      return value;
    case 'enum': {
      const v = typeof value === 'string' && spec.upper ? value.toUpperCase() : value;
      if (!spec.values.includes(v)) fail(`${JSON.stringify(value)} is not an option`);
      return v;
    }
    case 'integer':
      if (!Number.isInteger(value)) fail(`expected an integer, got ${JSON.stringify(value)}`);
      if (value < spec.min || value > spec.max) fail(`${value} is out of range`);
      return value;
    case 'set': {
      if (!Array.isArray(value)) fail('expected an array');
      const bad = value.filter((v) => !spec.values.includes(v));
      if (bad.length) fail(`unknown ${bad.length === 1 ? 'entry' : 'entries'} ${bad.map((b) => JSON.stringify(b)).join(', ')}`);
      return spec.values.filter((v) => value.includes(v));
    }
    case 'list':
      if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || v.length === 0)) fail('expected an array of non-empty strings');
      return [...new Set(value)];
    default:
      if (typeof value !== 'string' || value.length === 0) fail('expected non-empty text');
      return value;
  }
}

const TRUE_WORDS = new Set(['on', 'true', 'yes', '1', 'enable', 'enabled']);
const FALSE_WORDS = new Set(['off', 'false', 'no', '0', 'disable', 'disabled']);

// Parses user-typed text (CLI argument or env var) into a typed, validated value.
function parseValue(key, raw) {
  const spec = SCHEMA[key];
  if (raw === undefined || raw === null) throw new SettingsError(`Missing value for ${key}. Allowed: ${describeAllowed(spec)}.`);
  const text = String(raw).trim();
  if (spec.nullable && ['null', 'none', 'default'].includes(text.toLowerCase())) return null;
  switch (spec.type) {
    case 'boolean': {
      const lower = text.toLowerCase();
      if (TRUE_WORDS.has(lower)) return true;
      if (FALSE_WORDS.has(lower)) return false;
      return validate(key, text);
    }
    case 'enum': {
      const match = spec.values.find((v) => v.toLowerCase() === text.toLowerCase());
      return validate(key, match || text);
    }
    case 'integer':
      return validate(key, /^-?\d+$/.test(text) ? Number(text) : text);
    case 'set':
    case 'list': {
      let items;
      if (text.startsWith('[')) {
        try { items = JSON.parse(text); } catch { throw new SettingsError(`Invalid JSON array for ${key}.`); }
      } else {
        items = text.split(',').map((s) => s.trim()).filter(Boolean);
      }
      if (spec.type === 'set') items = items.map((s) => (typeof s === 'string' ? s.toLowerCase() : s));
      return validate(key, items);
    }
    default:
      return validate(key, text);
  }
}

function suggestKey(key) {
  const candidates = Object.keys(SCHEMA);
  const distance = (a, b) => {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
    }
    return dp[a.length][b.length];
  };
  const scored = candidates
    .map((c) => ({ c, d: Math.min(distance(key, c), c.endsWith(`.${key}`) || c.includes(key) ? 1 : Infinity) }))
    .sort((x, y) => x.d - y.d);
  return scored[0] && scored[0].d <= 3 ? scored[0].c : null;
}

function requireKey(key) {
  key = canonicalKey(key);
  if (!SCHEMA[key]) {
    if (REMOVED_KEYS.has(key.replace(/-/g, '_'))) {
      throw new SettingsError(`Unknown setting "${key}": it was removed in SecureCoder 0.3.0 and no longer has any effect. Run "securecoder config keys" to list settings.`, 'unknown_key');
    }
    const hint = suggestKey(key);
    throw new SettingsError(`Unknown setting "${key}".${hint ? ` Did you mean "${hint}"?` : ''} Run "securecoder config keys" to list settings.`, 'unknown_key');
  }
  return SCHEMA[key];
}

function requireScope(scope) {
  if (!SCOPES.includes(scope)) throw new SettingsError(`Unknown scope "${scope}". Use one of: ${SCOPES.join(', ')}.`, 'invalid_scope');
  return scope;
}

// ── file IO ──────────────────────────────────────────────────────────────────

// Config files are tiny. A project or local path is inside the repository, so
// it may be anything: a FIFO or a link to a device would block or exhaust
// memory in a synchronous read, and with it every hook.
const MAX_CONFIG_BYTES = 1024 * 1024;

function readScopeFile(file) {
  if (!fs.existsSync(file)) return { exists: false, data: {} };
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) return { exists: true, data: {}, error: 'not a regular file' };
    if (stat.size > MAX_CONFIG_BYTES) return { exists: true, data: {}, error: `larger than ${MAX_CONFIG_BYTES / 1024} KiB` };
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      return { exists: true, data: {}, error: 'top-level value must be a JSON object' };
    }
    return { exists: true, data };
  } catch (err) {
    return { exists: true, data: {}, error: err.message };
  }
}

function writeJsonAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  fs.writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o644 });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* best effort */ }
    throw err;
  }
}

// ── resolution ───────────────────────────────────────────────────────────────

function cloneDefault(value) {
  return value && typeof value === 'object' ? JSON.parse(JSON.stringify(value)) : value;
}

// The floor of a kill switch: default < user scope, the two sources a file
// inside the repository cannot touch. An invalid user value falls back to the
// default here exactly as it does in resolve(), which reports it.
function floorValue(key, userData) {
  if (hasPath(userData, key)) {
    try { return validate(key, getPath(userData, key)); } catch { /* reported by resolve() */ }
  }
  return SCHEMA[key].default;
}

// True when a project- or local-scope value would take a kill switch below
// its floor. The comparison is against the floor, not against whatever a lower
// repository scope produced: a repository file that strengthens the setting
// can always be undone by editing that same file, so shielding project-level
// strengthening from local scope would buy no security and only break
// legitimate personal overrides. Restating the floor is not weakening; the
// explicit check is needed because the `enabled` predicate ignores `prev`.
function belowFloor(key, scope, candidate, userData) {
  if (!FLOOR_KEYS.has(key) || scope === 'user') return false;
  const floor = floorValue(key, userData);
  return candidate !== floor && SCHEMA[key].weakens(candidate, floor);
}

function resolve(startDir = process.cwd(), { env = process.env, root: explicitRoot } = {}) {
  const root = explicitRoot ? path.resolve(explicitRoot) : findProjectRoot(startDir);
  const paths = scopePaths(root, env);
  const files = {};
  const warnings = [];
  const scopeData = {};

  for (const scope of SCOPES) {
    const read = readScopeFile(paths[scope]);
    files[scope] = { path: paths[scope], exists: read.exists, ...(read.error ? { error: read.error } : {}) };
    if (read.error) warnings.push(`Ignoring ${scope} config ${paths[scope]}: ${read.error}`);
    scopeData[scope] = read.data;
    for (const key of flattenKeys(read.data)) {
      if (REMOVED_KEYS.has(key)) warnings.push(`"${key}" in ${scope} config was removed in SecureCoder 0.3.0 and is ignored. Delete it from the file to silence this warning.`);
      else if (!SCHEMA[key]) warnings.push(`Unknown key "${key}" in ${scope} config (ignored).`);
    }
  }

  const values = {};
  for (const [key, spec] of Object.entries(SCHEMA)) {
    let value = cloneDefault(spec.default);
    let source = 'default';
    for (const scope of SCOPES) {
      if (!hasPath(scopeData[scope], key)) continue;
      if (spec.trusted && scope !== 'user') {
        warnings.push(`Ignoring "${key}" from ${scope} config: it selects executables or output files, so it is only honored from user config or environment variables.`);
        continue;
      }
      try {
        const candidate = validate(key, getPath(scopeData[scope], key));
        if (belowFloor(key, scope, candidate, scopeData.user)) {
          warnings.push(`Ignoring "${key}" = ${formatValue(candidate)} from ${scope} config: a file inside the repository may strengthen this setting but never weaken it. Set it in user config or $${spec.env} instead.`);
          continue;
        }
        value = candidate;
        source = scope;
      } catch (err) {
        warnings.push(`${err.message} (in ${scope} config; ignored)`);
      }
    }
    if (spec.env && env[spec.env] !== undefined && env[spec.env] !== '') {
      try {
        value = parseValue(key, env[spec.env]);
        source = 'env';
      } catch (err) {
        warnings.push(`${err.message} (from $${spec.env}; ignored)`);
      }
    }
    values[key] = { value, source };
  }

  if (values['retry.soft_limit'].value > values['retry.hard_limit'].value) {
    warnings.push(`retry.soft_limit (${values['retry.soft_limit'].value}) is above retry.hard_limit (${values['retry.hard_limit'].value}); the soft limit will never be reached.`);
  }

  const effective = {};
  for (const [key, { value }] of Object.entries(values)) setPath(effective, key, value);

  return { root, files, values, effective, warnings };
}

// ── mutation ─────────────────────────────────────────────────────────────────

function loadForWrite(file) {
  const read = readScopeFile(file);
  if (read.error) {
    throw new SettingsError(`Refusing to modify ${file}: it is not valid JSON (${read.error}). Fix or remove it first.`, 'malformed_file');
  }
  return read.data;
}

function describeChange(key, before, after, scope) {
  const spec = SCHEMA[key];
  const notices = [];
  if (spec.weakens && before.value !== undefined && after.value !== null && before.value !== null) {
    try {
      if (spec.weakens(after.value, before.value)) {
        let change = `changed from ${formatValue(before.value)} to ${formatValue(after.value)}`;
        if (Array.isArray(before.value) && Array.isArray(after.value)) {
          const added = after.value.filter((x) => !before.value.includes(x)).map((x) => `+${x}`);
          const removed = before.value.filter((x) => !after.value.includes(x)).map((x) => `-${x}`);
          change = `changed (${[...added, ...removed].join(', ')})`;
        }
        notices.push(`⚠ This reduces protection: ${key} ${change}.`);
      }
    } catch { /* comparison is advisory */ }
  }
  if (after.source !== scope) {
    notices.push(`Note: ${key} is still ${formatValue(after.value)} because the ${after.source} ${after.source === 'env' ? `variable $${spec.env}` : 'scope'} takes precedence over ${scope}.`);
  }
  return notices;
}

function assertWritable(key, scope) {
  const spec = requireKey(key);
  requireScope(scope);
  if (spec.trusted && scope !== 'user') {
    throw new SettingsError(`"${key}" can only be set in user scope (add --scope user), because it selects executables or output files.`, 'trusted_key');
  }
  return spec;
}

function set(key, value, { scope, cwd = process.cwd(), root, env = process.env } = {}) {
  key = canonicalKey(key);
  const spec = assertWritable(key, scope);
  const normalized = validate(key, value);
  const before = resolve(cwd, { env, root });
  const file = before.files[scope].path;
  // resolve() would ignore this value, so writing it would leave a dead entry
  // in the file and a misleading "takes precedence" note. Refuse up front.
  if (belowFloor(key, scope, normalized, readScopeFile(before.files.user.path).data)) {
    const change = normalized === false ? 'turned off' : `lowered to ${formatValue(normalized)}`;
    throw new SettingsError(`"${key}" cannot be ${change} from ${scope} config: a file inside the repository may strengthen this setting but never weaken it. Use --scope user (applies to all your projects) or the $${spec.env} environment variable.`, 'weakens_floor');
  }
  const data = loadForWrite(file);
  setPath(data, key, normalized);
  writeJsonAtomic(file, data);
  const after = resolve(cwd, { env, root: before.root });
  return {
    key, scope, file, value: normalized,
    previous: before.values[key],
    effective: after.values[key],
    notices: describeChange(key, before.values[key], after.values[key], scope),
  };
}

function setFromText(key, raw, options) {
  key = canonicalKey(key);
  requireKey(key);
  return set(key, parseValue(key, raw), options);
}

// Adds/removes list entries. A scope that does not define the key yet starts
// from the current effective value, so "exclude add build/" extends the
// defaults instead of replacing them with a one-element list.
function modifyList(key, { add = [], remove = [] }, { scope, cwd = process.cwd(), root, env = process.env } = {}) {
  key = canonicalKey(key);
  const spec = assertWritable(key, scope);
  if (spec.type !== 'set' && spec.type !== 'list') throw new SettingsError(`${key} is not a list setting.`);
  const current = resolve(cwd, { env, root });
  const data = loadForWrite(current.files[scope].path);
  let base = hasPath(data, key) ? getPath(data, key) : current.values[key].value;
  if (base === null) base = spec.type === 'set' ? [...spec.values] : [];
  const addItems = spec.type === 'set' ? add.map((s) => s.toLowerCase()) : add;
  const removeItems = spec.type === 'set' ? remove.map((s) => s.toLowerCase()) : remove;
  const missing = removeItems.filter((r) => !base.includes(r));
  const next = base.filter((item) => !removeItems.includes(item)).concat(addItems.filter((a) => !base.includes(a)));
  const result = set(key, next, { scope, cwd, root: current.root, env });
  if (missing.length) result.notices.unshift(`Not present (nothing removed): ${missing.join(', ')}`);
  return result;
}

function unset(key, { scope, cwd = process.cwd(), root, env = process.env } = {}) {
  key = canonicalKey(key);
  requireKey(key);
  requireScope(scope);
  const before = resolve(cwd, { env, root });
  const file = before.files[scope].path;
  if (!before.files[scope].exists) {
    return { key, scope, file, removed: false, effective: before.values[key], notices: [`${scope} config does not exist; nothing to remove.`] };
  }
  const data = loadForWrite(file);
  const removed = deletePath(data, key);
  if (removed) writeJsonAtomic(file, data);
  const after = resolve(cwd, { env, root: before.root });
  const notices = removed ? describeChange(key, before.values[key], after.values[key], after.values[key].source) : [`${key} was not set in ${scope} config.`];
  return { key, scope, file, removed, previous: before.values[key], effective: after.values[key], notices };
}

// Removes every known setting from one scope file, keeping comments and
// unknown keys (they may belong to a newer SecureCoder version).
function reset({ scope, cwd = process.cwd(), root, env = process.env } = {}) {
  requireScope(scope);
  const before = resolve(cwd, { env, root });
  const file = before.files[scope].path;
  if (!before.files[scope].exists) return { scope, file, removed: [], notices: [`${scope} config does not exist; nothing to reset.`] };
  const data = loadForWrite(file);
  const removed = Object.keys(SCHEMA).filter((key) => deletePath(data, key));
  if (removed.length) writeJsonAtomic(file, data);
  const after = resolve(cwd, { env, root: before.root });
  const notices = [];
  for (const key of removed) {
    const spec = SCHEMA[key];
    try {
      if (spec.weakens && spec.weakens(after.values[key].value, before.values[key].value)) {
        notices.push(`⚠ This reduces protection: ${key} is now ${formatValue(after.values[key].value)} (${after.values[key].source}).`);
      }
    } catch { /* advisory */ }
  }
  return { scope, file, removed, notices };
}

const STARTER_PROJECT_CONFIG = {
  _comment: 'SecureCoder project settings, shared with everyone working in this repository. Personal overrides belong in .securecoder.local.json. Run "/securecoder help" or "securecoder config keys" for every option.',
  severity_threshold: 'LOW',
  analyzers: ['syntax', 'semgrep', 'bandit'],
  semgrep_config: 'p/owasp-top-ten',
  exclude_patterns: DEFAULT_EXCLUDES,
};

function init({ scope = 'project', cwd = process.cwd(), root, env = process.env, force = false } = {}) {
  requireScope(scope);
  const resolved = resolve(cwd, { env, root });
  const file = resolved.files[scope].path;
  if (resolved.files[scope].exists && !force) {
    throw new SettingsError(`${file} already exists. Use "config set" to change it, or --force to overwrite.`, 'exists');
  }
  const data = scope === 'project'
    ? STARTER_PROJECT_CONFIG
    : { _comment: `SecureCoder ${scope} settings. Run "securecoder config keys" for every option.` };
  writeJsonAtomic(file, data);
  return { scope, file };
}

// Personal overrides, and the directory holding the hook error trail.
const GITIGNORE_ENTRIES = ['.securecoder.local.json', '.securecoder/'];

// Ensures everything SecureCoder writes for one developer is gitignored.
// Returns what was done: `added` entries were appended, `present` ones were
// already there.
function ensureLocalGitignored(root) {
  const gitignore = path.join(root, '.gitignore');
  const existing = fs.existsSync(gitignore) ? fs.readFileSync(gitignore, 'utf8') : '';
  const lines = existing.split(/\r?\n/).map((line) => line.trim().replace(/^\//, ''));
  // A directory entry ignores the same files without its trailing slash.
  const isPresent = (entry) => lines.includes(entry) || (entry.endsWith('/') && lines.includes(entry.slice(0, -1)));
  const present = GITIGNORE_ENTRIES.filter(isPresent);
  const added = GITIGNORE_ENTRIES.filter((entry) => !isPresent(entry));
  if (added.length === 0) return { file: gitignore, changed: false, added, present };
  const prefix = existing.length && !existing.endsWith('\n') ? '\n' : '';
  fs.writeFileSync(gitignore, `${existing}${prefix}${added.join('\n')}\n`);
  return { file: gitignore, changed: true, added, present };
}

// Default write scope: a project-local override inside a project, user scope
// when not inside any project (no .git or .securecoder.json up the tree).
function defaultScope(cwd = process.cwd()) {
  const start = path.resolve(cwd);
  const root = findProjectRoot(start);
  const inProject = fs.existsSync(path.join(root, '.git')) || fs.existsSync(path.join(root, '.securecoder.json'));
  return inProject ? 'local' : 'user';
}

function formatValue(value) {
  if (value === null || value === undefined) return 'unset';
  if (value === true) return 'on';
  if (value === false) return 'off';
  if (Array.isArray(value)) return value.length ? value.join(', ') : '(none)';
  return String(value);
}

module.exports = {
  SCHEMA,
  ALIASES,
  SCOPES,
  canonicalKey,
  SOURCES,
  SettingsError,
  resolve,
  set,
  setFromText,
  modifyList,
  unset,
  reset,
  init,
  parseValue,
  validate,
  describeAllowed,
  requireKey,
  defaultScope,
  ensureLocalGitignored,
  findProjectRoot,
  userConfigPath,
  formatValue,
};
