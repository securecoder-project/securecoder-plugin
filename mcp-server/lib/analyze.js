// Port of engine/workflow GuardianExecutor.kt — runs the configured guardians
// in parallel over a set of files, isolating per-guardian failures, and folds
// the results into violations + LLM-ready feedback + retry assessment.

'use strict';

const fs = require('fs');
const path = require('path');
const { loadConfig, isExcluded } = require('./config');
const { runSyntaxGuardians } = require('./syntax');
const { runCodeQLGuardian } = require('./codeql');
const { runBandit, runSemgrep } = require('./external');
const { buildFeedback } = require('./feedback');
const { recordAttempt, verdictGuidance } = require('./retry');

function resolveFiles(filePaths, projectRoot) {
  const files = [];
  const skipped = [];
  for (const p of filePaths) {
    const abs = path.isAbsolute(p) ? p : path.join(projectRoot, p);
    const rel = path.relative(projectRoot, abs);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      skipped.push({ path: p, reason: 'not a file' });
      continue;
    }
    files.push({ abs, rel: rel.startsWith('..') ? path.basename(abs) : rel, content: fs.readFileSync(abs, 'utf8') });
  }
  return { files, skipped };
}

async function analyze({
  filePaths,
  projectRoot = process.cwd(),
  analyzers = null, // null = config.analyzers; 'deep' additions via includeDeep
  includeDeep = false,
  session = null,
  log = () => {},
}) {
  const config = loadConfig(projectRoot);
  const { files: allFiles, skipped } = resolveFiles(filePaths, projectRoot);
  const excluded = allFiles.filter((f) => isExcluded(f.rel, config));
  const files = allFiles.filter((f) => !isExcluded(f.rel, config));
  for (const f of excluded) skipped.push({ path: f.rel, reason: 'matches exclude_patterns' });

  if (files.length === 0) {
    return { violations: [], failures: [], skipped, feedback: null, retry: null, analyzersRun: [] };
  }

  const selected = new Set(analyzers || config.analyzers);
  if (includeDeep) for (const a of config.deep_analyzers || []) selected.add(a);

  const runs = [];
  const failures = [];
  const guard = (name, promise) => runs.push(
    promise.then(
      (violations) => ({ name, violations }),
      (err) => {
        failures.push({ guardian: name, message: err.message || String(err) });
        return { name, violations: [] };
      },
    ),
  );

  if (selected.has('syntax')) {
    guard('syntax', runSyntaxGuardians(files, { bins: config.bins }));
  }
  if (selected.has('bandit')) {
    const overrides = (config.language_overrides && config.language_overrides.python) || {};
    guard('bandit', runBandit(files, {
      binary: config.bins.bandit,
      extraArgs: overrides.extra_args || [],
    }));
  }
  if (selected.has('semgrep')) {
    guard('semgrep', runSemgrep(files, {
      binary: config.bins.semgrep,
      config: config.semgrep_config,
    }));
  }
  if (selected.has('codeql')) {
    guard('codeql', runCodeQLGuardian(files, {
      binary: config.codeql.binary,
      enabledLanguages: config.codeql.languages,
      queryPackOverrides: config.codeql.query_packs || {},
      threads: config.codeql.threads,
      ramMb: config.codeql.ram_mb,
      timeoutMs: (config.codeql.timeout_seconds || 600) * 1000,
      log,
    }));
  }

  const results = await Promise.all(runs);
  const violations = results.flatMap((r) => r.violations);
  const analyzersRun = results.map((r) => r.name);

  const fileContents = new Map(files.map((f) => [f.rel, f.content]));
  const feedback = violations.length > 0 ? buildFeedback(violations, fileContents) : null;

  let retry = null;
  if (session) {
    const assessment = recordAttempt(session, violations, {
      softLimit: config.retry && config.retry.soft_limit,
      hardLimit: config.retry && config.retry.hard_limit,
    });
    retry = { ...assessment, guidance: verdictGuidance(assessment) };
  }

  return { violations, failures, skipped, feedback, retry, analyzersRun };
}

module.exports = { analyze };
