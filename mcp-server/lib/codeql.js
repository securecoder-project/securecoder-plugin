// Port of guardian/codeql CodeQLGuardian.kt + CodeQLRunner.kt.
// Writes the candidate files to a temp source root, builds a CodeQL database
// per detected language, analyzes with query-pack fallback, and parses SARIF.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { run, sanitizedEnv } = require('./proc');
const { detectLanguages } = require('./languages');
const { parseSarifToViolations } = require('./sarif');

function defaultQueryPackCandidates() {
  return {
    javascript: [
      'codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls',
      'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
    ],
    python: [
      'codeql/python-queries:codeql-suites/python-code-scanning.qls',
      'codeql/python-queries:codeql-suites/python-security-extended.qls',
    ],
    java: ['codeql/java-queries:codeql-suites/java-security-extended.qls'],
    cpp: [
      'codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls',
      'codeql/cpp-queries:codeql-suites/cpp-security-extended.qls',
    ],
    csharp: ['codeql/csharp-queries:codeql-suites/csharp-security-extended.qls'],
    ruby: ['codeql/ruby-queries:codeql-suites/ruby-security-extended.qls'],
    go: [
      'codeql/go-queries:codeql-suites/go-code-scanning.qls',
      'codeql/go-queries:codeql-suites/go-security-extended.qls',
    ],
    swift: ['codeql/swift-queries:codeql-suites/swift-security-extended.qls'],
  };
}

// Known CodeQL crash signatures where retrying with a fallback pack or
// skipping the language is safer than failing the whole analysis.
function isRecoverableToolFailure(message) {
  return (
    message.includes('SIGSEGV') ||
    message.includes('OutOfMemoryError') ||
    message.includes('NullPointerException') ||
    message.includes('EvaluationSchedule.allocateDfsSeqnums') ||
    message.includes('QueryEvaluator.setPriorityIfNecessary') ||
    /fatal internal error occurred/i.test(message) ||
    message.includes('hs_err_pid') ||
    message.includes('Cannot invoke "com.google.re2j.Machine.init(int)"') ||
    message.includes('OpenJDK Runtime Environment') ||
    message.includes('Aborted')
  );
}

function shouldRetryWithFallback(language, message) {
  return ['python', 'javascript', 'go', 'cpp'].includes(language) && isRecoverableToolFailure(message);
}

function shouldSkipCreateFailure(language, message) {
  if (!['cpp', 'javascript', 'python', 'go'].includes(language)) return false;
  const m = message.toLowerCase();
  return (
    message.includes('No supported build system detected.') ||
    m.includes('no required module provides package') ||
    m.includes('no such file or directory') ||
    m.includes('fatal error:') ||
    m.includes('undefined reference') ||
    m.includes('malformed expansion') ||
    m.includes('unexpected eof while looking for matching') ||
    m.includes('syntax error: unexpected end of file') ||
    isRecoverableToolFailure(message)
  );
}

function shouldSkipAnalyzeFailure(language, message) {
  return ['python', 'javascript', 'go', 'cpp'].includes(language) && isRecoverableToolFailure(message);
}

function writeBuildScript(sourceRoot, fileName, body) {
  const scriptPath = path.join(sourceRoot, fileName);
  fs.writeFileSync(scriptPath, body + '\n', { mode: 0o700 });
  return scriptPath;
}

function detectBuildCommand(language, sourceRoot) {
  if (language === 'python') return '/usr/bin/true';
  if (language === 'javascript') {
    return writeBuildScript(sourceRoot, '.securecoder-codeql-js-build.sh', [
      '#!/bin/sh',
      'find . \\( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" \\) -exec node --check {} \\;',
    ].join('\n'));
  }
  if (language === 'go') {
    return writeBuildScript(sourceRoot, '.securecoder-codeql-go-build.sh', [
      '#!/bin/sh',
      'find . -name "*.go" -exec go build {} \\;',
    ].join('\n'));
  }
  if (language === 'cpp') {
    return writeBuildScript(sourceRoot, '.securecoder-codeql-cpp-build.sh', [
      '#!/bin/sh',
      'find . -name "*.c" -exec clang -std=c11 -c {} -o /tmp/codeql-snippet-c.o \\;',
      'find . \\( -name "*.cc" -o -name "*.cpp" -o -name "*.cxx" \\) -exec clang++ -std=c++17 -c {} -o /tmp/codeql-snippet-cpp.o \\;',
    ].join('\n'));
  }
  if (language !== 'java') return null;
  const has = (f) => fs.existsSync(path.join(sourceRoot, f));
  if (has('build.gradle.kts') || has('build.gradle')) {
    return './gradlew --no-daemon -q clean build || gradle --no-daemon -q clean build';
  }
  if (has('pom.xml')) return 'mvn -q -DskipTests package';
  return 'find . -name "*.java" -exec javac {} +';
}

class CodeQLRunner {
  constructor(binary = 'codeql', { threads = 1, ramMb = 2048, timeoutMs = 600000 } = {}) {
    this.binary = binary;
    this.threads = String(threads);
    this.ramMb = String(ramMb);
    this.timeoutMs = timeoutMs;
  }

  async exec(args, cwd) {
    const { code, output, timedOut } = await run(args, {
      cwd,
      env: sanitizedEnv(this.ramMb),
      timeoutMs: this.timeoutMs,
    });
    if (timedOut) {
      throw new Error(`Command timed out after ${this.timeoutMs}ms (${args.join(' ')})`);
    }
    if (code !== 0) {
      throw new Error(`Command failed (${args.join(' ')}) with exit code ${code}. Output:\n${output}`);
    }
    return output;
  }

  async createDatabase(language, sourceRoot, dbDir, buildCommand) {
    const args = [
      this.binary, 'database', 'create', dbDir,
      `--language=${language}`,
      '--source-root', sourceRoot,
      `--threads=${this.threads}`,
      `--ram=${this.ramMb}`,
    ];
    if (buildCommand) args.push(`--command=${buildCommand}`);
    return this.exec(args, sourceRoot);
  }

  async analyzeDatabase(dbDir, queryPack, outSarif) {
    return this.exec([
      this.binary, 'database', 'analyze', dbDir, queryPack,
      '--format=sarifv2.1.0',
      '--output', outSarif,
      `--threads=${this.threads}`,
      `--ram=${this.ramMb}`,
    ], dbDir);
  }

  async getToolVersion() {
    const output = await this.exec([this.binary, '--version'], null);
    const firstLine = (output.split('\n')[0] || '').trim();
    const match = firstLine.match(/\b\d+(?:\.\d+)+\b/);
    if (!match) throw new Error(`Unable to parse CodeQL version from: '${firstLine}'`);
    return match[0];
  }
}

async function analyzeWithFallback({ runner, language, dbDir, queryPacks, outSarif, log }) {
  let lastFailure = null;
  for (let i = 0; i < queryPacks.length; i++) {
    try {
      await runner.analyzeDatabase(dbDir, queryPacks[i], outSarif);
      return true;
    } catch (e) {
      lastFailure = e;
      const msg = e.message || '';
      if (i + 1 < queryPacks.length && shouldRetryWithFallback(language, msg)) {
        log(`Retrying CodeQL for ${language} with fallback pack after failure: ${msg.slice(0, 200)}`);
        continue;
      }
      if (shouldSkipAnalyzeFailure(language, msg)) {
        log(`Skipping CodeQL for ${language} after analyze failure: ${msg.slice(0, 200)}`);
        return false;
      }
      throw e;
    }
  }
  if (lastFailure && shouldSkipAnalyzeFailure(language, lastFailure.message || '')) {
    log(`Skipping CodeQL for ${language} after repeated analyze failures`);
    return false;
  }
  throw lastFailure || new Error(`CodeQL analyze failed for ${language} without details`);
}

// files: [{ rel, content }] — candidate source files, paths relative to project root.
// Returns Violation[] with location.file mapped back to the given rel paths.
async function runCodeQLGuardian(files, options = {}) {
  const {
    binary = 'codeql',
    enabledLanguages = null,
    queryPackOverrides = {},
    threads = 1,
    ramMb = 2048,
    timeoutMs = 600000,
    log = () => {},
  } = options;

  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codeql-guardian-'));
  const sourceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codeql-src-'));
  try {
    for (const file of files) {
      const target = path.join(sourceRoot, file.rel);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, file.content);
    }

    const packCandidates = { ...defaultQueryPackCandidates() };
    for (const [language, packs] of Object.entries(queryPackOverrides)) {
      packCandidates[language] = [...packs, ...(packCandidates[language] || [])]
        .filter((p, i, arr) => arr.indexOf(p) === i);
    }

    const languages = [...detectLanguages(files.map((f) => f.rel))]
      .filter((l) => !enabledLanguages || enabledLanguages.includes(l));
    log(`CodeQL: detected languages [${languages.join(', ')}] for ${files.length} file(s)`);

    const runner = new CodeQLRunner(binary, { threads, ramMb, timeoutMs });
    const sarifPaths = [];
    for (const language of languages) {
      const queryPacks = packCandidates[language] || [];
      if (queryPacks.length === 0) continue;
      const dbDir = path.join(workRoot, `db-${language}`);
      const outSarif = path.join(workRoot, `results-${language}.sarif`);
      const buildCmd = detectBuildCommand(language, sourceRoot);

      try {
        await runner.createDatabase(language, sourceRoot, dbDir, buildCmd);
      } catch (e) {
        if (shouldSkipCreateFailure(language, e.message || '')) {
          log(`Skipping CodeQL for ${language} after database create failure: ${(e.message || '').slice(0, 200)}`);
          continue;
        }
        throw e;
      }

      const analyzed = await analyzeWithFallback({ runner, language, dbDir, queryPacks, outSarif, log });
      if (analyzed && fs.existsSync(outSarif)) sarifPaths.push(outSarif);
    }

    const relSet = new Set(files.map((f) => f.rel));
    const violations = [];
    for (const sarifPath of sarifPaths) {
      const text = fs.readFileSync(sarifPath, 'utf8');
      for (const v of parseSarifToViolations(text, 'codeql')) {
        // SARIF URIs are relative to the temp source root; map back if possible.
        const uri = v.location.file.replace(/^\.\//, '');
        v.location.file = relSet.has(uri) ? uri : uri;
        violations.push(v);
      }
    }
    return violations;
  } finally {
    fs.rmSync(sourceRoot, { recursive: true, force: true });
    fs.rmSync(workRoot, { recursive: true, force: true });
  }
}

module.exports = { runCodeQLGuardian, CodeQLRunner, defaultQueryPackCandidates, detectBuildCommand };
