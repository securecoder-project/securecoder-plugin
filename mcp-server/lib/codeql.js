// CodeQL deep analyzer. Port of guardian/codeql CodeQLGuardian.kt + CodeQLRunner.kt.
// Writes the files under analysis to a temp source root, builds one CodeQL
// database per detected language, runs that language's query suite, and parses
// the SARIF.
//
// There is deliberately no crash recovery here. Any CodeQL subprocess failure
// (non-zero exit, timeout, binary that cannot spawn) throws out of
// runCodeQLGuardian and is contained by the per-analyzer isolation in
// analyze.js: the other analyzers still report and the failure is listed in the
// result. The one exception is a project CodeQL cannot build (see
// isUnbuildableProject), which is an expected outcome rather than a fault.

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { run, sanitizedEnv } = require('./proc');
const { detectLanguages } = require('./languages');
const { parseSarifToViolations } = require('./sarif');

// The one query suite run for each language. A language without an entry is
// not analyzed.
const QUERY_PACKS = {
  javascript: 'codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls',
  python: 'codeql/python-queries:codeql-suites/python-code-scanning.qls',
  java: 'codeql/java-queries:codeql-suites/java-security-extended.qls',
  cpp: 'codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls',
  csharp: 'codeql/csharp-queries:codeql-suites/csharp-security-extended.qls',
  ruby: 'codeql/ruby-queries:codeql-suites/ruby-security-extended.qls',
  go: 'codeql/go-queries:codeql-suites/go-code-scanning.qls',
  swift: 'codeql/swift-queries:codeql-suites/swift-security-extended.qls',
};

// Resource limits are fixed rather than settings: choosing better values takes
// a reading of CodeQL's own documentation, and these suit a handful of files.
const THREADS = 1;
const RAM_MB = 2048;
const DEFAULT_TIMEOUT_MS = 600000;

// True when `codeql database create` failed because the project cannot be
// built: no build system for the autobuilder to drive, or a Go file importing
// a module that no go.mod provides. That is common for a few loose files and
// says nothing about CodeQL's health, so the language is skipped instead of
// being reported as an analyzer failure.
function isUnbuildableProject(message) {
  return (
    message.includes('No supported build system detected.') ||
    message.toLowerCase().includes('no required module provides package')
  );
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
  constructor(binary = 'codeql', { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.binary = binary;
    this.timeoutMs = timeoutMs;
  }

  async exec(args, cwd) {
    const { code, output, timedOut } = await run(args, {
      cwd,
      env: sanitizedEnv(RAM_MB),
      timeoutMs: this.timeoutMs,
    });
    if (timedOut) {
      throw new Error(`Command timed out after ${this.timeoutMs}ms (${args.join(' ')})`);
    }
    if (code !== 0) {
      // Failures are shown by their first line, so the cause goes there and
      // the long command line after it.
      const cause = output.split('\n').map((l) => l.trim()).find(Boolean) || 'no output';
      throw new Error(`codeql ${args.slice(1, 3).join(' ')} failed with exit code ${code}: ${cause.slice(0, 300)}\nCommand: ${args.join(' ')}\nOutput:\n${output}`);
    }
    return output;
  }

  async createDatabase(language, sourceRoot, dbDir, buildCommand) {
    const args = [
      this.binary, 'database', 'create', dbDir,
      `--language=${language}`,
      '--source-root', sourceRoot,
      `--threads=${THREADS}`,
      `--ram=${RAM_MB}`,
    ];
    if (buildCommand) args.push(`--command=${buildCommand}`);
    return this.exec(args, sourceRoot);
  }

  async analyzeDatabase(dbDir, queryPack, outSarif) {
    return this.exec([
      this.binary, 'database', 'analyze', dbDir, queryPack,
      '--format=sarifv2.1.0',
      '--output', outSarif,
      `--threads=${THREADS}`,
      `--ram=${RAM_MB}`,
    ], dbDir);
  }
}

// files: [{ rel, content }] — candidate source files, paths relative to project root.
// Returns Violation[] with location.file mapped back to the given rel paths.
async function runCodeQLGuardian(files, options = {}) {
  const { binary = 'codeql', timeoutMs = DEFAULT_TIMEOUT_MS, log = () => {} } = options;

  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codeql-guardian-'));
  const sourceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'codeql-src-'));
  try {
    for (const file of files) {
      const target = path.join(sourceRoot, file.rel);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, file.content);
    }

    const languages = [...detectLanguages(files.map((f) => f.rel))];
    log(`CodeQL: detected languages [${languages.join(', ')}] for ${files.length} file(s)`);

    const runner = new CodeQLRunner(binary, { timeoutMs });
    const sarifPaths = [];
    for (const language of languages) {
      const queryPack = QUERY_PACKS[language];
      if (!queryPack) continue;
      const dbDir = path.join(workRoot, `db-${language}`);
      const outSarif = path.join(workRoot, `results-${language}.sarif`);
      const buildCmd = detectBuildCommand(language, sourceRoot);

      try {
        await runner.createDatabase(language, sourceRoot, dbDir, buildCmd);
      } catch (e) {
        if (!isUnbuildableProject(e.message || '')) throw e;
        log(`Skipping CodeQL for ${language}: the project cannot be built`);
        continue;
      }

      await runner.analyzeDatabase(dbDir, queryPack, outSarif);
      if (fs.existsSync(outSarif)) sarifPaths.push(outSarif);
    }

    const violations = [];
    for (const sarifPath of sarifPaths) {
      const text = fs.readFileSync(sarifPath, 'utf8');
      for (const v of parseSarifToViolations(text, 'codeql')) {
        // SARIF URIs are relative to the temp source root, which mirrors the
        // rel paths the files came in with.
        v.location.file = v.location.file.replace(/^\.\//, '');
        violations.push(v);
      }
    }
    return violations;
  } finally {
    fs.rmSync(sourceRoot, { recursive: true, force: true });
    fs.rmSync(workRoot, { recursive: true, force: true });
  }
}

module.exports = { runCodeQLGuardian, CodeQLRunner, QUERY_PACKS, isUnbuildableProject, detectBuildCommand };
