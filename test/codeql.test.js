'use strict';

// The CodeQL guardian against a stub `codeql` executable: a shell script that
// records how it was called and then behaves as each test asks. No real CodeQL
// is involved, so the suite stays fast and needs nothing installed.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { analyze } = require('../mcp-server/lib/analyze');
const { runCodeQLGuardian, QUERY_PACKS, isUnbuildableProject } = require('../mcp-server/lib/codeql');
const { loadConfig } = require('../mcp-server/lib/config');
const { ROOT, cleanEnv, makeProject, runNode } = require('./helpers');

const CLI = path.join(ROOT, 'bin', 'securecoder');
const NO_STUB = process.platform === 'win32' && 'a #!/bin/sh stub cannot be spawned on Windows';
const SYNTAX_ONLY = { analyzers: ['syntax'] };
const BROKEN_JS = 'function (\n';
const CLEAN_JS = 'const x = 1;\n';

const SARIF = {
  version: '2.1.0',
  runs: [{
    tool: {
      driver: {
        name: 'CodeQL',
        rules: [{
          id: 'js/code-injection',
          name: 'CodeInjection',
          properties: { tags: ['security', 'external/cwe/cwe-094'], precision: 'high', 'security-severity': '9.3' },
        }],
      },
    },
    results: [{
      ruleId: 'js/code-injection',
      message: { text: 'This code execution depends on a user-provided value.' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'src/app.js', uriBaseId: '%SRCROOT%' }, region: { startLine: 2 } } }],
    }],
  }],
};

// Writes an executable `codeql` whose `database create` and `database analyze`
// steps run the given shell snippets (default: succeed and do nothing more).
// Create always makes the database directory, as the analyze step runs inside
// it. With `sarif`, analyze writes that document to its --output path.
// Every call appends its arguments to a log, one line per call, and leaves the
// JVM options it was given in a second file.
function makeStub({ create = ':', analyze: analyzeStep = ':', sarif = null } = {}) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-codeql-stub-')));
  const binary = path.join(dir, 'codeql');
  const argvLog = path.join(dir, 'argv.log');
  const javaArgs = path.join(dir, 'java-args');
  if (sarif) {
    fs.writeFileSync(path.join(dir, 'results.sarif'), JSON.stringify(sarif));
    analyzeStep = [
      'prev=',
      '    for arg in "$@"; do',
      `      if [ "$prev" = "--output" ]; then cp '${path.join(dir, 'results.sarif')}' "$arg"; fi`,
      '      prev=$arg',
      '    done',
    ].join('\n');
  }
  fs.writeFileSync(binary, [
    '#!/bin/sh',
    `printf '%s\\037' "$@" >> '${argvLog}'`,
    `printf '\\n' >> '${argvLog}'`,
    `printf '%s' "$CODEQL_JAVA_ARGS" > '${javaArgs}'`,
    'case "$1 $2" in',
    '  "database create")',
    '    mkdir -p "$3"',
    `    ${create}`,
    '    ;;',
    '  "database analyze")',
    `    ${analyzeStep}`,
    '    ;;',
    'esac',
    'exit 0',
    '',
  ].join('\n'));
  fs.chmodSync(binary, 0o755);
  const calls = () => (fs.existsSync(argvLog) ? fs.readFileSync(argvLog, 'utf8') : '')
    .split('\n').filter(Boolean).map((line) => line.split('\x1f').slice(0, -1));
  return {
    binary,
    calls,
    steps: () => calls().map((argv) => argv.slice(0, 2).join(' ')),
    javaArgs: () => fs.readFileSync(javaArgs, 'utf8'),
  };
}

// Effective config that runs the stub as CodeQL and this node as the syntax checker.
function stubEnv(stub) {
  return cleanEnv({ CODEQL_BIN: stub.binary, NODE_BIN: process.execPath });
}

function deepScan(root, stub, filePaths, extra = {}) {
  const log = [];
  return analyze({
    filePaths,
    projectRoot: root,
    analyzers: ['syntax'],
    includeDeep: true,
    config: loadConfig(root, { env: stubEnv(stub) }),
    log: (m) => log.push(m),
    ...extra,
  }).then((result) => ({ ...result, log }));
}

const flagValue = (argv, flag) => argv[argv.indexOf(flag) + 1];

test('one query suite per language, and only a project that cannot be built is skipped', () => {
  assert.deepEqual(QUERY_PACKS, {
    javascript: 'codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls',
    python: 'codeql/python-queries:codeql-suites/python-code-scanning.qls',
    java: 'codeql/java-queries:codeql-suites/java-security-extended.qls',
    cpp: 'codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls',
    csharp: 'codeql/csharp-queries:codeql-suites/csharp-security-extended.qls',
    ruby: 'codeql/ruby-queries:codeql-suites/ruby-security-extended.qls',
    go: 'codeql/go-queries:codeql-suites/go-code-scanning.qls',
    swift: 'codeql/swift-queries:codeql-suites/swift-security-extended.qls',
  });

  assert.equal(isUnbuildableProject('[build-stdout] No supported build system detected.'), true);
  assert.equal(isUnbuildableProject("main.go:3:8: No Required Module Provides Package github.com/x/y; see 'go help modules'"), true);
  // Crashes, and build errors that are about the code rather than the project.
  for (const message of [
    'SIGSEGV (0xb) at pc=0x0000',
    'java.lang.OutOfMemoryError: Java heap space',
    'An error report file with more information is saved as: hs_err_pid4242.log',
    'Oops! A fatal internal error occurred.',
    'app.c:1:10: fatal error: missing.h: No such file or directory',
    'undefined reference to `main\'',
    'Command timed out after 600000ms',
    '',
  ]) assert.equal(isUnbuildableProject(message), false, message);
});

test('a failing database create leaves the other analyzers reporting and is listed as a failure', { skip: NO_STUB }, async () => {
  // The 0.2.0 crash recovery matched "fatal internal error occurred" and
  // "hs_err_pid" and skipped the language without a trace.
  const stub = makeStub({ create: 'echo "Oops! A fatal internal error occurred. See hs_err_pid4242.log"; exit 3' });
  const root = makeProject({ files: { 'broken.js': BROKEN_JS, 'ok.js': CLEAN_JS }, config: SYNTAX_ONLY });

  const result = await deepScan(root, stub, ['broken.js']);
  assert.deepEqual(result.analyzersRun, ['syntax', 'codeql']);
  assert.deepEqual(result.violations.map((v) => [v.analyzer, v.rule.id, v.location.file, v.hardReject]), [['syntax', 'javascript-syntax', 'broken.js', true]]);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].guardian, 'codeql');
  // The cause is on the first line, which is all the reports show of a failure.
  assert.match(result.failures[0].message, /^codeql database create failed with exit code 3: Oops! A fatal internal error occurred\. See hs_err_pid4242\.log\nCommand: .* database create .*\nOutput:\n/);
  assert.deepEqual(stub.steps(), ['database create']);
  // The temp copy of the sources is removed on the failure path too.
  assert.equal(fs.existsSync(flagValue(stub.calls()[0], '--source-root')), false);

  // The same through the CLI: the scan is clean, says what failed, and exits 0.
  const cli = runNode(CLI, ['scan', '--deep', 'ok.js'], { env: stubEnv(stub), cwd: root });
  assert.equal(cli.status, 0, cli.stderr);
  assert.match(cli.stdout, /^Analyzers run: syntax, codeql\nCLEAN: no findings at or above LOW\.\n\(Analyzer codeql failed: codeql database create failed with exit code 3: Oops! A fatal internal error occurred\. See hs_err_pid4242\.log\)\n$/);
  const json = JSON.parse(runNode(CLI, ['scan', '--deep', '--json', 'ok.js'], { env: stubEnv(stub), cwd: root }).stdout);
  assert.deepEqual(json.failures.map((f) => f.guardian), ['codeql']);
  assert.equal(fs.existsSync(path.join(root, '.securecoder')), false);
});

test('a failing database analyze is a failure too, with no second attempt on another suite', { skip: NO_STUB }, async () => {
  // 0.2.0 retried JavaScript on a fallback suite after a SIGSEGV and, when
  // that failed as well, skipped the language as if nothing had happened.
  const stub = makeStub({ analyze: 'echo "# A fatal error has been detected by the Java Runtime Environment: SIGSEGV (0xb)"; exit 134' });
  const root = makeProject({ files: { 'ok.js': CLEAN_JS }, config: SYNTAX_ONLY });

  const result = await deepScan(root, stub, ['ok.js']);
  assert.deepEqual(result.analyzersRun, ['syntax', 'codeql']);
  assert.deepEqual(result.violations, []);
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].guardian, 'codeql');
  assert.match(result.failures[0].message, /^codeql database analyze failed with exit code 134: # A fatal error has been detected by the Java Runtime Environment: SIGSEGV \(0xb\)\n/);
  assert.deepEqual(stub.steps(), ['database create', 'database analyze']);
});

test('a project CodeQL cannot build skips that language without a failure', { skip: NO_STUB }, async () => {
  const stub = makeStub({ create: 'echo "[build-stdout] No supported build system detected."; exit 1' });
  const root = makeProject({ files: { 'ok.js': CLEAN_JS }, config: SYNTAX_ONLY });

  const result = await deepScan(root, stub, ['ok.js']);
  assert.deepEqual(result.analyzersRun, ['syntax', 'codeql']);
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.violations, []);
  assert.deepEqual(stub.steps(), ['database create']);
  assert.deepEqual(result.log.filter((m) => m.startsWith('Skipping')), ['Skipping CodeQL for javascript: the project cannot be built']);
});

test('a skipped language does not stop the others', { skip: NO_STUB }, async () => {
  const stub = makeStub({
    sarif: SARIF,
    create: 'case "$*" in *--language=go*) echo "main.go:3:8: no required module provides package github.com/x/y"; exit 1 ;; esac',
  });
  const files = [
    { rel: 'main.go', content: 'package main\n\nimport "github.com/x/y"\n\nfunc main() { y.Run() }\n' },
    { rel: 'src/app.js', content: CLEAN_JS },
  ];
  const log = [];
  const violations = await runCodeQLGuardian(files, { binary: stub.binary, log: (m) => log.push(m) });
  assert.deepEqual(violations.map((v) => [v.rule.id, v.location.file]), [['js/code-injection', 'src/app.js']]);
  assert.deepEqual(stub.calls().map((argv) => [argv[1], argv.find((a) => a.startsWith('--language=')) || argv[3]]), [
    ['create', '--language=go'],
    ['create', '--language=javascript'],
    ['analyze', QUERY_PACKS.javascript],
  ]);
  assert.deepEqual(log, ['CodeQL: detected languages [go, javascript] for 2 file(s)', 'Skipping CodeQL for go: the project cannot be built']);
});

test('SARIF results come back as codeql violations on the files that were scanned', { skip: NO_STUB }, async () => {
  const stub = makeStub({ sarif: SARIF });
  const root = makeProject({ files: { 'src/app.js': 'const run = (input) =>\n  input();\n' }, config: SYNTAX_ONLY });

  const result = await deepScan(root, stub, [path.join(root, 'src', 'app.js')]);
  assert.deepEqual(result.failures, []);
  assert.deepEqual(result.analyzersRun, ['syntax', 'codeql']);
  assert.equal(result.violations.length, 1);
  const { raw, ...violation } = result.violations[0];
  assert.deepEqual(violation, {
    rule: { id: 'js/code-injection', name: 'CodeInjection', cwe: 'CWE-94' },
    message: 'This code execution depends on a user-provided value.',
    location: { file: path.join('src', 'app.js'), startLine: 2, endLine: 2 },
    hardReject: false,
    confidence: 'high',
    analyzer: 'codeql',
  });
  assert.equal(JSON.parse(raw).ruleId, 'js/code-injection');
  assert.match(result.feedback, /js\/code-injection/);
});

test('every step gets the fixed resource limits and each language exactly one query suite', { skip: NO_STUB }, async () => {
  const stub = makeStub({ sarif: SARIF });
  const files = [
    { rel: 'app.py', content: 'x = 1\n' },
    { rel: 'src/app.js', content: CLEAN_JS },
    { rel: 'README.md', content: '# no language\n' },
  ];
  const violations = await runCodeQLGuardian(files, { binary: stub.binary });
  assert.equal(violations.length, 2);

  const calls = stub.calls();
  assert.deepEqual(stub.steps(), ['database create', 'database analyze', 'database create', 'database analyze']);
  for (const argv of calls) {
    assert.ok(argv.includes('--threads=1'), argv.join(' '));
    assert.ok(argv.includes('--ram=2048'), argv.join(' '));
  }
  assert.equal(stub.javaArgs(), '-Xmx2048m');

  const [createPy, analyzePy, createJs, analyzeJs] = calls;
  assert.ok(createPy.includes('--language=python') && createJs.includes('--language=javascript'));
  // database analyze <db> <suite> --format=… --output <sarif> --threads=… --ram=…
  assert.equal(analyzePy[2], createPy[2]);
  assert.equal(analyzeJs[2], createJs[2]);
  assert.deepEqual(analyzePy.slice(3, 5), [QUERY_PACKS.python, '--format=sarifv2.1.0']);
  assert.deepEqual(analyzeJs.slice(3, 5), [QUERY_PACKS.javascript, '--format=sarifv2.1.0']);
  assert.equal(calls.flat().filter((arg) => arg.endsWith('.qls')).length, 2);

  // The database, the SARIF and the copied sources are gone afterwards.
  for (const dir of [createPy[2], flagValue(createPy, '--source-root'), path.dirname(flagValue(analyzePy, '--output'))]) {
    assert.equal(fs.existsSync(dir), false, dir);
  }
});

test('a timeout or a binary that cannot spawn fails the analyzer as well', { skip: NO_STUB }, async () => {
  // exec, so the kill reaches the sleeping process and its pipes close.
  const stub = makeStub({ create: 'exec sleep 30' });
  const files = [{ rel: 'ok.js', content: CLEAN_JS }];
  await assert.rejects(runCodeQLGuardian(files, { binary: stub.binary, timeoutMs: 300 }), /^Error: Command timed out after 300ms \(.* database create /);

  await assert.rejects(runCodeQLGuardian(files, { binary: path.join(path.dirname(stub.binary), 'missing') }), /ENOENT/);

  // analyze.js passes codeql.timeout_seconds and codeql.binary through.
  const root = makeProject({ files: { 'ok.js': CLEAN_JS }, config: SYNTAX_ONLY });
  const config = loadConfig(root, { env: stubEnv(stub) });
  assert.equal(config.codeql.timeout_seconds, 600);
  const result = await deepScan(root, stub, ['ok.js'], { config: { ...config, codeql: { ...config.codeql, timeout_seconds: 0.3 } } });
  assert.deepEqual(result.violations, []);
  assert.deepEqual(result.failures.map((f) => f.guardian), ['codeql']);
  assert.match(result.failures[0].message, /^Command timed out after 300ms/);
});
