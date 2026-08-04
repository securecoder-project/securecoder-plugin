// Port of guardian/codeql SarifParser.kt — SARIF 2.1.0 → Violation[].
// Extends the original by resolving rule metadata (precision, level, CWE)
// from run.tool.driver.rules, where CodeQL actually stores it.

'use strict';

// Violation shape (mirrors guardian/api Models.kt):
// { rule: {id, name?, cwe?, owasp?}, message, location: {file, startLine?, endLine?},
//   hardReject?, confidence?, raw?, analyzer }

function collectRules(run) {
  const byId = new Map();
  const drivers = [];
  if (run.tool && run.tool.driver) drivers.push(run.tool.driver);
  for (const ext of (run.tool && run.tool.extensions) || []) drivers.push(ext);
  for (const driver of drivers) {
    for (const rule of driver.rules || []) {
      if (rule && rule.id) byId.set(rule.id, rule);
    }
  }
  return byId;
}

function cweFromRule(rule) {
  const tags = (rule && rule.properties && rule.properties.tags) || [];
  for (const tag of tags) {
    const m = String(tag).match(/cwe\/cwe-(\d+)/i);
    if (m) return `CWE-${parseInt(m[1], 10)}`;
  }
  return null;
}

function parseSarifToViolations(text, analyzer = 'codeql') {
  let root;
  try {
    root = JSON.parse(text);
  } catch {
    return [];
  }
  if (!root || typeof root !== 'object' || !Array.isArray(root.runs)) return [];
  const out = [];
  for (const run of root.runs) {
    const rules = collectRules(run);
    const results = Array.isArray(run.results) ? run.results : [];
    for (const res of results) out.push(mapResultToViolation(res, rules, analyzer));
  }
  return out;
}

function mapResultToViolation(res, rules, analyzer) {
  const ruleId = res.ruleId || 'unknown';
  const rule = rules.get(ruleId) || null;
  const message = (res.message && res.message.text) || 'CodeQL issue';

  const firstLoc = Array.isArray(res.locations) ? res.locations[0] : null;
  const phys = firstLoc && firstLoc.physicalLocation;
  const artifact = phys && phys.artifactLocation;
  const region = phys && phys.region;

  const filePath = (artifact && (artifact.uri || artifact.uriBaseId)) || '<unknown>';
  const startLine = region && typeof region.startLine === 'number' ? region.startLine : null;
  const endLine = (region && typeof region.endLine === 'number' ? region.endLine : null) || startLine;

  const ruleProps = (rule && rule.properties) || {};
  const precision = (res.properties && res.properties.precision) || ruleProps.precision;
  const level = res.level ||
    (rule && rule.defaultConfiguration && rule.defaultConfiguration.level) || null;
  const securitySeverity = parseFloat(ruleProps['security-severity']);
  let confidence = precision || level;
  if (!Number.isNaN(securitySeverity)) {
    // GitHub code-scanning thresholds: >=9 critical, >=7 high, >=4 medium.
    confidence = securitySeverity >= 7 ? 'high' : securitySeverity >= 4 ? 'medium' : (confidence || 'low');
  }

  return {
    rule: {
      id: ruleId,
      name: (rule && rule.name) || null,
      cwe: cweFromRule(rule),
    },
    message,
    location: { file: filePath, startLine, endLine },
    hardReject: false,
    confidence: confidence || null,
    raw: JSON.stringify(res),
    analyzer,
  };
}

module.exports = { parseSarifToViolations };
