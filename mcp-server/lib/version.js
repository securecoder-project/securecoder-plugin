// Single source of truth for the plugin version: the root package.json.
// scripts/check-manifests.js keeps every harness manifest in sync with it.

'use strict';

const path = require('path');

const PLUGIN_ROOT = path.resolve(__dirname, '..', '..');

let version = '0.0.0';
try {
  version = require(path.join(PLUGIN_ROOT, 'package.json')).version || version;
} catch {
  // A trimmed install without package.json still runs; it just reports 0.0.0.
}

module.exports = { VERSION: version, PLUGIN_ROOT };
