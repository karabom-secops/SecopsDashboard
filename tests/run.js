'use strict';

/**
 * tests/run.js — the test runner.
 *
 * WHY THIS EXISTS
 *
 * Until now this repo had no tests directory and no test script. Every suite
 * written for it lived in a temporary scratchpad and was lost when the session
 * ended. For a codebase whose worst failure mode is showing one client another
 * client's data, that is not a defensible place to keep the checks.
 *
 * Each *.test.js file is a plain Node script run as its own child process, so a
 * crash or a stray process.exit in one suite cannot take the run with it, and
 * each gets a clean module registry. Every suite receives the repo root as
 * argv[2].
 *
 *   npm test                  run everything
 *   npm test portal           run suites whose name contains "portal"
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const filter = process.argv[2] || '';

function discover(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'helpers' || entry.name === 'fixtures') continue;
      out.push(...discover(full));
    } else if (entry.name.endsWith('.test.js')) {
      out.push(full);
    }
  }
  return out.sort();
}

const files = discover(__dirname)
  .filter(f => !filter || path.basename(f).includes(filter));

if (!files.length) {
  console.error(filter ? 'No suites match "' + filter + '".' : 'No suites found.');
  process.exit(1);
}

const results = [];
for (const file of files) {
  const name = path.relative(__dirname, file).replace(/\\/g, '/');
  const started = Date.now();
  const run = spawnSync(process.execPath, [file, ROOT], {
    encoding: 'utf8',
    // Suites must not inherit a half-configured environment; they are pure
    // logic and browser-free by design.
    env: Object.assign({}, process.env, { NODE_ENV: 'test' }),
  });
  const ms = Date.now() - started;
  const ok = run.status === 0;
  results.push({ name, ok, ms, out: (run.stdout || '') + (run.stderr || '') });

  // Only failing suites print their body. A green run should be readable at a
  // glance; a red one should show everything without a second command.
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name.padEnd(40) + ms + 'ms');
  if (!ok) console.log(results[results.length - 1].out.replace(/^/gm, '      '));
}

const failed = results.filter(r => !r.ok);
console.log('\n' + (results.length - failed.length) + '/' + results.length + ' suites passed');
if (failed.length) {
  console.log('failed: ' + failed.map(f => f.name).join(', '));
}
process.exit(failed.length ? 1 : 0);
