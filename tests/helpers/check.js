'use strict';

/**
 * tests/helpers/check.js — the whole assertion library.
 *
 * Deliberately tiny. The suites in this directory are plain Node scripts run by
 * tests/run.js; there is no framework, no globals, and nothing to learn beyond
 * check(name, condition, detail).
 *
 * `detail` is printed on both pass and fail, and it matters more than it looks:
 * a passing assertion that prints the value it checked is how you notice the
 * check was vacuous — comparing undefined to undefined, or asserting something
 * that could never have been false.
 */

function createChecker(title) {
  let passed = 0;
  let failed = 0;

  function check(name, condition, detail) {
    const ok = !!condition;
    ok ? passed++ : failed++;
    const line = (ok ? 'PASS  ' : 'FAIL  ') + name +
      (detail !== undefined ? '  [' + detail + ']' : '');
    console.log(line);
    return ok;
  }

  function section(name) {
    console.log('\n-- ' + name + ' --');
  }

  function done() {
    console.log(
      failed
        ? '\n' + failed + ' of ' + (passed + failed) + ' CHECKS FAILED in ' + title
        : '\nALL ' + passed + ' CHECKS PASSED in ' + title
    );
    process.exit(failed ? 1 : 0);
  }

  return { check, section, done, counts: () => ({ passed, failed }) };
}

module.exports = { createChecker };
