'use strict';

/**
 * The phishing click signal.
 *
 * THE BUG THIS SUITE EXISTS FOR
 *
 * The Awareness tab reported a 99% phishing click rate for a client whose real
 * rate was nothing like it. The cause was one line: the parser fed the Clicked
 * column straight to `new Date()`, and `new Date()` accepts a bare integer as a
 * YEAR. An export whose Clicked column holds 0/1 flags therefore produced a
 * valid timestamp for every single row — including, with perfect irony, the
 * rows whose flag said 0, which became the year 2000.
 *
 * Every consumer read a click as `!!clicked_at`, so essentially everyone
 * counted as a clicker. The same number was going onto the board report slide.
 *
 * The checks below drive the real parser over both column shapes.
 *
 *   node tests/awareness-parser.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('awareness-parser');
const { parseSessionHistoryCSV } = require(path.join(ROOT, 'lib', 'awareness-parser.js'));

/** Build a history CSV with a chosen name and set of values for the click column. */
function csv(clickHeader, clickValues) {
  const head = 'User First Name,User Last Name,User Email,Sent Date (UTC),Type,' +
               'Title,Status,Completed Date (UTC),Elapsed Seconds,' + clickHeader +
               ',Quiz Score';
  const rows = clickValues.map((v, i) =>
    `First${i},Last${i},user${i}@example.com,2026-03-01 08:00,Phishing Simulation,` +
    `Q1 Sim,Complete,2026-03-01 08:05,60,${v},`);
  return [head].concat(rows).join('\n');
}

const rate = (parsed) => {
  const known = parsed.rows.filter(r => r.clicked !== null);
  return known.length ? Math.round(
    known.filter(r => r.clicked === true).length / known.length * 100) : null;
};

section('a 0/1 flag column is read as a flag, not as a year');

// This is the exact shape that produced 99%.
const flags = parseSessionHistoryCSV(csv('Clicked', ['0', '0', '0', '0', '1']));
check('five rows parsed', flags.rows.length === 5, flags.rows.length);
check('the column is recognised as a flag', flags.stats.clickSource === 'flag',
  flags.stats.clickSource);
check('a 0 is NOT a click', flags.rows[0].clicked === false, flags.rows[0].clicked);
check('and gets no timestamp', flags.rows[0].clickedAt === null, flags.rows[0].clickedAt);
check('a 1 IS a click', flags.rows[4].clicked === true, flags.rows[4].clicked);
// The honest answer: we know they clicked, we do not know when.
check('but a flag still cannot date the click', flags.rows[4].clickedAt === null,
  flags.rows[4].clickedAt);
check('the rate is 20%, not 99%', rate(flags) === 20, rate(flags));

section('yes/no and true/false spellings are read the same way');
const words = parseSessionHistoryCSV(csv('Clicked Link', ['No', 'no', 'FALSE', 'Yes', 'TRUE']));
check('No / false are non-clicks',
  [0, 1, 2].every(i => words.rows[i].clicked === false));
check('Yes / true are clicks', [3, 4].every(i => words.rows[i].clicked === true));
check('the rate is 40%', rate(words) === 40, rate(words));

section('a real timestamp column still works, and still dates the click');
const stamps = parseSessionHistoryCSV(
  csv('Clicked (UTC)', ['', '', '2026-03-01 08:30', '', 'N/A']));
check('the column is recognised as a timestamp', stamps.stats.clickSource === 'timestamp',
  stamps.stats.clickSource);
check('a dated row is a click', stamps.rows[2].clicked === true);
check('and keeps its time', /^2026-03-01T/.test(stamps.rows[2].clickedAt || ''),
  stamps.rows[2].clickedAt);
// An empty cell in a timestamp column is the ordinary way of saying "no click".
check('an empty cell is a non-click, not an unknown', stamps.rows[0].clicked === false,
  stamps.rows[0].clicked);
check('N/A is a non-click too', stamps.rows[4].clicked === false, stamps.rows[4].clicked);
check('the rate is 20%', rate(stamps) === 20, rate(stamps));

section('"we were not told" never reads as "they did not click"');

const noColumn = parseSessionHistoryCSV(
  'User Email,Sent Date (UTC),Type,Status\n' +
  'a@example.com,2026-03-01 08:00,Phishing Simulation,Complete');
check('an export with no click column reports none',
  noColumn.stats.clickSource === 'absent', noColumn.stats.clickSource);
check('and its rows are unknown, not clean', noColumn.rows[0].clicked === null,
  noColumn.rows[0].clicked);
check('so there is no rate to show at all', rate(noColumn) === null, rate(noColumn));

// A value that is neither a date nor a recognised flag.
const junk = parseSessionHistoryCSV(csv('Clicked', ['maybe', '1']));
check('an unreadable value is unknown', junk.rows[0].clicked === null, junk.rows[0].clicked);
check('and is counted as such', junk.stats.clickUnknown === 1, junk.stats.clickUnknown);
check('while the readable row still counts', rate(junk) === 100, rate(junk));

section('the year-from-an-integer trap is closed for every date field');

// Sent and Completed run through the same parser and had the same exposure.
const nums = parseSessionHistoryCSV(
  'User Email,Sent Date (UTC),Type,Status,Completed Date (UTC),Clicked (UTC)\n' +
  'a@example.com,2026-03-01 08:00,Phishing Simulation,Complete,0,2');
check('a bare 0 does not become the year 2000',
  nums.rows[0].completedDate === null, nums.rows[0].completedDate);
check('a bare 2 does not become the year 2001',
  nums.rows[0].clickedAt === null, nums.rows[0].clickedAt);
// A spreadsheet serial would otherwise land in the year 45352.
const serial = parseSessionHistoryCSV(csv('Clicked (UTC)', ['45352']));
check('a spreadsheet serial is refused rather than read as a year',
  serial.rows[0].clickedAt === null, serial.rows[0].clickedAt);

section('every consumer reads the fact, not the timestamp');

const tabJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-awareness.js'), 'utf8');
const repJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8');

for (const [name, src] of [['tab-awareness.js', tabJs], ['report-sections.js', repJs]]) {
  check(name + ' has a tri-state clickState()',
    /function clickState\(s\)[\s\S]{0,320}return null;/.test(src));
  check(name + ' no longer counts a click as !!clicked_at',
    !/!!s\.clicked_at/.test(src) && !/\.filter\(function \(s\) \{ return s\.clicked_at; \}\)/.test(src));
}

section('the click rate means what the vendor means by it');

/*
 * THE REAL CAUSE OF THE 99%.
 *
 * Reflex divided unique people who ever clicked by unique people ever sent a
 * simulation. Arctic Wolf divides click events by simulations sent. On the
 * client's live data — 2,182 simulations over 241 people, ~436 clicks — those
 * are 99% and 20% respectively, and BOTH are arithmetically correct. Across
 * roughly nine simulations each, nearly everyone clicks something eventually.
 *
 * The two numbers were shown under the same name, so the dashboard appeared to
 * contradict the vendor console the client also has open. Verified in a real
 * browser against a fixture built to those figures: the card prints 20%, and
 * reverting this one division prints exactly 99%.
 *
 * The cross-check that proves the ingest was never at fault: sessions sent and
 * training completion match the console exactly (4,579 and 78%).
 */
check('the headline divides clicks by SIMULATIONS, as the vendor does',
  /phishClickRate\s*=\s*knownSims\.length > 0\s*\?\s*Math\.round\(clickedSims \/ knownSims\.length \* 100\)/.test(tabJs));
check('and says so in the sub-line, so the unit is never ambiguous',
  /simulations clicked/.test(tabJs));
check('the per-person figure survives under its own name',
  /Staff Who Have Clicked/.test(tabJs));
check('and is the one that divides people by people',
  /clickedPhishEmails\.size \/ sentPhishEmails\.size/.test(tabJs));
check('labelled with the question it answers',
  /clicked at least one, ever/.test(tabJs));

// The board report must not disagree with the console either.
check('the report divides clicks by measured simulations',
  /clickPct:\s*known\.length \? completionPct\(clicked, known\.length\)/.test(repJs));
check('and keeps the per-person view separately named',
  /staffClickedPct/.test(repJs));

// The denominator is the half people forget.
check('the tab excludes unknown rows from the denominator',
  /knownSims = phishingSims\.filter/.test(tabJs));
check('and shows "Not reported" rather than a reassuring zero',
  /Not reported/.test(tabJs) && /phishClickRate === null/.test(tabJs));
check('the board report excludes them too',
  /known\s*=\s*sims\.filter\(function \(s\) \{ return clickState\(s\) !== null; \}\)/.test(repJs));
check('and a campaign with nothing measured is dropped, not shown as 0%',
  /filter\(function \(c\) \{ return c\.sent > 0; \}\)/.test(repJs));

section('the migration does not launder the old bug into confident data');

const mig = fs.readFileSync(path.join(ROOT, 'db', 'migrate-awareness-clicked.sql'), 'utf8');
check('clicked is nullable — NULL means "not reported"',
  /ADD COLUMN IF NOT EXISTS clicked BOOLEAN;/.test(mig));
check('it is NOT given a default', !/clicked BOOLEAN[^;]*DEFAULT/.test(mig));
// A fabricated year-2000 timestamp precedes every real send, which is what
// separates it from a genuine click without inventing a cutoff date.
check('the backfill trusts a timestamp only when it follows the send',
  /clicked_at >= sent_date/.test(mig));
check('and leaves everything else NULL rather than FALSE',
  !/SET clicked = FALSE/.test(mig));

done();
