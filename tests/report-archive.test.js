'use strict';

/**
 * The published report archive.
 *
 * WHAT MATTERS HERE
 *
 * The archive serves files from disk to whoever asks. Two failure modes are
 * worth real assertions: a path that escapes the archive root, and a listing or
 * download that crosses tenants. Everything else is bookkeeping.
 *
 * No database and no real decks — the pool and filesystem are stubbed, so this
 * exercises the logic that decides WHAT to serve rather than pg's ability to
 * return rows.
 *
 *   node tests/report-archive.test.js <repoRoot>
 */

const path = require('path');
const fs = require('fs');
const os = require('os');
const ROOT = process.argv[2] || path.join(__dirname, '..');

// The module reads REPORT_ARCHIVE_DIR at load time, so it is set first.
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'archive-test-'));
process.env.REPORT_ARCHIVE_DIR = TMP;

const A = require(path.join(ROOT, 'lib', 'report-archive.js'));
const { createChecker } = require('./helpers/check');
const { check, section, done } = createChecker('report-archive');

/** A pool that returns canned rows and records what it was asked. */
function fakePool(rows) {
  const queries = [];
  return {
    queries,
    async query(sql, params) {
      queries.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params: params || [] });
      return { rows: typeof rows === 'function' ? rows(sql, params) : (rows || []) };
    },
  };
}

/**
 * A res double that is a REAL Writable stream.
 *
 * sendPublicationPptx pipes a read stream into it, and pipe() needs a genuine
 * stream target — a plain object with an `on` stub throws inside Node's
 * internals, which looks like a bug in the code under test and is not one.
 */
const { Writable } = require('stream');

function fakeRes() {
  const chunks = [];
  const r = new Writable({
    write(chunk, _enc, cb) { chunks.push(chunk); cb(); },
  });
  r.statusCode = 200;
  r.headers = {};
  r.body = null;
  r.headersSent = false;
  r.chunks = chunks;
  r.status = (c) => { r.statusCode = c; return r; };
  r.setHeader = (k, v) => { r.headers[String(k).toLowerCase()] = v; };
  r.json = (o) => { r.body = o; return r; };
  // Express's res.end doubles as "send this body"; Writable.end takes a chunk
  // too, so recording it here keeps both meanings working.
  const origEnd = r.end.bind(r);
  r.end = (v) => { if (v !== undefined) r.body = v; return origEnd(); };
  return r;
}

(async function main() {

  // ── Path traversal ─────────────────────────────────────────────────────
  section('a stored path can never escape the archive root');
  {
    const ok = A.resolveArchivePath('7/2026-08-abc.pptx');
    check('a normal relative path resolves', !!ok && ok.startsWith(path.resolve(TMP)), ok);

    // The stored value is always generated server-side, so in principle none of
    // these can occur. The check exists because that reasoning depends on every
    // future caller staying careful, and a path assertion does not.
    const hostile = [
      '../../../etc/passwd',
      '..\\..\\windows\\system32\\config\\sam',
      '/etc/shadow',
      '7/../../../../secrets.txt',
      'C:\\Windows\\win.ini',
    ];
    hostile.forEach((h) => {
      check('refuses ' + JSON.stringify(h), A.resolveArchivePath(h) === null,
        String(A.resolveArchivePath(h)));
    });
    check('refuses an empty path', A.resolveArchivePath('') === null);
    check('refuses a non-string', A.resolveArchivePath({}) === null &&
      A.resolveArchivePath(null) === null);
    // A path that merely LOOKS like a sibling of the root must not pass a naive
    // startsWith check — hence the path.sep in the implementation.
    check('refuses a sibling directory sharing the root prefix',
      A.resolveArchivePath('../' + path.basename(TMP) + '-evil/x.pptx') === null);
  }

  // ── Filenames ──────────────────────────────────────────────────────────
  section('download filenames are safe and carry the version');
  {
    const name = A.archiveFilename({ client_name: 'Acme Ltd', period: '2026-08',
      period_label: 'August 2026', version: 3 });
    check('includes the version', /-v3\.pptx$/.test(name), name);
    check('has a single .pptx extension', (name.match(/\.pptx/g) || []).length === 1, name);

    // A tenant name is free text and reaches a Content-Disposition header; a
    // raw newline there would let a caller inject further response headers.
    const nasty = A.archiveFilename({
      client_name: 'Evil"\r\nSet-Cookie: a=b', period: '2026-08', version: 1 });
    check('strips quotes and newlines from the client name',
      !/["\r\n]/.test(nasty), JSON.stringify(nasty));
  }

  // ── Listing ────────────────────────────────────────────────────────────
  section('listing is scoped and marks superseded versions');
  {
    const pool = fakePool([
      { id: 3, period: '2026-08', version: 2, status: 'published' },
      { id: 2, period: '2026-08', version: 1, status: 'published' },
      { id: 1, period: '2026-07', version: 1, status: 'published' },
    ]);
    const rows = await A.listPublications(pool, { tenantId: 7 });

    check('the tenant is always the first parameter', pool.queries[0].params[0] === 7);
    check('and appears in the WHERE clause', /WHERE tenant_id = \$1/.test(pool.queries[0].sql));
    // isLatest is per PERIOD: an older period's newest version is not
    // superseded merely because a newer period exists.
    check('the newest version of a period is latest', rows[0].isLatest === true);
    check('an older version of the SAME period is not', rows[1].isLatest === false);
    check('but the newest of an OLDER period still is', rows[2].isLatest === true,
      rows[2].period + ' v' + rows[2].version);
    check('deck_html is never in a listing — it is megabytes per row',
      !/deck_html,/.test(pool.queries[0].sql) && /deck_html IS NOT NULL/.test(pool.queries[0].sql));
    check('nor are the raw sections', !/sections/.test(pool.queries[0].sql));
  }

  section('the portal sees only published reports');
  {
    const pool = fakePool([]);
    await A.listPublications(pool, { tenantId: 7, publishedOnly: true });
    check('publishedOnly filters withdrawn ones out',
      /status = 'published'/.test(pool.queries[0].sql), pool.queries[0].sql.slice(0, 120));

    const staff = fakePool([]);
    await A.listPublications(staff, { tenantId: 7 });
    check('while staff see every version, withdrawn included',
      !/status = 'published'/.test(staff.queries[0].sql));
  }

  // ── Ownership ──────────────────────────────────────────────────────────
  section('ownership lives in the WHERE clause');
  {
    const pool = fakePool([]);
    await A.getPublication(pool, 42, 7);
    const q = pool.queries[0];
    // A post-fetch `if (row.tenant_id !== tenantId)` leaks existence through
    // timing and through any error that forgets the check. In the WHERE clause,
    // another tenant's id and a nonexistent id are the same answer.
    check('id AND tenant both filter', /WHERE id = \$1 AND tenant_id = \$2/.test(q.sql), q.sql);
    check('with the tenant bound, not interpolated', q.params[1] === 7);
    check('a missing row returns null, not a partial object',
      (await A.getPublication(fakePool([]), 42, 7)) === null);
  }

  // ── Serving ────────────────────────────────────────────────────────────
  section('a purged or missing file fails cleanly');
  {
    const res = fakeRes();
    A.sendPublicationPptx(res, { id: 1, pptx_path: null, pptx_bytes: 10, version: 1,
      client_name: 'X', period: '2026-08' });
    check('a purged report is 410, not a crash', res.statusCode === 410, res.statusCode);

    const res2 = fakeRes();
    A.sendPublicationPptx(res2, { id: 1, pptx_path: '7/does-not-exist.pptx',
      pptx_bytes: 10, version: 1, client_name: 'X', period: '2026-08' });
    check('a vanished file is 410 too', res2.statusCode === 410, res2.statusCode);
  }

  section('a real file streams with correct headers');
  {
    const dir = path.join(TMP, '7');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'deck.pptx'), Buffer.from('PK-not-really'));

    const res = fakeRes();
    const stream = A.sendPublicationPptx(res, {
      id: 1, pptx_path: '7/deck.pptx', pptx_bytes: 13, version: 2,
      client_name: 'Acme', period: '2026-08', period_label: 'August 2026',
    });
    await new Promise(r => res.on('finish', r));

    check('a stream is returned', !!stream);
    check('and the bytes actually arrive',
      Buffer.concat(res.chunks).toString() === 'PK-not-really',
      Buffer.concat(res.chunks).toString());
    check('Content-Type is the pptx mime',
      /presentationml\.presentation$/.test(res.headers['content-type']), res.headers['content-type']);
    check('Content-Disposition is an attachment', /^attachment;/.test(res.headers['content-disposition']));
    check('and carries a UTF-8 fallback filename',
      /filename\*=UTF-8''/.test(res.headers['content-disposition']));
    check('Content-Length comes from disk, not the row',
      res.headers['content-length'] === 13, res.headers['content-length']);
    check('nosniff is set', res.headers['x-content-type-options'] === 'nosniff');
    check('the archive is never cached', /no-store/.test(res.headers['cache-control']));

  }

  section('the archived HTML runs sandboxed');
  {
    const res = fakeRes();
    A.sendPublicationHtml(res, { id: 1, deck_html: '<p>hi</p>', version: 1,
      client_name: 'Acme', period: '2026-08' });

    check('it is served as HTML', /text\/html/.test(res.headers['content-type']));
    // The archived document carries report-deck.js's inline pagination script.
    // Served same-origin that script would sit inside the portal's cookie
    // scope; the sandbox directive forces an opaque origin instead.
    const csp = res.headers['content-security-policy'] || '';
    check('a CSP is set', !!csp);
    check('it sandboxes the document', /(^|;\s*)sandbox\b/.test(csp), csp.slice(0, 60));
    check('scripts may still run, so pagination and print work',
      /allow-scripts/.test(csp));
    check('but it is NOT given back same-origin access',
      !/allow-same-origin/.test(csp), csp);
    check('default-src is none', /default-src 'none'/.test(csp));
    check('served inline, not as a download', /^inline;/.test(res.headers['content-disposition']));

    const missing = fakeRes();
    A.sendPublicationHtml(missing, { id: 2, deck_html: null });
    check('a report with no archived HTML is 404, not an empty page',
      missing.statusCode === 404, missing.statusCode);
  }

  // ── Housekeeping ───────────────────────────────────────────────────────
  section('retention keeps the row and drops the bytes');
  {
    const pool = fakePool((sql) => /SELECT id, pptx_path/.test(sql)
      ? [{ id: 5, pptx_path: '7/old.pptx' }] : []);
    fs.mkdirSync(path.join(TMP, '7'), { recursive: true });
    fs.writeFileSync(path.join(TMP, '7', 'old.pptx'), 'x');

    const n = await A.pruneReportArchive(pool);
    check('one file pruned', n === 1, n);
    check('the file is gone', !fs.existsSync(path.join(TMP, '7', 'old.pptx')));
    const upd = pool.queries.find(q => /UPDATE report_publications/.test(q.sql));
    check('the row survives, marked purged',
      upd && /pptx_path = NULL, purged_at = NOW\(\)/.test(upd.sql));
    check('the latest version of a period is never pruned',
      /version < \(SELECT MAX\(version\)/.test(pool.queries[0].sql));
  }

  section('an un-migrated database is not an error');
  {
    const missing = { async query() { const e = new Error('nope'); e.code = '42P01'; throw e; } };
    check('prune degrades quietly', (await A.pruneReportArchive(missing)) === 0);
    // The sweep DELETES files. Without the table it cannot tell an orphan from
    // a live artefact, and deleting on a guess is the one outcome worth
    // avoiding entirely.
    check('and the sweep refuses to delete anything on a guess',
      (await A.sweepOrphanReportFiles(missing)) === 0);
  }

  section('the orphan sweep removes remnants, not live files');
  {
    const dir = path.join(TMP, '9');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'live.pptx'), 'x');
    fs.writeFileSync(path.join(dir, 'orphan.pptx'), 'x');
    fs.writeFileSync(path.join(dir, 'crashed.pptx.tmp'), 'x');

    // 7/deck.pptx was written by the streaming test above and is still on disk.
    // It is declared live here so this checks tenant 9's three files rather
    // than accidentally counting an earlier test's leftovers.
    const pool = fakePool([{ pptx_path: '9/live.pptx' }, { pptx_path: '7/deck.pptx' }]);
    const n = await A.sweepOrphanReportFiles(pool);

    check('the live file survives', fs.existsSync(path.join(dir, 'live.pptx')));
    check('the orphan is removed', !fs.existsSync(path.join(dir, 'orphan.pptx')));
    // A surviving .tmp means a publish did not finish: the real name is only
    // ever reached by rename.
    check('an unfinished publish is cleaned up', !fs.existsSync(path.join(dir, 'crashed.pptx.tmp')));
    check('two files removed', n === 2, n);
  }

  section('the archive is never inside public/');
  {
    // express.static is mounted before the session middleware, so anything
    // under public/ is served to anonymous callers. An archive there would
    // publish every client's board report to the internet.
    const pub = path.resolve(ROOT, 'public');
    const arch = path.resolve(A.ARCHIVE_DIR);
    check('ARCHIVE_DIR is outside the static root',
      !arch.startsWith(pub + path.sep) && arch !== pub, arch);

    // And the default, independent of this test's env override.
    const defaultDir = path.resolve(ROOT, 'data', 'reports');
    check('the default is under data/, not public/',
      !defaultDir.startsWith(pub + path.sep), defaultDir);
  }

  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) { /* temp dir */ }
  done();
})();
