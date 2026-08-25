'use strict';

/**
 * lib/report-pptx-route.js
 *
 * The Express handler for POST /api/reports/pptx, kept out of server.js so it
 * can be mounted and exercised over real HTTP by a test. The alternative was a
 * handler that only ever runs behind requireAuth, which needs a database that
 * has been unreachable throughout development — i.e. a handler nobody had run.
 *
 * server.js supplies the auth middleware and the logo; everything here is pure
 * request-in, file-out.
 */

const fs = require('fs');
const path = require('path');
const { buildPptx } = require('./report-pptx');

const PPTX_MIME =
  'application/vnd.openxmlformats-officedocument.presentationml.presentation';

// A malformed or hostile client should not be able to make the server chew
// through unbounded work. These are far above anything the real deck produces
// (15 sections, at most 3 bodies each).
const MAX_SECTIONS = 60;
const MAX_BODIES   = 20;

/**
 * Validate and clamp the request body.
 * @returns {{ ctx: Object, sections: Array }} or {{ error: string, status: number }}
 */
function sanitiseRequest(body) {
  const b = body || {};
  const meta = b.ctx || {};
  const raw = Array.isArray(b.sections) ? b.sections : [];

  if (!raw.length) return { error: 'No sections to render.', status: 400 };
  if (raw.length > MAX_SECTIONS) return { error: 'Too many sections.', status: 400 };

  const sections = raw
    .filter(s => s && typeof s.label === 'string' && Array.isArray(s.bodies))
    .map(s => ({
      label: String(s.label).slice(0, 200),
      bodies: s.bodies
        .filter(h => typeof h === 'string' && h.trim())
        .slice(0, MAX_BODIES),
    }))
    .filter(s => s.bodies.length);

  if (!sections.length) return { error: 'No renderable section content.', status: 400 };

  const str = (v, n) => String(v == null ? '' : v).slice(0, n);
  return {
    sections,
    ctx: {
      clientName:  str(meta.clientName, 120),
      period:      str(meta.period, 40),
      periodLabel: str(meta.periodLabel, 80),
      author:      str(meta.author, 120),
      dateStr:     str(meta.dateStr, 40),
    },
  };
}

/**
 * A download filename that is safe in a Content-Disposition header and on every
 * filesystem. Client names come from the tenant table and can hold anything —
 * quotes, slashes, newlines — and a raw newline here would let a caller inject
 * further response headers.
 */
function pptxFilename(ctx) {
  const c = ctx || {};
  const name = String(c.clientName || '')
    .replace(/[^A-Za-z0-9._ -]+/g, ' ')
    .trim()
    .replace(/\s+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 60) || 'Client';
  const period = String(c.period || '').replace(/[^0-9-]/g, '').slice(0, 10) || 'report';
  return name + '-Cybersecurity-Board-Report-' + period + '.pptx';
}

/** The deck logo as a data URI, read once off disk. */
function makeLogoReader(rootDir) {
  let cache;
  return function logoDataUri() {
    if (cache !== undefined) return cache;
    try {
      const p = path.join(rootDir, 'public', 'img', 'reflex-logo.png');
      cache = 'data:image/png;base64,' + fs.readFileSync(p).toString('base64');
    } catch (err) {
      // The deck still builds, just unbranded — better than failing the export.
      cache = null;
    }
    return cache;
  };
}

/**
 * createPptxHandler — the Express handler.
 *
 * @param {Object}   opts
 * @param {Function} opts.logoDataUri  returns a data: URI, or null
 * @param {Function} [opts.log]        called with a one-line summary
 * @param {Function} [opts.onError]    (res, err) — server.js's error responder
 */
function createPptxHandler(opts) {
  const o = opts || {};
  const logo = o.logoDataUri || (() => null);
  const log  = o.log || (() => {});
  const onError = o.onError || function (res, err) {
    res.status(500).json({ error: err.message });
  };

  return async function pptxHandler(req, res) {
    try {
      const parsed = sanitiseRequest(req.body);
      if (parsed.error) return res.status(parsed.status).json({ error: parsed.error });

      const ctx = Object.assign({}, parsed.ctx, { logoDataUri: logo() });
      const { buffer, stats } = await buildPptx(ctx, parsed.sections);
      const filename = pptxFilename(ctx);

      log('[pptx] ' + filename + ': ' + stats.slides + ' slides, ' +
        stats.sections + ' sections' +
        (stats.skipped.length ? ', skipped ' + stats.skipped.join('/') : '') +
        (stats.unmapped ? ', ' + stats.unmapped + ' unmapped blocks' : ''));

      res.setHeader('Content-Type', PPTX_MIME);
      res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
      res.setHeader('Content-Length', buffer.length);
      res.setHeader('X-Pptx-Slides', String(stats.slides));
      return res.end(buffer);
    } catch (err) {
      return onError(res, err);
    }
  };
}

module.exports = {
  createPptxHandler, sanitiseRequest, pptxFilename, makeLogoReader,
  PPTX_MIME, MAX_SECTIONS, MAX_BODIES,
};
