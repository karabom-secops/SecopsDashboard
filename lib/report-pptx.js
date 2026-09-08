'use strict';

/**
 * lib/report-pptx.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Builds the board report as a native, editable PowerPoint deck (16:9).
 *
 * WHY THIS IS A TRANSLATOR AND NOT A SECOND RENDERER
 *
 * The obvious way to do this is to write fifteen PPTX section builders beside
 * the fifteen HTML ones in public/js/report-sections.js. That is also the way
 * this ends up wrong: two renderers reading the same data drift the moment
 * anyone edits one of them, and the deck starts disagreeing with the PDF about
 * the client's own numbers. We have already been bitten by exactly that class
 * of split-brain bug in this codebase.
 *
 * So the section renderers stay the single source of truth. This module takes
 * the HTML they already emit, parses it back into a small block vocabulary, and
 * lays those blocks out as real PowerPoint shapes, tables and text. Change a
 * section and both outputs change together, because there is only one place
 * that knows what a section says.
 *
 * The price is that this file must understand the deck's HTML vocabulary. That
 * vocabulary is small, controlled and entirely ours (see DECK_CSS in
 * public/js/report-deck.js) — 135 distinct constructs across every section, of
 * which tables, label/value tiles and prose account for the large majority.
 * Anything unrecognised still degrades to readable text rather than vanishing:
 * see textFallback().
 *
 * GEOMETRY. Portrait A4 is right for a printed PDF and wrong for a projector,
 * so this deck is 13.333in x 7.5in widescreen. Content laid out for a tall page
 * therefore has to re-flow into a wide one, which means a section can occupy
 * more slides here than it does pages in the PDF. Continuation slides are
 * titled "<Section> (cont.)".
 */

const path = require('path');
const PptxGenJS = require('pptxgenjs');
const { parse } = require('node-html-parser');
const brandAssets = require('./brand-assets');

/* ── Palette ────────────────────────────────────────────────────────────────
 * Mirrors the DECK_* entries of PALETTE in public/js/report-shell.js. That file
 * is a browser IIFE and cannot be required here, so the values are repeated —
 * and a parity test asserts the two stay identical, because a deck whose blue
 * differs from the PDF's blue is worse than no deck at all. */
const P = {
  BLUE:       '1077C7',
  TABLE_HEAD: '2E75B6',
  NAVY:       '12294A',
  CARD:       'EEEEEE',
  GREEN:      '2E9E5B',
  AMBER:      'E08A1E',
  MAROON:     '8B1A2B',
  TRACK:      'D9D9D9',
  INK:        '262626',
  MUTED:      '595959',
  FOOT:       '7F7F7F',
  WHITE:      'FFFFFF',
  RULE:       'BFBFBF',

  /* Template colours with no counterpart in the HTML deck, so exempt from the
     palette parity check — they exist only in the PowerPoint. */
  SLATE:        '2B3445',   // slide titles, cover subtitle, the heavy rule
  LIGHT_BLUE:   '6FADDE',   // second chart series
  TABLE_BORDER: 'BDD7EE',   // hairlines between table rows
  TABLE_EDGE:   '9DC3E6',   // table outer edge
};

/* ── Type ───────────────────────────────────────────────────────────────────
 *
 * The brand spec is Montserrat, headings 48px and body 28px.
 *
 * PowerPoint sizes type in POINTS, so those px figures need a canvas to convert
 * against. This deck is 13.333in x 7.5in = 960 x 540pt, and a 1920x1080 design
 * canvas — the usual one for 16:9 — puts one px at half a point:
 *
 *     48px heading -> 24pt        28px body -> 14pt
 *
 * That also lands the heading exactly where the reference template's slide
 * titles measure, which is the corroboration for choosing this canvas over a
 * 1280x720 one. If the spec was drawn against a different canvas, PX_TO_PT is
 * the single number to change.
 *
 * Montserrat does not ship with Office. On a machine without it PowerPoint
 * substitutes, and the deck will not look like the template — it is a free
 * Google font and needs installing on any machine that presents from this.
 */
const FONT = 'Montserrat';

const PX_TO_PT = 0.5;
const px = n => n * PX_TO_PT;

const TYPE = {
  heading:  px(48),   // slide titles
  body:     px(28),   // prose, bullets, the default
  subhead:  px(32),
  // Dense tabular data sits below body size by convention — a six-column table
  // at body size fits about four rows to a slide and turns a report into a
  // flipbook. Kept proportional to the spec rather than picked freehand.
  tableHead: px(24),
  tableBody: px(22),
  note:      px(20),  // footnotes, captions, axis labels
  tileLabel: px(20),
  footer:    px(18),
  coverTitle: px(80),
  coverSub:   px(38),
  coverDate:  px(28),
  closing:    px(108),
  // A headline figure inside a KPI tile. Shrinks to fit its tile via fitFont(),
  // so this is its ceiling rather than its size.
  bigNumber:  px(44),
};

/* ── Geometry (inches) ─────────────────────────────────────────────────────── */
const SLIDE_W = 13.333;
const SLIDE_H = 7.5;
const MARGIN  = 0.6;
const BODY_W  = SLIDE_W - MARGIN * 2;      // 12.133
const TITLE_Y = 0.42;
const BODY_TOP    = 1.24;
const BODY_BOTTOM = 6.82;                  // footer sits below this
const BODY_H  = BODY_BOTTOM - BODY_TOP;    // 5.58
const FOOT_Y  = 6.95;

/* ═══════════════════════════════════════════════════════════════════════════
 * 1. PARSE — deck HTML into a block vocabulary
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Collapse whitespace and decode the entities the section renderers emit.
 *
 * Child elements are joined with a space. Without it, markup that relies on CSS
 * for its spacing runs together: `<div>Agent currency<span>target 98%</span></div>`
 * came out as "Agent currencytarget 98%" on a client slide. The collapse at the
 * end means an existing space is not doubled.
 */
function text(node) {
  if (!node) return '';
  return decode(rawText(node)).replace(/\s+/g, ' ').trim();
}

function rawText(node) {
  if (!node) return '';
  if (node.nodeType === 3) return node.rawText || '';
  if (!node.childNodes || !node.childNodes.length) return node.rawText || '';
  return node.childNodes.map(rawText).join(' ');
}

/**
 * Named entities the sections actually emit, plus numeric escapes.
 *
 * The catch-all at the end replaces anything unlisted with a space rather than
 * leaving it raw — a literal "&mdash;" on a client slide reads as a bug. But the
 * catch-all is a last resort, not the plan: it silently ate the em-dash in
 * "Endpoints — Managed EDR". Every entity the deck produces is named here, so
 * add to this table rather than relying on the fallback.
 *
 * &amp; is parked on a sentinel first and restored last. Decoding it early would
 * turn "&amp;lt;" into "<" (decoding twice); leaving it to the named pass would
 * match "amp" against the table, miss, and replace an ampersand with a space.
 */
const AMP = String.fromCharCode(1);   // a control char deck HTML cannot contain
const ENTITIES = {
  nbsp: ' ', middot: '·', bull: '•',
  mdash: '—', ndash: '–', minus: '−',
  lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”',
  quot: '"', apos: "'", hellip: '…',
  times: '×', divide: '÷', deg: '°', plusmn: '±',
  trade: '™', copy: '©', reg: '®',
  larr: '←', rarr: '→', uarr: '↑', darr: '↓', harr: '↔',
  lt: '<', gt: '>',
};

function decode(s) {
  return String(s || '')
    .split('&amp;').join(AMP)
    .replace(/&#(\d+);/g, (_, n) => safeChar(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => safeChar(parseInt(n, 16)))
    .replace(/&([a-z]+);/gi, (_, name) => {
      const v = ENTITIES[name.toLowerCase()];
      return v === undefined ? ' ' : v;
    })
    .split(AMP).join('&');
}

function safeChar(code) {
  return Number.isFinite(code) && code > 0 && code <= 0x10FFFF
    ? String.fromCodePoint(code) : ' ';
}

function classes(node) {
  return String((node && node.getAttribute && node.getAttribute('class')) || '')
    .trim().split(/\s+/).filter(Boolean);
}

function hasClass(node, c) { return classes(node).indexOf(c) !== -1; }

/** Pull a CSS declaration out of an inline style attribute. */
function styleProp(node, prop) {
  const s = (node && node.getAttribute && node.getAttribute('style')) || '';
  const m = new RegExp(prop + '\\s*:\\s*([^;]+)').exec(s);
  return m ? m[1].trim() : null;
}

function hexOf(node, prop) {
  const v = styleProp(node, prop || 'background');
  const m = v && /#([0-9a-f]{6})/i.exec(v);
  return m ? m[1].toUpperCase() : null;
}

/**
 * Map a RAG class or inline colour to a PowerPoint fill. The section renderers
 * express state two ways — a semantic class (.rag-no) or a literal hex from the
 * score bands — so both have to resolve here.
 */
function toneOf(node) {
  const c = classes(node);
  if (c.indexOf('rag-no') !== -1 || c.indexOf('ov-bad') !== -1) return P.MAROON;
  if (c.indexOf('rag-yes') !== -1) return P.GREEN;
  if (c.indexOf('amber') !== -1 || c.indexOf('rag-unknown') !== -1) return P.AMBER;
  if (c.indexOf('green') !== -1) return P.GREEN;
  const hex = hexOf(node, 'background') || hexOf(node, 'color');
  return hex || null;
}

/**
 * Walk a section body into blocks.
 *
 * Order matters: the specific handlers run before the generic descent, so a
 * table inside a .sec-block is claimed as a table rather than flattened to its
 * text. Anything with no handler falls through to a text block, which is why an
 * unmapped future construct degrades instead of disappearing.
 */
function parseBlocks(html) {
  const root = parse('<div id="__r">' + String(html || '') + '</div>');
  const out = [];
  walk(root.querySelector('#__r'), out);
  return mergeAxisLabels(out).filter(b => b && !(b.type === 'text' && !b.text));
}

/**
 * The trend chart's x-axis is a SIBLING of the chart, not a child of it, so the
 * walk meets the labels after the block they belong to has already been built.
 * Fold them back in — otherwise twelve month labels arrive as twelve orphan text
 * blocks and each one claims a line of its own on the slide.
 */
function mergeAxisLabels(blocks) {
  const out = [];
  blocks.forEach((b) => {
    if (b.type === 'xlabels') {
      const prev = out[out.length - 1];
      if (prev && prev.type === 'stacked') {
        prev.cols.forEach((c, i) => { if (!c.label) c.label = b.labels[i] || ''; });
        return;
      }
      return;   // labels with no chart to attach to are noise, not content
    }
    out.push(b);
  });
  return out;
}

function walk(node, out) {
  if (!node || !node.childNodes) return;
  node.childNodes.forEach((child) => {
    if (child.nodeType === 3) {                       // bare text between blocks
      const t = decode(child.rawText).replace(/\s+/g, ' ').trim();
      if (t) out.push({ type: 'text', text: t });
      return;
    }
    if (child.nodeType !== 1) return;
    const tag = child.rawTagName ? child.rawTagName.toLowerCase() : '';
    const block = claim(child, tag);
    if (block === null) { walk(child, out); return; }  // transparent container
    if (block) out.push(block);
  });
}

/**
 * Try every specific handler for one element.
 *  - returns a block  → consumed
 *  - returns null     → descend into it
 *  - returns undefined→ ignore entirely
 */
function claim(el, tag) {
  if (tag === 'table')                 return tableBlock(el);
  if (tag === 'ul' || tag === 'ol')    return bulletBlock(el);
  if (tag === 'p')                     return { type: 'prose', paras: [text(el)] };
  if (tag === 'br')                    return undefined;

  if (hasClass(el, 'sec-sub'))         return { type: 'subhead', text: text(el) };
  if (hasClass(el, 'sec-comment'))     return commentBlock(el);
  if (hasClass(el, 'es-prose'))        return proseBlock(el);
  if (hasClass(el, 'bi-grid'))         return tilesBlock(el, '.bi-cell', '.bi-v', '.bi-l');
  if (hasClass(el, 'ov-row'))          return ovRowBlock(el);
  if (hasClass(el, 'ov-stack'))        return null;
  if (hasClass(el, 'sev-row'))         return sevRowBlock(el);
  if (hasClass(el, 'cmp-row'))         return cmpRowBlock(el);
  if (hasClass(el, 'cc-grid'))         return ccGridBlock(el);
  if (hasClass(el, 'hm-wrap'))         return heatMapBlock(el);
  if (hasClass(el, 'tl-wrap'))         return barsBlock(el);
  if (hasClass(el, 'tr-chart'))        return stackedBlock(el);
  if (hasClass(el, 'tr-xaxis'))        return { type: 'xlabels', labels: el.querySelectorAll('.tr-xl').map(text) };
  if (hasClass(el, 've-facts'))        return tilesBlock(el, '.ve-fact', '.ve-fv', '.ve-fl');
  if (hasClass(el, 'gc-list'))         return qaBlock(el);
  if (hasClass(el, 'rec-list'))        return recBlock(el);
  if (hasClass(el, 'rem-cols'))        return columnsBlock(el);
  if (hasClass(el, 'as-wrap'))         return quoteBlock(el);
  if (hasClass(el, 'sb-bar'))          return undefined;   // decorative rail

  // Claimed by columnsBlock() via querySelector before the walk descends. Left
  // unclaimed they are ALSO collected as text blocks, and each column printed
  // its heading and sub-heading twice.
  if (hasClass(el, 'rem-h') || hasClass(el, 'rem-sub')) return undefined;
  if (hasClass(el, 'hm-legend'))       return legendBlock(el);

  if (hasClass(el, 'rag-note') || hasClass(el, 'rem-more') ||
      hasClass(el, 'rag-basis') || hasClass(el, 'coverage-note')) {
    return { type: 'note', text: text(el) };
  }
  if (hasClass(el, 'dt-cap'))          return { type: 'caption', text: text(el) };
  if (hasClass(el, 'dt-empty') || hasClass(el, 'rem-empty')) {
    return { type: 'note', text: text(el) };
  }

  // Structural wrappers we descend through.
  if (hasClass(el, 'sec-block') || hasClass(el, 'rem-col') || hasClass(el, 'tk-wrap')) {
    return null;
  }

  // A leaf div/span with text and no recognised class: keep the words.
  if (!el.querySelector || !el.querySelector('div,table,ul,ol,p')) {
    const t = text(el);
    return t ? { type: 'text', text: t } : undefined;
  }
  return null;
}

function proseBlock(el) {
  const ps = el.querySelectorAll('p').map(text).filter(Boolean);
  return { type: 'prose', paras: ps.length ? ps : [text(el)] };
}

function bulletBlock(el) {
  return { type: 'bullets', items: el.querySelectorAll('li').map(text).filter(Boolean) };
}

function commentBlock(el) {
  const l = el.querySelector('.sec-comment-label');
  const b = el.querySelector('.sec-comment-body');
  return { type: 'comment', label: text(l) || 'Comment', text: text(b) || text(el) };
}

/**
 * A data table. Column widths come from the <colgroup> the sections emit, which
 * is the only place the intended proportions are recorded — falling back to
 * equal columns would wreck every table whose first column is a long name.
 */
function tableBlock(el) {
  const widths = el.querySelectorAll('col').map((c) => {
    const m = /([\d.]+)%/.exec(styleProp(c, 'width') || '');
    return m ? parseFloat(m[1]) : null;
  }).filter(w => w != null);

  const head = el.querySelectorAll('thead tr').map(tr =>
    tr.querySelectorAll('th').map(th => ({
      text: text(th), num: hasClass(th, 'num'),
    })));

  const rows = el.querySelectorAll('tbody tr').map(tr => ({
    total: hasClass(tr, 'total'),
    cells: tr.querySelectorAll('td,th').map(td => ({
      text: text(td),
      num:  hasClass(td, 'num'),
      bold: !!td.querySelector('b,strong') || hasClass(tr, 'total'),
      tone: cellTone(td),
    })),
  }));

  if (!head.length && !rows.length) return undefined;
  return { type: 'table', head, rows, widths, rag: hasClass(el, 'rag') };
}

/** A cell is toned only by a pill inside it — never by the row's own styling. */
function cellTone(td) {
  const pill = td.querySelector('.rag-pill,.rag-no,.rag-yes,.rag-unknown,.ov-bad');
  return pill ? toneOf(pill) : null;
}

/** Generic value/label tile grid. */
function tilesBlock(el, cellSel, valSel, labSel) {
  const items = el.querySelectorAll(cellSel).map((c) => {
    const v = c.querySelector(valSel);
    const l = c.querySelector(labSel);
    const nd = v && hasClass(v, 'nd');
    return {
      value: nd ? 'No data' : text(v),
      label: text(l),
      tone:  nd ? null : toneOf(v) || (hasClass(c, 'ok') ? P.GREEN : null),
      muted: !!nd,
    };
  }).filter(i => i.value || i.label);
  return items.length ? { type: 'tiles', items, compact: hasClass(el, 'tight') } : undefined;
}

function ovRowBlock(el) {
  const items = el.querySelectorAll('.ov-card').map((c) => {
    const num  = c.querySelector('.ov-num');
    const pill = c.querySelector('.ov-pill');
    const nd   = c.querySelector('.ov-nodata');
    return {
      value: nd ? 'No data' : text(num || pill),
      label: text(c.querySelector('.ov-t')),
      sub:   text(c.querySelector('.ov-d')),
      tone:  pill ? toneOf(pill) : null,
      muted: !!nd,
    };
  }).filter(i => i.label || i.value);
  return items.length ? { type: 'tiles', items } : undefined;
}

function sevRowBlock(el) {
  const items = el.querySelectorAll('.sev-card').map(c => ({
    value: text(c.querySelector('.sev-n')),
    label: text(c.querySelector('.sev-l')),
    sub:   text(c.querySelector('.sev-sla')),
    tone:  toneOf(c.querySelector('.sev-dot') || c),
  })).filter(i => i.label || i.value);
  return items.length ? { type: 'tiles', items } : undefined;
}

/** Weighted score cards — value, weight, and a proportional bar. */
function cmpRowBlock(el) {
  const items = el.querySelectorAll('.cmp-card').map((c) => {
    const fill = c.querySelector('.cmp-fill');
    const m = /([\d.]+)%/.exec(styleProp(fill, 'width') || '');
    return {
      label: text(c.querySelector('.cmp-t')),
      weight: text(c.querySelector('.cmp-w')),
      value: text(c.querySelector('.cmp-score')),
      sub:   text(c.querySelector('.cmp-d')),
      pct:   m ? parseFloat(m[1]) : 0,
      tone:  hexOf(fill, 'background') || P.BLUE,
    };
  });
  return items.length ? { type: 'meters', items } : undefined;
}

/**
 * Control-coverage groups. `.cc-l` may carry a nested `.cc-t` target suffix
 * ("Agent currency" + "target 98%"); split it out so the target renders as the
 * muted aside it is in the HTML, rather than as part of the metric's name.
 */
function ccGridBlock(el) {
  const groups = el.querySelectorAll('.cc-group').map(g => ({
    heading: text(g.querySelector('.cc-gh')),
    items: g.querySelectorAll('.cc-item').map((i) => {
      const l = i.querySelector('.cc-l');
      const t = l && l.querySelector('.cc-t');
      const note = t ? text(t) : '';
      let label = text(l);
      if (note && label.endsWith(note)) label = label.slice(0, -note.length).trim();
      return {
        label,
        note,
        value: text(i.querySelector('.cc-v')),
        tone:  toneOf(i.querySelector('.cc-v')),
      };
    }),
  })).filter(g => g.items.length);
  return groups.length ? { type: 'ccgroups', groups } : undefined;
}

/**
 * The 5x5 risk heat map. In HTML it is a CSS grid of row-label + five cells;
 * here it becomes a native table with per-cell fills, which stays editable and
 * survives being resized in PowerPoint.
 */
function heatMapBlock(el) {
  const grid = el.querySelector('.hm-grid');
  if (!grid) return undefined;

  const rows = [];
  let current = null;
  grid.childNodes.filter(n => n.nodeType === 1).forEach((n) => {
    if (hasClass(n, 'hm-rl')) { current = { label: text(n), cells: [] }; rows.push(current); return; }
    if (hasClass(n, 'hm-cell') && current) {
      const faded = parseFloat(styleProp(n, 'opacity') || '1') < 0.5;
      current.cells.push({
        n: text(n.querySelector('.hm-n')),
        fill: hexOf(n, 'background') || 'FFFFFF',
        faded,
      });
    }
  });
  if (!rows.length) return undefined;

  return {
    type: 'heatmap',
    rows,
    yTitle: text(el.querySelector('.hm-ylab')),
    xTitle: text(el.querySelector('.hm-xtitle')),
    xLabels: el.querySelectorAll('.hm-xl').map(text),
  };
}

/** Horizontal bar list (threat landscape). */
function barsBlock(el) {
  const items = el.querySelectorAll('.tl-row').map((r) => {
    const fill = r.querySelector('.tl-fill');
    const m = /([\d.]+)%/.exec(styleProp(fill, 'width') || '');
    return {
      name: text(r.querySelector('.tl-name')),
      value: text(r.querySelector('.tl-n')),
      pct: m ? parseFloat(m[1]) : 0,
      tone: hexOf(fill, 'background') || P.BLUE,
    };
  }).filter(i => i.name);

  // A severity row is `<span class="sev-dot"></span>Critical<span class="tl-sev-n">1</span>`
  // — the label is a bare text node between two spans, and `.tl-sev` is the
  // CONTAINER of the rows, not anything inside one. Selecting `.tl-sev` within a
  // row therefore found nothing and silently dropped the whole panel.
  const side = el.querySelectorAll('.tl-sev-row').map((r) => {
    const n = r.querySelector('.tl-sev-n');
    const value = text(n);
    let label = text(r);
    if (value && label.endsWith(value)) label = label.slice(0, -value.length).trim();
    return { label, value, tone: toneOf(r.querySelector('.sev-dot')) };
  }).filter(i => i.label);

  const total = text(el.querySelector('.tl-total'));
  const totalLabel = text(el.querySelector('.tl-total-l'));
  if (!items.length && !side.length) return undefined;
  return { type: 'bars', items, side, total, totalLabel };
}

/**
 * Stacked trend columns. The HTML encodes each segment's share as a CSS height,
 * so the proportions are recoverable; the absolute counts are not, which is why
 * this renders as a proportional stack rather than a value-axis chart.
 */
function stackedBlock(el) {
  const cols = el.querySelectorAll('.tr-col').map(c => ({
    segs: c.querySelectorAll('.tr-seg').map((s) => {
      const m = /([\d.]+)%/.exec(styleProp(s, 'height') || '');
      return { pct: m ? parseFloat(m[1]) : 0, tone: hexOf(s, 'background') || P.BLUE };
    }).filter(s => s.pct > 0),
  }));
  const labels = el.parentNode
    ? (el.parentNode.querySelectorAll('.tr-xl') || []).map(text)
    : [];
  const inner = el.querySelectorAll('.tr-xl').map(text);
  const xl = inner.length ? inner : labels;
  cols.forEach((c, i) => { c.label = xl[i] || ''; });
  return cols.length ? { type: 'stacked', cols } : undefined;
}

function qaBlock(el) {
  const items = el.querySelectorAll('.gc-item').map(i => ({
    ref: text(i.querySelector('.gc-ref')),
    q:   text(i.querySelector('.gc-q')),
    a:   text(i.querySelector('.gc-a')),
  })).filter(i => i.q || i.a);
  return items.length ? { type: 'qa', items } : undefined;
}

/**
 * Executive recommendations. `.rec-meta` is the CONTAINER of the chip and the
 * impact, not a third field — reading it as one printed "Major · Decision Major".
 * The item's urgency is carried by its border-left-color, so the accent bar
 * takes that rather than a flat blue.
 */
function recBlock(el) {
  const items = el.querySelectorAll('.rec-item').map((i) => {
    const chipEl = i.querySelector('.rec-chip');
    return {
      area:   text(i.querySelector('.rec-area')),
      text:   text(i.querySelector('.rec-text')),
      impact: text(i.querySelector('.rec-impact')),
      chip:   text(chipEl),
      tone:   hexOf(i, 'border-left-color') || (chipEl && hexOf(chipEl, 'background')) || P.BLUE,
    };
  }).filter(i => i.text || i.area);
  return items.length ? { type: 'recs', items } : undefined;
}

/** Two side-by-side columns (remediated / scheduled). */
function columnsBlock(el) {
  const cols = el.querySelectorAll('.rem-col').map((c) => {
    const blocks = [];
    walk(c, blocks);
    return {
      heading: text(c.querySelector('.rem-h')),
      sub:     text(c.querySelector('.rem-sub')),
      blocks:  blocks.filter(b => b.type !== 'text' || b.text),
    };
  });
  return cols.length ? { type: 'columns', cols } : undefined;
}

function quoteBlock(el) {
  return {
    type: 'quote',
    text: text(el.querySelector('.as-quote')),
    by:   text(el.querySelector('.as-by')),
    role: text(el.querySelector('.as-role')),
    date: text(el.querySelector('.as-date')),
  };
}

function legendBlock(el) {
  const keys = el.querySelectorAll('.hm-key').map(k => ({
    label: text(k),
    tone:  hexOf(k.querySelector('.hm-sw'), 'background') || P.TRACK,
  }));
  return keys.length ? { type: 'legend', keys } : undefined;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 2. MEASURE — estimate how tall each block will render
 *
 * PowerPoint gives no text-metrics API, so heights are estimated from character
 * counts. Estimates are deliberately generous: under-estimating overflows the
 * slide and silently clips content (the .pg-body overflow:hidden trap that bit
 * the PDF deck), while over-estimating only breaks a section one slide earlier
 * than strictly necessary. Wrong in the safe direction, on purpose.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Characters that fit on one line at a given width and point size. */
function charsPerLine(widthIn, pt) {
  return Math.max(8, Math.floor(widthIn / (pt * 0.0071)));
}

function lineCount(str, widthIn, pt) {
  const per = charsPerLine(widthIn, pt);
  return Math.max(1, Math.ceil(String(str || '').length / per));
}

/**
 * These are used for BOTH measurement and drawing, deliberately. When the two
 * disagreed — measuring rows at 0.29in while drawing them at 0.23in — a seven
 * row table was judged too tall for a slide that had two inches of empty space
 * left, and one row was pushed onto a continuation slide of its own.
 */
const ROW_H         = 0.30;   // one table body row
const HEAD_H        = 0.34;   // table header row
const TILE_H        = 1.14;   // one row of value/label tiles
const TILE_H_COMPACT = 1.02;
const CC_ROW_H      = 0.32;   // one control-coverage line
const BAR_ROW_H     = 0.38;   // one horizontal bar
const GAP           = 0.16;   // between blocks

/** Tiles wrap at six across — beyond that they get too narrow to read. */
function tilesPerRow(n) { return n <= 6 ? n : Math.ceil(n / 2); }

/**
 * One line of type, in inches, at a given point size.
 *
 * Every height below derives from this rather than from a tuned constant.
 * Measurement and drawing must agree on the SAME point size: when they
 * disagreed by a couple of points a seven-row table was judged too tall for a
 * slide with two inches to spare. Raising the type to the brand's 28px body
 * would have reintroduced exactly that, silently, on every text block at once.
 */
function lineH(pt) { return pt * 1.42 / 72; }

/** Vertical padding around a block, scaled with the type it contains. */
function pad(pt) { return lineH(pt) * 0.35; }

/* ── One recommendation's geometry ─────────────────────────────────────────
 *
 * SHARED BY measure() AND drawRecs(), for the reason the ROW_H comment above
 * gives and this block ignored: they had two different opinions about how tall
 * a recommendation is, and they were both wrong in different ways.
 *
 *   measure()   wrapped at TYPE.body (14pt) across BODY_W - 1.7
 *   drawRecs()  wrapped at a hardcoded 10pt across BODY_W - 1.7, at a
 *               hardcoded 0.20in per line — then DREW the text at
 *               TYPE.tableBody (11pt) into a box of BODY_W - 1.9
 *
 * Three disagreements in one block: the point size used to estimate the wrap,
 * the width used to estimate it, and the line height. Every one of them made
 * the drawn height too small, so a recommendation of more than about two lines
 * had its impact label ("Moderate", "Commercial") printed on top of its own
 * last line, its accent bar cut short, and the next item started before the
 * previous one had finished.
 *
 * It surfaced when the recommendations grew past a single line — the "Services
 * not currently consumed" entry names every service in the catalogue — but the
 * bug was always there waiting for a long enough sentence.
 *
 * Now there is one function. Anything drawing a recommendation must ask it for
 * the height, and must draw the text at REC_TEXT_PT into REC_TEXT_W, or the
 * two drift apart again.
 */
const REC_TEXT_PT   = TYPE.tableBody;   // the size the body text is DRAWN at
const REC_INSET     = 0.16;             // left inset past the accent bar
const REC_CHIP_W    = 1.45;             // chip column reserved on the right
const REC_CHIP_GAP  = 0.29;             // clear space between text and chip
const REC_AREA_H    = 0.22;             // the bold area heading
const REC_IMPACT_H  = 0.22;             // the impact caption under the text
const REC_PAD       = 0.10;             // breathing room inside the item
const REC_GAP       = 0.10;             // between items

/** Usable width for a recommendation's heading and body text. */
function recTextW(w) {
  return (w || BODY_W) - REC_INSET - REC_CHIP_W - REC_CHIP_GAP;
}

/*
 * charsPerLine() assumes an average character is 0.0071in per point — about
 * 0.51em. Montserrat is a wide face and its real average is nearer 0.57em, so
 * the generic estimate returns roughly a tenth more characters per line than
 * actually fit. On a two-line item that rounds away; on the four-line
 * "services not consumed" entry it lost a whole line, and a lost line here is
 * an impact label printed on top of the text.
 *
 * Corrected locally rather than in charsPerLine(), which every other block has
 * been tuned against. Erring long matches this file's stated policy: an
 * over-estimate costs a little white space, an under-estimate overlaps text.
 */
const REC_WRAP_SAFETY = 1.12;

/** Height of the wrapped body text alone. */
function recTextH(it, w) {
  const chars = String(it.text || '').length * REC_WRAP_SAFETY;
  const per   = charsPerLine(recTextW(w), REC_TEXT_PT);
  return Math.max(1, Math.ceil(chars / per)) * lineH(REC_TEXT_PT);
}

/** Full height of one recommendation item, excluding the gap after it. */
function recItemH(it, w) {
  return (it.area ? REC_AREA_H : 0) +
         recTextH(it, w) +
         (it.impact ? REC_IMPACT_H : 0) +
         REC_PAD;
}

function measure(b, w) {
  const W = w || BODY_W;
  const T = TYPE;
  switch (b.type) {
    case 'subhead': return lineH(T.subhead) + 0.18;   // text + rule + clearance
    case 'caption': return lineH(T.body) + 0.06;
    case 'text':    return lineCount(b.text, W, T.body) * lineH(T.body) + pad(T.body);
    case 'note':    return lineCount(b.text, W, T.note) * lineH(T.note) + pad(T.note);
    case 'prose':
      return b.paras.reduce((h, p) =>
        h + lineCount(p, W, T.body) * lineH(T.body) + pad(T.body) * 1.6, 0);
    case 'bullets':
      return b.items.reduce((h, i) =>
        h + lineCount(i, W - 0.3, T.body) * lineH(T.body) + pad(T.body), 0);
    case 'table':
      return HEAD_H * Math.max(1, b.head.length) + b.rows.length * ROW_H + 0.12;
    case 'tiles':
      return Math.ceil(b.items.length / tilesPerRow(b.items.length)) *
             ((b.compact ? TILE_H_COMPACT : TILE_H) + 0.12);
    case 'meters':  return 1.34;
    case 'ccgroups':
      return Math.max.apply(null, b.groups.map(g => g.items.length * CC_ROW_H + 0.46));
    case 'heatmap': return 4.35;
    case 'bars':    return Math.max(b.items.length * BAR_ROW_H + 0.30,
                             (b.side || []).length * 0.32 + (b.total ? 0.95 : 0.30));
    case 'stacked': return 2.75;
    case 'qa':      return b.items.reduce((h, i) =>
                      h + lineCount(i.q, W, T.body) * lineH(T.body) +
                          lineCount(i.a, W, T.body) * lineH(T.body) + 0.24, 0);
    // One height function, shared with drawRecs — see recItemH().
    case 'recs':    return b.items.reduce((h, i) => h + recItemH(i, W) + REC_GAP, 0);
    case 'columns':
      return Math.max.apply(null, b.cols.map(c =>
        0.56 + c.blocks.reduce((h, x) => h + measure(x, W / b.cols.length - 0.3) + GAP, 0)));
    case 'comment': return 0.36 + lineCount(b.text, W - 0.4, T.body) * lineH(T.body) + 0.24;
    case 'quote':   return 0.30 + lineCount(b.text, W - 1.2, T.subhead) * lineH(T.subhead) + 1.10;
    case 'legend':  return 0.34;
    default:        return 0.25;
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 3. PAGINATE — pack blocks onto slides
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Split a table that cannot fit the space left, repeating its header on the
 * continuation. A table too tall even for a whole empty slide keeps splitting,
 * so there is no input that silently loses rows.
 */
function splitTable(b, avail) {
  const room = avail - HEAD_H * Math.max(1, b.head.length) - 0.12;
  let fit = Math.floor(room / ROW_H);
  if (fit < 2) return null;                      // not worth a two-row stub
  if (fit >= b.rows.length) return null;         // no split needed

  // Never strand a single row under a repeated header on the next slide — it
  // reads as a mistake. Pull one row forward so the continuation carries two.
  if (b.rows.length - fit === 1 && fit > 2) fit -= 1;

  return [
    Object.assign({}, b, { rows: b.rows.slice(0, fit) }),
    Object.assign({}, b, { rows: b.rows.slice(fit) }),
  ];
}

/** Same idea for the list-shaped blocks. */
function splitList(b, avail, key) {
  const items = b[key] || [];
  if (items.length < 2) return null;
  let h = 0, fit = 0;
  for (let i = 0; i < items.length; i++) {
    const one = { ...b };
    one[key] = [items[i]];
    const oneH = measure(one, BODY_W);
    if (h + oneH > avail) break;
    h += oneH; fit++;
  }
  if (fit < 1 || fit >= items.length) return null;
  const headPart = { ...b }; headPart[key] = items.slice(0, fit);
  const tailPart = { ...b }; tailPart[key] = items.slice(fit);
  return [headPart, tailPart];
}

const SPLITTABLE = { bullets: 'items', qa: 'items', recs: 'items', prose: 'paras' };

/**
 * Pack one section's blocks into pages. A sub-heading is never left stranded at
 * the foot of a slide with its content on the next one.
 */
function paginate(blocks) {
  const pages = [];
  let page = [], used = 0;
  const flush = () => { if (page.length) pages.push(page); page = []; used = 0; };

  const queue = blocks.slice();
  let guard = 0;
  while (queue.length && guard++ < 800) {
    const b = queue.shift();
    const h = measure(b, BODY_W);
    const avail = BODY_H - used;

    if (h <= avail) {
      const isHeading = b.type === 'subhead' || b.type === 'caption';
      if (isHeading && queue.length && avail - h < 0.9) { flush(); queue.unshift(b); continue; }
      page.push(b); used += h + GAP;
      continue;
    }

    if (b.type === 'table') {
      const parts = splitTable(b, avail);
      if (parts) { page.push(parts[0]); flush(); queue.unshift(parts[1]); continue; }
    }
    if (SPLITTABLE[b.type]) {
      const parts = splitList(b, avail, SPLITTABLE[b.type]);
      if (parts) { page.push(parts[0]); flush(); queue.unshift(parts[1]); continue; }
    }

    if (page.length) { flush(); queue.unshift(b); continue; }

    // Taller than an entire empty slide and unsplittable — place it anyway
    // rather than dropping it. Only the fixed-size visuals can reach here.
    page.push(b); used += h + GAP;
  }
  flush();
  return pages.length ? pages : [[]];
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 4. RENDER — blocks to PowerPoint shapes
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Shrink a headline figure until it fits its tile rather than letting it clip. */
function fitFont(str, widthIn, base, min) {
  let pt = base;
  while (pt > min && lineCount(str, widthIn, pt) > 1) pt -= 1;
  return pt;
}

function drawBlock(slide, b, y) {
  switch (b.type) {
    case 'subhead':  drawSubhead(slide, b, y);  break;
    case 'caption':  drawCaption(slide, b, y);  break;
    case 'text':     drawPara(slide, b.text, y, 10, P.INK); break;
    case 'note':     drawPara(slide, b.text, y, 9, P.MUTED); break;
    case 'prose':    drawProse(slide, b, y);    break;
    case 'bullets':  drawBullets(slide, b, y);  break;
    case 'table':    drawTable(slide, b, y);    break;
    case 'tiles':    drawTiles(slide, b, y);    break;
    case 'meters':   drawMeters(slide, b, y);   break;
    case 'ccgroups': drawCcGroups(slide, b, y); break;
    case 'heatmap':  drawHeatMap(slide, b, y);  break;
    case 'bars':     drawBars(slide, b, y);     break;
    case 'stacked':  drawStacked(slide, b, y);  break;
    case 'qa':       drawQa(slide, b, y);       break;
    case 'recs':     drawRecs(slide, b, y);     break;
    case 'columns':  drawColumns(slide, b, y);  break;
    case 'comment':  drawComment(slide, b, y);  break;
    case 'quote':    drawQuote(slide, b, y);    break;
    case 'legend':   drawLegend(slide, b, y);   break;
    default: break;
  }
  return measure(b, BODY_W) + GAP;
}

function drawSubhead(slide, b, y) {
  // The rule sits UNDER the text, so its offset has to follow the type size.
  // Pinned to a constant 0.28in it cut straight through the descenders once the
  // subhead grew to the brand's scale.
  const h = lineH(TYPE.subhead);
  slide.addText(b.text, {
    x: MARGIN, y, w: BODY_W, h, fontFace: FONT, fontSize: TYPE.subhead,
    bold: true, color: P.NAVY, valign: 'top', margin: 0,
  });
  slide.addShape('rect', {
    x: MARGIN, y: y + h + 0.03, w: 1.1, h: 0.022,
    fill: { color: P.BLUE }, line: { type: 'none' },
  });
}

function drawCaption(slide, b, y) {
  slide.addText(b.text, {
    x: MARGIN, y, w: BODY_W, h: 0.24, fontFace: FONT, fontSize: TYPE.tableBody,
    bold: true, color: P.MUTED,
  });
}

function drawPara(slide, str, y, pt, color) {
  slide.addText(str, {
    x: MARGIN, y, w: BODY_W, h: lineCount(str, BODY_W, pt) * 0.20,
    fontFace: FONT, fontSize: pt, color, valign: 'top', lineSpacingMultiple: 1.05,
  });
}

function drawProse(slide, b, y) {
  slide.addText(b.paras.map((p, i) => ({
    text: p,
    options: { breakLine: true, paraSpaceAfter: i < b.paras.length - 1 ? 8 : 0 },
  })), {
    x: MARGIN, y, w: BODY_W, h: measure(b, BODY_W) - 0.05,
    fontFace: FONT, fontSize: TYPE.body, color: P.INK, valign: 'top', lineSpacingMultiple: 1.12,
  });
}

function drawBullets(slide, b, y) {
  slide.addText(b.items.map(i => ({
    text: i, options: { bullet: { code: '2022' }, breakLine: true, paraSpaceAfter: 4 },
  })), {
    x: MARGIN + 0.06, y, w: BODY_W - 0.06, h: measure(b, BODY_W) - 0.05,
    fontFace: FONT, fontSize: TYPE.body, color: P.INK, valign: 'top', lineSpacingMultiple: 1.1,
  });
}

/**
 * A real PowerPoint table — selectable, restylable, copyable into Word.
 * Column widths come from the section's own colgroup; without them a long first
 * column would be squeezed to the width of a two-digit count.
 */
function drawTable(slide, b, y) {
  const cols = (b.head[0] || (b.rows[0] && b.rows[0].cells) || []).length;
  if (!cols) return;

  const widths = b.widths.length === cols
    ? b.widths.map(p => BODY_W * p / 100)
    : new Array(cols).fill(BODY_W / cols);

  // Template table: solid brand-blue header in white bold, plain white body
  // rows — no zebra striping — separated by light blue hairlines. The first
  // column stays left-aligned so names remain scannable; everything else is
  // centred, as the reference deck does it.
  const rows = [];
  b.head.forEach((hr) => {
    rows.push(hr.map((c, i) => ({
      text: c.text,
      options: {
        fill: P.BLUE, color: P.WHITE, bold: true, fontSize: TYPE.tableBody,
        align: 'center', valign: 'middle', fontFace: FONT,
      },
    })));
  });
  b.rows.forEach((r) => {
    rows.push(r.cells.map((c, i) => ({
      text: c.text,
      options: {
        color: c.tone || P.INK,
        bold: !!c.bold,
        fontSize: TYPE.tableBody,
        align: i === 0 && !c.num ? 'left' : 'center',
        valign: 'middle',
        fontFace: FONT,
        fill: r.total ? 'EAF3FB' : P.WHITE,
      },
    })));
  });

  slide.addTable(rows, {
    x: MARGIN, y, w: BODY_W, colW: widths, rowH: ROW_H,
    border: { type: 'solid', color: P.TABLE_BORDER, pt: 0.75 }, autoPage: false,
  });
}

function drawTiles(slide, b, y) {
  const per = tilesPerRow(b.items.length);
  const gap = 0.16;
  const tw  = (BODY_W - gap * (per - 1)) / per;
  const th  = b.compact ? TILE_H_COMPACT : TILE_H;

  b.items.forEach((item, i) => {
    const col = i % per, row = Math.floor(i / per);
    const x  = MARGIN + col * (tw + gap);
    const ty = y + row * (th + 0.12);

    slide.addShape('roundRect', {
      x, y: ty, w: tw, h: th, rectRadius: 0.06,
      fill: { color: P.CARD }, line: { color: 'E2E6EC', width: 0.75 },
    });
    slide.addShape('rect', {
      x, y: ty, w: tw, h: 0.045,
      fill: { color: item.tone || P.BLUE }, line: { type: 'none' },
    });
    slide.addText(item.value || '—', {
      x: x + 0.08, y: ty + 0.11, w: tw - 0.16, h: 0.40,
      fontFace: FONT, fontSize: fitFont(item.value || '', tw - 0.24, TYPE.bigNumber, TYPE.tableBody),
      bold: true, color: item.muted ? P.MUTED : (item.tone || P.NAVY),
      align: 'center', valign: 'middle',
    });
    // Labels are long ("Security incidents this period (4 MDR, 5 logged)") and
    // were spilling out of the bottom of the card. Shrink the type once the
    // label needs a third line rather than letting it escape the tile.
    const labelW = tw - 0.14;
    const lines  = lineCount(item.label || '', labelW, TYPE.tileLabel);
    slide.addText(item.label || '', {
      x: x + 0.07, y: ty + 0.50, w: labelW, h: th - 0.54,
      fontFace: FONT, fontSize: lines > 2 ? TYPE.footer : TYPE.tileLabel,
      color: P.MUTED, align: 'center', valign: 'top', lineSpacingMultiple: 0.92,
    });
  });
}

/** Weighted component cards: label, weight, score and a proportional bar. */
function drawMeters(slide, b, y) {
  const per = b.items.length || 1;
  const gap = 0.18;
  const w = (BODY_W - gap * (per - 1)) / per;

  b.items.forEach((m, i) => {
    const x = MARGIN + i * (w + gap);
    slide.addShape('roundRect', {
      x, y, w, h: 1.30, rectRadius: 0.06,
      fill: { color: P.CARD }, line: { color: 'E2E6EC', width: 0.75 },
    });
    slide.addText(
      [{ text: m.label, options: { bold: true, color: P.NAVY, fontSize: TYPE.body } },
       { text: m.weight ? '  ' + m.weight : '', options: { color: P.MUTED, fontSize: TYPE.note } }],
      { x: x + 0.12, y: y + 0.10, w: w - 0.24, h: 0.26, fontFace: FONT, valign: 'middle' });

    slide.addShape('rect', {
      x: x + 0.12, y: y + 0.44, w: w - 0.24, h: 0.15,
      fill: { color: P.TRACK }, line: { type: 'none' },
    });
    if (m.pct > 0) {
      slide.addShape('rect', {
        x: x + 0.12, y: y + 0.44, w: (w - 0.24) * Math.min(100, m.pct) / 100, h: 0.15,
        fill: { color: m.tone }, line: { type: 'none' },
      });
    }
    slide.addText(m.value || '', {
      x: x + 0.12, y: y + 0.63, w: w - 0.24, h: 0.24,
      fontFace: FONT, fontSize: TYPE.body, bold: true, color: P.INK,
    });
    slide.addText(m.sub || '', {
      x: x + 0.12, y: y + 0.85, w: w - 0.24, h: 0.26,
      fontFace: FONT, fontSize: TYPE.footer, color: P.MUTED, valign: 'top',
    });
  });
}

function drawCcGroups(slide, b, y) {
  const per = b.groups.length || 1;
  const gap = 0.24;
  const w = (BODY_W - gap * (per - 1)) / per;

  b.groups.forEach((g, gi) => {
    const x = MARGIN + gi * (w + gap);
    slide.addText(g.heading, {
      x, y, w, h: 0.26, fontFace: FONT, fontSize: TYPE.body, bold: true, color: P.NAVY,
    });
    g.items.forEach((it, i) => {
      const iy = y + 0.36 + i * CC_ROW_H;
      slide.addText(
        [{ text: it.label, options: { color: P.INK } }]
          .concat(it.note ? [{ text: '  ' + it.note, options: { color: P.FOOT, fontSize: TYPE.footer } }] : []),
        {
          x, y: iy, w: w * 0.62, h: 0.26, fontFace: FONT, fontSize: TYPE.tableBody,
          valign: 'middle',
        });
      slide.addText(it.value, {
        x: x + w * 0.62, y: iy, w: w * 0.38, h: 0.26, fontFace: FONT, fontSize: TYPE.tableBody,
        bold: true, color: it.tone || P.INK, align: 'right', valign: 'middle',
      });
      slide.addShape('rect', {
        x, y: iy + 0.27, w, h: 0.006, fill: { color: 'E8ECF1' }, line: { type: 'none' },
      });
    });
  });
}

/**
 * The 5x5 heat map as a native table with per-cell fills. Empty cells keep the
 * band colour at low opacity in HTML; PowerPoint table cells have no opacity, so
 * the tint is pre-blended against white instead.
 */
function drawHeatMap(slide, b, y) {
  const cells = (b.rows[0] && b.rows[0].cells.length) || 5;
  const side = 0.72, labW = 0.34;
  const gridW = labW + cells * side;
  const x0 = MARGIN + Math.max(0, (BODY_W - gridW) / 2);

  slide.addText(b.yTitle || 'Likelihood', {
    x: x0 - 1.05, y: y + (cells * side) / 2 - 0.15, w: 1.5, h: 0.3,
    fontFace: FONT, fontSize: TYPE.tableBody, bold: true, color: P.MUTED,
    align: 'center', rotate: 270,
  });

  const rows = b.rows.map(r => [{
    text: r.label,
    options: { fill: P.WHITE, color: P.MUTED, bold: true, fontSize: TYPE.note,
      align: 'center', valign: 'middle', fontFace: FONT },
  }].concat(r.cells.map(c => ({
    text: c.n || '',
    options: {
      fill: c.faded ? blend(c.fill, 0.22) : c.fill,
      color: c.n ? P.WHITE : P.MUTED,
      bold: true, fontSize: TYPE.subhead, align: 'center', valign: 'middle', fontFace: FONT,
    },
  }))));

  slide.addTable(rows, {
    x: x0, y, w: gridW, colW: [labW].concat(new Array(cells).fill(side)),
    rowH: side, border: { type: 'solid', color: P.WHITE, pt: 1.5 }, autoPage: false,
  });

  const axisY = y + b.rows.length * side + 0.06;
  (b.xLabels || []).forEach((l, i) => {
    slide.addText(l, {
      x: x0 + labW + i * side, y: axisY, w: side, h: 0.24,
      fontFace: FONT, fontSize: TYPE.note, color: P.MUTED, align: 'center',
    });
  });
  slide.addText(b.xTitle || 'Impact', {
    x: x0 + labW, y: axisY + 0.24, w: cells * side, h: 0.26,
    fontFace: FONT, fontSize: TYPE.tableBody, bold: true, color: P.MUTED, align: 'center',
  });
}

/** Pre-blend a colour toward white — PowerPoint table cells have no opacity. */
function blend(hex, alpha) {
  const n = parseInt(hex, 16);
  if (!isFinite(n)) return 'FFFFFF';
  const mix = (c) => Math.round(c * alpha + 255 * (1 - alpha));
  const r = mix((n >> 16) & 255), g = mix((n >> 8) & 255), b2 = mix(n & 255);
  return ((1 << 24) + (r << 16) + (g << 8) + b2).toString(16).slice(1).toUpperCase();
}

function drawBars(slide, b, y) {
  const hasSide = !!(b.total || (b.side && b.side.length));
  const barsW = hasSide ? BODY_W * 0.68 : BODY_W;
  const nameW = Math.min(3.2, barsW * 0.34);
  const trackW = barsW - nameW - 0.7;

  b.items.forEach((it, i) => {
    const iy = y + i * BAR_ROW_H;
    slide.addText(it.name, {
      x: MARGIN, y: iy, w: nameW, h: 0.3, fontFace: FONT, fontSize: TYPE.tableBody,
      color: P.INK, valign: 'middle',
    });
    slide.addShape('rect', {
      x: MARGIN + nameW, y: iy + 0.07, w: trackW, h: 0.17,
      fill: { color: P.TRACK }, line: { type: 'none' },
    });
    if (it.pct > 0) {
      slide.addShape('rect', {
        x: MARGIN + nameW, y: iy + 0.07, w: trackW * Math.min(100, it.pct) / 100,
        h: 0.17, fill: { color: it.tone }, line: { type: 'none' },
      });
    }
    slide.addText(it.value, {
      x: MARGIN + nameW + trackW + 0.08, y: iy, w: 0.6, h: 0.3,
      fontFace: FONT, fontSize: TYPE.tableBody, bold: true, color: P.INK, valign: 'middle',
    });
  });

  if (!hasSide) return;
  const sx = MARGIN + barsW + 0.3;
  const sw = BODY_W - barsW - 0.3;
  if (b.total) {
    slide.addText(b.total, {
      x: sx, y, w: sw, h: 0.44, fontFace: FONT, fontSize: TYPE.bigNumber, bold: true,
      color: P.NAVY, align: 'center',
    });
    slide.addText(b.totalLabel || '', {
      x: sx, y: y + 0.44, w: sw, h: 0.24, fontFace: FONT, fontSize: TYPE.note,
      color: P.MUTED, align: 'center',
    });
  }
  b.side.forEach((s, i) => {
    const iy = y + 0.82 + i * 0.32;
    slide.addText(s.label, {
      x: sx, y: iy, w: sw * 0.6, h: 0.26, fontFace: FONT, fontSize: TYPE.tableBody,
      color: s.tone || P.INK, valign: 'middle',
    });
    slide.addText(s.value, {
      x: sx + sw * 0.6, y: iy, w: sw * 0.4, h: 0.26, fontFace: FONT, fontSize: TYPE.tableBody,
      bold: true, color: P.INK, align: 'right', valign: 'middle',
    });
  });
}

/**
 * Proportional stacked columns. The HTML records each segment as a percentage
 * height, so the shape of the trend is recoverable but the absolute counts are
 * not — this is drawn without a value axis it cannot honestly label.
 */
function drawStacked(slide, b, y) {
  const n = b.cols.length || 1;
  const gap = 0.10;
  const cw = Math.min(0.72, (BODY_W - gap * (n - 1)) / n);
  const totalW = cw * n + gap * (n - 1);
  const x0 = MARGIN + Math.max(0, (BODY_W - totalW) / 2);
  const chartH = 2.2;

  b.cols.forEach((c, i) => {
    const x = x0 + i * (cw + gap);
    slide.addShape('rect', {
      x, y, w: cw, h: chartH, fill: { color: 'F2F4F7' }, line: { type: 'none' },
    });
    let top = y + chartH;
    c.segs.forEach((s) => {
      const sh = chartH * s.pct / 100;
      top -= sh;
      slide.addShape('rect', {
        x, y: top, w: cw, h: sh, fill: { color: s.tone }, line: { type: 'none' },
      });
    });
    slide.addText(c.label || '', {
      x, y: y + chartH + 0.04, w: cw, h: 0.24,
      fontFace: FONT, fontSize: TYPE.note, color: P.MUTED, align: 'center',
    });
  });
}

function drawQa(slide, b, y) {
  let cy = y;
  b.items.forEach((it) => {
    const qh = lineCount(it.q, BODY_W - 0.1, 10) * 0.20;
    slide.addText(
      [{ text: it.ref ? it.ref + '  ' : '', options: { color: P.BLUE, bold: true } },
       { text: it.q, options: { color: P.NAVY, bold: true } }],
      { x: MARGIN, y: cy, w: BODY_W, h: qh, fontFace: FONT, fontSize: TYPE.tableBody, valign: 'top' });
    cy += qh + 0.02;
    const ah = lineCount(it.a, BODY_W - 0.2, 10) * 0.20;
    slide.addText(it.a, {
      x: MARGIN + 0.16, y: cy, w: BODY_W - 0.16, h: ah,
      fontFace: FONT, fontSize: TYPE.tableBody, color: P.INK, valign: 'top',
    });
    cy += ah + 0.20;
  });
}

function drawRecs(slide, b, y) {
  let cy = y;
  const tw = recTextW(BODY_W);

  b.items.forEach((it) => {
    // Both from recItemH()'s parts, so what is drawn is exactly what was
    // measured. The stacking offsets below are derived from the same
    // constants rather than re-typed, which is how they came apart before.
    const th = recTextH(it, BODY_W);
    const h  = recItemH(it, BODY_W);
    const textY = cy + (it.area ? REC_AREA_H : 0);

    slide.addShape('rect', {
      x: MARGIN, y: cy, w: 0.05, h, fill: { color: it.tone || P.BLUE }, line: { type: 'none' },
    });
    if (it.area) {
      slide.addText(it.area, {
        x: MARGIN + REC_INSET, y: cy, w: tw, h: REC_AREA_H,
        fontFace: FONT, fontSize: TYPE.note, bold: true, color: P.BLUE,
      });
    }
    slide.addText(it.text || '', {
      x: MARGIN + REC_INSET, y: textY, w: tw, h: th,
      fontFace: FONT, fontSize: REC_TEXT_PT, color: P.INK, valign: 'top',
    });
    if (it.impact) {
      slide.addText(it.impact, {
        x: MARGIN + REC_INSET, y: textY + th, w: tw, h: REC_IMPACT_H,
        fontFace: FONT, fontSize: TYPE.note, color: P.MUTED,
      });
    }
    if (it.chip) {
      // Right-aligned against the body edge, inside the gutter recTextW()
      // reserved — so a long chip can never sit on top of the text.
      const chipX = MARGIN + BODY_W - REC_CHIP_W;
      slide.addShape('roundRect', {
        x: chipX, y: cy + 0.02, w: REC_CHIP_W, h: 0.28, rectRadius: 0.05,
        fill: { color: it.tone || P.BLUE }, line: { type: 'none' },
      });
      slide.addText(it.chip, {
        x: chipX, y: cy + 0.02, w: REC_CHIP_W, h: 0.28,
        fontFace: FONT, fontSize: TYPE.note, bold: true, color: P.WHITE,
        align: 'center', valign: 'middle',
      });
    }
    cy += h + REC_GAP;
  });
}

function drawColumns(slide, b, y) {
  const n = b.cols.length || 1;
  const gap = 0.3;
  const w = (BODY_W - gap * (n - 1)) / n;

  b.cols.forEach((c, i) => {
    const x = MARGIN + i * (w + gap);
    let cy = y;
    if (c.heading) {
      slide.addText(c.heading, {
        x, y: cy, w, h: 0.26, fontFace: FONT, fontSize: TYPE.body, bold: true, color: P.NAVY,
      });
      cy += 0.28;
    }
    if (c.sub) {
      slide.addText(c.sub, {
        x, y: cy, w, h: 0.22, fontFace: FONT, fontSize: TYPE.note, color: P.MUTED,
      });
      cy += 0.24;
    }
    c.blocks.forEach((blk) => { cy += drawIn(slide, blk, x, cy, w); });
  });
}

/** Draw a block inside an arbitrary column box rather than the full body width. */
function drawIn(slide, b, x, y, w) {
  const h = measure(b, w);
  if (b.type === 'table') {
    const cols = (b.head[0] || (b.rows[0] && b.rows[0].cells) || []).length;
    if (!cols) return h + GAP;
    const widths = b.widths.length === cols
      ? b.widths.map(p => w * p / 100) : new Array(cols).fill(w / cols);
    const rows = [];
    b.head.forEach(hr => rows.push(hr.map(c => ({
      text: c.text,
      options: { fill: P.BLUE, color: P.WHITE, bold: true, fontSize: TYPE.note,
        align: 'center', valign: 'middle', fontFace: FONT },
    }))));
    b.rows.forEach((r, i) => rows.push(r.cells.map(c => ({
      text: c.text,
      options: { color: c.tone || P.INK, bold: !!c.bold, fontSize: TYPE.footer,
        align: i === 0 && !c.num ? 'left' : 'center', valign: 'middle', fontFace: FONT,
        fill: P.WHITE },
    }))));
    slide.addTable(rows, {
      x, y, w, colW: widths, rowH: ROW_H - 0.03,
      border: { type: 'solid', color: P.TABLE_BORDER, pt: 0.75 }, autoPage: false,
    });
    return h + GAP;
  }
  const str = b.text || (b.paras || []).join('  ') || (b.items || []).join('  ');
  if (str) {
    slide.addText(str, {
      x, y, w, h, fontFace: FONT, fontSize: b.type === 'note' ? TYPE.note : TYPE.tableBody,
      color: b.type === 'note' ? P.MUTED : P.INK, valign: 'top',
    });
  }
  return h + GAP;
}

function drawComment(slide, b, y) {
  const h = measure(b, BODY_W);
  slide.addShape('rect', {
    x: MARGIN, y, w: BODY_W, h, fill: { color: 'F2F7FC' }, line: { type: 'none' },
  });
  slide.addShape('rect', {
    x: MARGIN, y, w: 0.05, h, fill: { color: P.BLUE }, line: { type: 'none' },
  });
  slide.addText(b.label, {
    x: MARGIN + 0.18, y: y + 0.06, w: BODY_W - 0.3, h: 0.22,
    fontFace: FONT, fontSize: TYPE.note, bold: true, color: P.BLUE,
  });
  slide.addText(b.text, {
    x: MARGIN + 0.18, y: y + 0.28, w: BODY_W - 0.36, h: h - 0.34,
    fontFace: FONT, fontSize: TYPE.tableBody, color: P.INK, valign: 'top',
  });
}

function drawQuote(slide, b, y) {
  const th = lineCount(b.text, BODY_W - 1.2, 12) * 0.26;
  slide.addShape('rect', {
    x: MARGIN, y, w: 0.06, h: th + 0.2, fill: { color: P.BLUE }, line: { type: 'none' },
  });
  slide.addText(b.text, {
    x: MARGIN + 0.3, y, w: BODY_W - 0.6, h: th + 0.2,
    fontFace: FONT, fontSize: TYPE.body, italic: true, color: P.INK,
    valign: 'top', lineSpacingMultiple: 1.15,
  });
  const sy = y + th + 0.55;
  slide.addShape('rect', {
    x: MARGIN + 0.3, y: sy, w: 3.0, h: 0.012, fill: { color: P.RULE }, line: { type: 'none' },
  });
  [[b.by, TYPE.body, true, P.NAVY], [b.role, TYPE.tableBody, false, P.MUTED],
   [b.date, TYPE.tableBody, false, P.MUTED]]
    .filter(r => r[0]).forEach((r, i) => {
      slide.addText(r[0], {
        x: MARGIN + 0.3, y: sy + 0.08 + i * 0.24, w: 5, h: 0.24,
        fontFace: FONT, fontSize: r[1], bold: r[2], color: r[3],
      });
    });
}

function drawLegend(slide, b, y) {
  // Two things wrapped legend keys onto two lines: a guessed 0.062in-per-char
  // width, and PowerPoint's default 0.1in inset on EVERY side of a text box,
  // which quietly removes 0.2in of the usable measure. Size from the same
  // estimator the layout uses and zero the inset, so the box is the text box.
  const PT = TYPE.note;
  let x = MARGIN;
  b.keys.forEach((k) => {
    slide.addShape('rect', {
      x, y: y + 0.06, w: 0.16, h: 0.16, fill: { color: k.tone }, line: { type: 'none' },
    });
    const w = Math.max(0.55, (k.label || '').length * PT * 0.0071 + 0.14);
    slide.addText(k.label, {
      x: x + 0.22, y, w, h: 0.28, fontFace: FONT, fontSize: PT,
      color: P.MUTED, valign: 'middle', margin: 0, wrap: false,
    });
    x += 0.22 + w + 0.18;
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 5. SLIDE CHROME — the Reflex deck template
 *
 * Matched to the reference template rather than invented:
 *
 *   Cover / closing   full-bleed brand blue, the knot mark as an oversized
 *                     watermark bleeding off the top-right, the white
 *                     horizontal lockup top-left, a white headline with a dark
 *                     slate second line.
 *   Content           white, dark slate title top-left, blue lockup top-right,
 *                     a heavy slate rule under both.
 *   Every slide       the footer bar: three dots of increasing size, the date,
 *                     a long rule, and the page number hard right.
 *
 * The static parts live on slide masters so the logo and watermark are each
 * embedded once rather than once per slide.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Footer bar, measured off the reference deck (inches). */
const FOOT_CY    = 7.27;          // vertical centre of the whole bar
const DOTS       = [
  { cx: 0.60, r: 0.075 },
  { cx: 1.00, r: 0.075 },
  { cx: 1.45, r: 0.105 },         // the third is deliberately larger
];
const FOOT_DATE_X = 1.72;
const FOOT_RULE   = { x: 2.90, w: 9.40 };
const FOOT_PAGE_X = 12.40;

/* Title block on content slides. */
const RULE_Y     = 1.02;
const RULE_H     = 0.045;
const LOGO_H     = 0.42;          // content slides; the cover's is larger

/** Only a real data: image URI may reach addImage — anything else is dropped. */
function stripDataUri(uri) {
  return typeof uri === 'string' && /^data:image\/(png|jpeg|jpg|gif);base64,/.test(uri)
    ? uri : null;
}

const MASTER_COVER   = 'REFLEX_COVER';
const MASTER_CONTENT = 'REFLEX_CONTENT';
// The closing slide reuses the cover master — identical chrome, different copy.
const MASTER_CLOSING = MASTER_COVER;

/**
 * The footer bar as master objects, tinted for a light or dark ground.
 *
 * The dots are NOT here. A slide master accepts only chart, image, line, rect,
 * text and placeholder objects — an `ellipse` is silently rendered as a rect,
 * which put three squares in the footer of every slide. They are drawn per
 * slide by footerDots() instead.
 */
function footerObjects(ctx, onBlue) {
  const rule  = onBlue ? '5CA9DF' : P.BLUE;
  const text  = onBlue ? 'BBD9F5' : P.FOOT;

  const objs = [];

  if (ctx.dateStr) {
    objs.push({ text: {
      text: ctx.dateStr,
      options: {
        x: FOOT_DATE_X, y: FOOT_CY - 0.14, w: 1.05, h: 0.28,
        fontFace: FONT, fontSize: TYPE.tableBody, color: text, valign: 'middle', margin: 0,
      },
    } });
  }

  objs.push({ rect: {
    x: FOOT_RULE.x, y: FOOT_CY - 0.011, w: FOOT_RULE.w, h: 0.022,
    fill: { color: rule }, line: { type: 'none' },
  } });

  return objs;
}

/**
 * The knot watermark, top-right.
 *
 * Placed WHOLLY INSIDE the slide. It used to be an oversized square anchored
 * off the corner so it bled off two edges; PowerPoint clips to the slide so
 * that looked right there, but nothing guarantees clipping — in a PDF viewer
 * the mark sprawled far outside the slide on three sides. The bleed is now
 * baked into the image (see WATERMARK_CROP in lib/brand-assets.js), so the
 * result is identical and no renderer can spill it.
 *
 * Height is fixed and width derived from the image's own aspect, so a change to
 * the crop cannot silently squash the mark.
 */
const WATERMARK_H = 7.0;

function watermarkObject(brand) {
  const wm = brand && stripDataUri(brand.markWatermark);
  if (!wm) return [];
  const w = WATERMARK_H * (brand.watermarkAspect || 1);
  return [{ image: { data: wm, x: SLIDE_W - w, y: 0, w, h: WATERMARK_H } }];
}

/** The three footer dots, of increasing size. Per slide — see footerObjects(). */
function footerDots(slide, onBlue) {
  const colour = onBlue ? P.WHITE : P.BLUE;
  DOTS.forEach((d) => {
    slide.addShape('ellipse', {
      x: d.cx - d.r, y: FOOT_CY - d.r, w: d.r * 2, h: d.r * 2,
      fill: { color: colour }, line: { type: 'none' },
    });
  });
}

function defineMasters(pres, ctx, brand) {
  const logoWhite = brand && stripDataUri(brand.logoWhite);
  const logoBlue  = brand && stripDataUri(brand.logo);
  const aspect    = (brand && brand.logoAspect) || 3.43;

  // The cover and the closing slide share one master: their chrome is identical
  // and only the copy on top differs. Defining them separately embedded the
  // watermark and the white lockup twice — pptxgenjs does not dedupe identical
  // images across layouts, and those two PNGs are the largest things in the file.
  // Watermark first, so the logo and copy sit above it.
  pres.defineSlideMaster({
    title: MASTER_COVER,
    background: { color: P.BLUE },
    objects: []
      .concat(watermarkObject(brand))
      .concat(logoWhite
        ? [{ image: { data: logoWhite, x: MARGIN, y: 0.60, h: 0.52, w: 0.52 * aspect } }]
        : [])
      .concat(footerObjects(ctx, true)),
  });

  pres.defineSlideMaster({
    title: MASTER_CONTENT,
    background: { color: P.WHITE },
    objects: []
      .concat(logoBlue
        ? [{ image: {
            data: logoBlue,
            x: SLIDE_W - MARGIN - LOGO_H * aspect,
            y: RULE_Y - LOGO_H - 0.02,
            h: LOGO_H, w: LOGO_H * aspect,
          } }]
        : [])
      // The heavy slate rule the whole template hangs off.
      .concat([{ rect: {
        x: MARGIN, y: RULE_Y, w: BODY_W, h: RULE_H,
        fill: { color: P.SLATE }, line: { type: 'none' },
      } }])
      .concat(footerObjects(ctx, false)),
  });
}

function addCover(pres, ctx) {
  const s = pres.addSlide({ masterName: MASTER_COVER });
  footerDots(s, true);

  s.addText(ctx.clientName || 'Client', {
    x: MARGIN, y: 2.62, w: SLIDE_W - MARGIN * 2 - 5.2, h: 0.95,
    fontFace: FONT, fontSize: TYPE.coverTitle, bold: true, color: P.WHITE, valign: 'bottom', margin: 0,
  });
  s.addText('Cybersecurity Board Report', {
    x: MARGIN, y: 3.62, w: SLIDE_W - MARGIN * 2 - 5.2, h: 0.5,
    fontFace: FONT, fontSize: TYPE.coverSub, bold: true, color: P.SLATE, valign: 'top', margin: 0,
  });

  // The date sits between two hairlines — the template's signature detail.
  const RULE_W = 6.45;
  s.addShape('rect', {
    x: MARGIN, y: 5.34, w: RULE_W, h: 0.012,
    fill: { color: '7FB9E4' }, line: { type: 'none' },
  });
  s.addText([ctx.periodLabel, ctx.author].filter(Boolean).join('   /   ') ||
            (ctx.dateStr || ''), {
    x: MARGIN, y: 5.44, w: RULE_W, h: 0.4,
    fontFace: FONT, fontSize: TYPE.coverDate, bold: true, color: P.WHITE, valign: 'middle', margin: 0,
  });
  s.addShape('rect', {
    x: MARGIN, y: 5.90, w: RULE_W, h: 0.012,
    fill: { color: '7FB9E4' }, line: { type: 'none' },
  });

  s.addText('© Reflex™ ' + (ctx.year || new Date().getFullYear()), {
    x: SLIDE_W - MARGIN - 3, y: 6.88, w: 3, h: 0.28,
    fontFace: FONT, fontSize: TYPE.tableBody, color: 'D6E9FA', align: 'right', valign: 'middle', margin: 0,
  });

  s.addText('0', {
    x: FOOT_PAGE_X, y: FOOT_CY - 0.14, w: SLIDE_W - FOOT_PAGE_X - 0.35, h: 0.28,
    fontFace: FONT, fontSize: TYPE.tableBody, color: 'BBD9F5', align: 'right', valign: 'middle', margin: 0,
  });
  return s;
}

/** The closing slide: "Thank" in white over "You" in slate, as the template. */
function addClosing(pres, ctx, pageNo) {
  const s = pres.addSlide({ masterName: MASTER_CLOSING });
  footerDots(s, true);

  s.addText('Thank', {
    x: MARGIN, y: 2.55, w: 6, h: 1.0,
    fontFace: FONT, fontSize: TYPE.closing, bold: true, color: P.WHITE, valign: 'bottom', margin: 0,
  });
  s.addText('You', {
    x: MARGIN, y: 3.45, w: 6, h: 1.0,
    fontFace: FONT, fontSize: TYPE.closing, bold: true, color: P.SLATE, valign: 'top', margin: 0,
  });

  s.addText(String(pageNo), {
    x: FOOT_PAGE_X, y: FOOT_CY - 0.14, w: SLIDE_W - FOOT_PAGE_X - 0.35, h: 0.28,
    fontFace: FONT, fontSize: TYPE.tableBody, color: 'BBD9F5', align: 'right', valign: 'middle', margin: 0,
  });
  return s;
}

function addContentSlide(pres, ctx, title, pageNo) {
  // Logo, rule and footer bar come from MASTER_CONTENT — see defineMasters().
  // Only what changes per slide is added here.
  const s = pres.addSlide({ masterName: MASTER_CONTENT });
  footerDots(s, false);

  s.addText(title, {
    x: MARGIN, y: 0.34, w: BODY_W - LOGO_H * 3.6 - 0.4, h: 0.58,
    fontFace: FONT, fontSize: TYPE.heading, bold: true, color: P.SLATE,
    valign: 'middle', margin: 0,
  });

  s.addText(String(pageNo), {
    x: FOOT_PAGE_X, y: FOOT_CY - 0.14, w: SLIDE_W - FOOT_PAGE_X - 0.35, h: 0.28,
    fontFace: FONT, fontSize: TYPE.tableBody, color: P.FOOT, align: 'right', valign: 'middle', margin: 0,
  });
  return s;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 6. BUILD
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * buildPptx — assemble the deck.
 *
 * @param {Object} ctx       cover metadata: clientName, periodLabel, period,
 *                           author, dateStr, year, and rootDir (for the brand
 *                           marks; falls back to this file's package root)
 * @param {Array}  sections  [{ label, bodies: [htmlString, ...] }], in deck order
 * @returns {Promise<{buffer: Buffer, stats: Object}>}
 */
async function buildPptx(ctx, sections) {
  const c = ctx || {};
  const pres = new PptxGenJS();
  pres.defineLayout({ name: 'REFLEX_16x9', width: SLIDE_W, height: SLIDE_H });
  pres.layout  = 'REFLEX_16x9';
  pres.author  = c.author || 'Reflex Solutions';
  pres.company = 'Reflex Solutions (Pty) Ltd';
  pres.title   = [c.clientName, 'Cybersecurity Board Report', c.periodLabel]
    .filter(Boolean).join(' — ');

  // The horizontal lockup, its white variant and the watermark are all
  // composed from public/img/reflex-logo.png — see lib/brand-assets.js.
  const brand = brandAssets.loadBrand(c.rootDir || path.join(__dirname, '..'));

  defineMasters(pres, c, brand);
  addCover(pres, c);

  let pageNo = 1;
  const stats = { slides: 1, sections: 0, blocks: 0, unmapped: 0, skipped: [] };

  (sections || []).forEach((sec) => {
    const blocks = [];
    (sec.bodies || []).forEach((html) => {
      parseBlocks(html).forEach(b => blocks.push(b));
    });
    if (!blocks.length) { stats.skipped.push(sec.label); return; }

    stats.sections++;
    stats.blocks   += blocks.length;
    stats.unmapped += blocks.filter(b => b.type === 'text').length;

    paginate(blocks).forEach((page, i) => {
      pageNo++;
      const slide = addContentSlide(pres, c, sec.label + (i ? ' (cont.)' : ''), pageNo);
      let y = BODY_TOP;
      page.forEach((b) => { y += drawBlock(slide, b, y); });
      stats.slides++;
    });
  });

  // The template closes on a Thank You slide.
  addClosing(pres, c, pageNo + 1);
  stats.slides++;

  const raw = await pres.write({ outputType: 'nodebuffer' });
  const buffer = await deflate(Buffer.isBuffer(raw) ? raw : Buffer.from(raw));
  return { buffer, stats };
}

/**
 * Re-zip the presentation with DEFLATE.
 *
 * pptxgenjs accepts `compression: true` and then ignores it — in 4.0.1 the
 * compressed and uncompressed buffers come back byte-identical. Slide XML is
 * extremely repetitive (every text run repeats its full font block), so STORED
 * parts make the deck roughly five times larger than it needs to be: 1.4MB
 * instead of ~260KB, which is the difference between a deck that emails and one
 * that bounces.
 *
 * Entry order is preserved so [Content_Types].xml stays first, and any failure
 * falls back to the original buffer — a large deck beats no deck.
 */
async function deflate(buf) {
  try {
    const JSZip = require('jszip');
    const src = await JSZip.loadAsync(buf);
    const out = new JSZip();
    for (const name of Object.keys(src.files)) {
      const f = src.files[name];
      if (f.dir) continue;
      out.file(name, await f.async('nodebuffer'), { binary: true });
    }
    return await out.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: { level: 9 },
      mimeType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    });
  } catch (err) {
    return buf;
  }
}

module.exports = {
  buildPptx, parseBlocks, paginate, measure, blend, lineCount,
  FOOT_CY, DOTS, RULE_Y, RULE_H,
  P, FONT, SLIDE_W, SLIDE_H, BODY_W, BODY_H, BODY_TOP, MARGIN,
  // Recommendation geometry. Exported so the no-overlap invariant can be
  // asserted arithmetically instead of discovered in a client's deck — which
  // is how the last one was found.
  recTextW, recTextH, recItemH,
  REC_TEXT_PT, REC_INSET, REC_CHIP_W, REC_CHIP_GAP,
  REC_AREA_H, REC_IMPACT_H, REC_PAD, REC_GAP,
};
