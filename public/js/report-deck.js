'use strict';

/**
 * 16:9 slide-deck shell for the client-facing report.
 *
 * Owns geometry and chrome only — it knows nothing about SecOps data. The
 * per-slide bodies come from report-sections.js.
 *
 * Deliberately separate from the A4 report in tab-secure-score.js: that is a
 * flow document the printer paginates, this is fixed-geometry boxes where
 * content must not reflow. Only the primitives in report-shell.js are shared.
 */
window.ReportDeck = (function () {

  var S = window.ReportShell;
  var P = S.PALETTE;

  // 16:9 at a printable size. 338.7mm x 190.5mm is the PowerPoint default.
  var SLIDE_W = '338.7mm';
  var SLIDE_H = '190.5mm';

  var DECK_CSS = [
'*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}',
'html,body{background:#fff}',
'body{font-family:"Segoe UI",Arial,Helvetica,sans-serif;color:' + P.DECK_INK + ';-webkit-font-smoothing:antialiased}',

'@page{size:' + SLIDE_W + ' ' + SLIDE_H + ';margin:0}',

'.slide{position:relative;overflow:hidden;width:' + SLIDE_W + ';height:' + SLIDE_H + ';',
'  background:#fff;padding:15mm 18mm 12mm;display:flex;flex-direction:column;',
'  page-break-after:always;break-after:page;page-break-inside:avoid;break-inside:avoid}',
/* Without this Chrome emits a trailing blank page after the final slide. */
'.slide:last-of-type{page-break-after:auto;break-after:auto}',

/* header */
'.sl-head{display:flex;justify-content:space-between;align-items:flex-start;flex:0 0 auto;gap:10mm}',
'.sl-title{font-size:30pt;font-weight:800;color:' + P.DECK_BLUE + ';line-height:1.05;letter-spacing:-.4pt}',
'.sl-rule{height:2.5pt;background:' + P.DECK_BLUE + ';margin-top:3.5mm}',
'.sl-logo{height:13mm;width:auto;flex:0 0 auto;align-self:flex-start}',
'.sl-body{flex:1 1 auto;padding-top:6mm;min-height:0;overflow:hidden}',

/* footer */
'.sl-foot{flex:0 0 auto;display:flex;align-items:center;gap:3mm;font-size:8.5pt;',
'  color:' + P.DECK_FOOT + ';padding-top:4mm}',
'.sl-dots{display:flex;align-items:center;gap:1.6mm;flex:0 0 auto}',
'.sl-dot{width:1.5mm;height:1.5mm;border-radius:50%;background:' + P.DECK_BLUE + '}',
'.sl-dot.lg{width:2.9mm;height:2.9mm}',
'.sl-foot-rule{flex:1 1 auto;height:.5pt;background:#BFBFBF}',
'.sl-page{flex:0 0 auto}',

/* cover */
'.slide.cover{background:' + P.DECK_BLUE + ';padding:0;color:#fff}',
'.cover-inner{position:relative;z-index:2;height:100%;padding:15mm 18mm 12mm;',
'  display:flex;flex-direction:column}',
'.cover-wm{position:absolute;top:-34mm;right:-30mm;width:132mm;height:132mm;opacity:.07;',
'  z-index:1;pointer-events:none}',
'.cover-copy{position:absolute;right:18mm;bottom:19mm;font-size:8.5pt;',
'  color:rgba(255,255,255,.85);z-index:3}',
/* align-self is load-bearing: .cover-inner is a column flex container, so the
   default align-items:stretch would blow the logo out to the full slide width
   and destroy its aspect ratio. reflex-logo.png is a stacked lockup (~1.27:1)
   with an alpha channel, so brightness(0) invert(1) yields a clean white mark. */
'.cover-logo{height:16mm;width:auto;flex:0 0 auto;align-self:flex-start;',
'  filter:brightness(0) invert(1)}',
'.cover-mid{margin-top:auto;margin-bottom:auto;padding-right:40mm}',
'.cover-title{font-size:50pt;font-weight:800;line-height:1.03;color:#fff;letter-spacing:-1.1pt}',
'.cover-sub{font-size:20pt;font-weight:700;color:' + P.DECK_NAVY + ';margin-top:6mm;line-height:1.15}',
'.cover-hr{width:78mm;height:1pt;background:rgba(255,255,255,.8);margin:11mm 0 5mm}',
'.cover-author{font-size:13.5pt;font-weight:700;color:#fff}',
'.cover-hr2{width:78mm;height:1pt;background:rgba(255,255,255,.8);margin:5mm 0 0}',
'.slide.cover .sl-foot{color:rgba(255,255,255,.85)}',
'.slide.cover .sl-dot{background:rgba(255,255,255,.55)}',
'.slide.cover .sl-dot.lg{background:rgba(255,255,255,.9)}',
'.slide.cover .sl-foot-rule{background:rgba(255,255,255,.45)}',

/* overview cards */
'.ov-row{display:grid;gap:6mm}',
'.ov-row.top{grid-template-columns:repeat(2,1fr);margin-bottom:6mm}',
'.ov-row.bot{grid-template-columns:repeat(3,1fr)}',
/* Single row of three. The row is centred in the slide body and each card
   centres its own content, so three tiles don't read as a top-heavy strip with
   the values stranded at the bottom. */
'.ov-stack{height:100%;display:flex;flex-direction:column;justify-content:center;gap:7mm}',
'.ov-row.three{grid-template-columns:repeat(3,1fr)}',
'.ov-row.three .ov-card{min-height:58mm}',

/* Secure Score component breakdown (mirrors the cards on the Secure Score tab) */
'.cmp-row{display:grid;grid-template-columns:repeat(3,1fr);gap:6mm}',
'.cmp-card{border:.5pt solid #D6E4F0;border-radius:1.5mm;padding:5mm 5.5mm}',
'.cmp-head{display:flex;align-items:baseline;justify-content:space-between;gap:3mm}',
'.cmp-t{font-size:12pt;font-weight:600;color:' + P.DECK_INK + '}',
'.cmp-w{font-size:9pt;color:' + P.DECK_MUTED + '}',
'.cmp-bar{margin:3mm 0 2.5mm;height:2.4mm;border-radius:1.2mm;background:#E6ECF2;overflow:hidden}',
'.cmp-fill{height:100%;border-radius:1.2mm}',
'.cmp-score{font-size:19pt;font-weight:700;color:' + P.DECK_INK + ';line-height:1}',
'.cmp-d{margin-top:2mm;font-size:8.5pt;color:' + P.DECK_MUTED + ';line-height:1.4}',
'.ov-card{background:' + P.DECK_CARD + ';border-radius:1.5mm;padding:6mm 6mm 5mm;',
'  display:flex;flex-direction:column;min-height:0}',
'.ov-ico{width:8.5mm;height:8.5mm;color:' + P.DECK_BLUE + ';margin-bottom:3mm;flex:0 0 auto}',
'.ov-t{font-size:15pt;font-weight:600;color:' + P.DECK_INK + ';margin-bottom:2mm}',
'.ov-d{font-size:9.5pt;color:' + P.DECK_MUTED + ';line-height:1.45;flex:1 1 auto}',
'.ov-pill{align-self:flex-start;margin-top:4.5mm;border-radius:1mm;padding:2.5mm 9mm;',
'  font-size:20pt;font-weight:700;color:#fff;line-height:1}',
'.ov-pill.green{background:' + P.DECK_GREEN + '}',
'.ov-pill.amber{background:' + P.DECK_AMBER + '}',
'.ov-num{margin-top:4.5mm;font-size:30pt;font-weight:400;color:' + P.DECK_INK + ';line-height:1;',
'  text-align:center}',
'.ov-nodata{margin-top:4.5mm;font-size:13pt;font-style:italic;color:#A6A6A6;text-align:center}',
'.ov-sub{margin-top:2.5mm;font-size:11pt;font-weight:600;color:' + P.DECK_MUTED + ';',
'  text-transform:uppercase;letter-spacing:.6pt}',

/* data tables */
'.dt-cap{font-size:12pt;font-weight:600;color:' + P.DECK_INK + ';margin:0 0 2.2mm;text-align:center}',
'.dt{width:100%;border-collapse:collapse;font-size:9pt;table-layout:fixed;line-height:1.3}',
'.dt thead th{background:' + P.DECK_TABLE_HEAD + ';color:#fff;font-weight:600;text-align:left;',
'  padding:2mm 2.6mm;font-size:8.5pt;vertical-align:bottom}',
'.dt tbody td{padding:1.9mm 2.6mm;border-bottom:.5pt solid #E6E6E6;vertical-align:top;',
'  word-wrap:break-word;overflow-wrap:break-word}',
'.dt tbody tr:nth-child(even){background:#F2F5F9}',
'.dt tr.total td{font-weight:700;background:#E4EAF2;border-bottom:none}',
'.dt .num{text-align:right}',
'.dt-empty{font-size:10pt;font-style:italic;color:#A6A6A6;padding:4mm 0;text-align:center}',

/* tickets slide */
'.tk-wrap{border:1pt solid ' + P.DECK_BLUE + ';border-radius:1mm;padding:4mm 5mm;overflow:hidden}',
'.tk-wrap .dt thead th{background:#F2F2F2;color:' + P.DECK_MUTED + ';border-bottom:.75pt solid #BFBFBF}',
'.tk-wrap .dt tbody tr{background:none}',
'.tk-id{color:' + P.DECK_MAROON + ';font-weight:600;white-space:nowrap;text-align:right}',
'.tk-desc{color:' + P.DECK_MAROON + '}',
'.tk-when{color:' + P.DECK_MUTED + ';white-space:nowrap;font-size:8.5pt}',

/* bullets */
'.bl{list-style:none;padding:0;margin:0}',
'.bl li{position:relative;padding-left:7mm;margin-bottom:4.5mm;font-size:13pt;line-height:1.45;',
'  color:' + P.DECK_INK + '}',
'.bl li::before{content:"";position:absolute;left:1.5mm;top:2.2mm;width:1.8mm;height:1.8mm;',
'  border-radius:50%;background:' + P.DECK_BLUE + '}',

/* severity pill row (vulnerabilities) */
'.sev-row{display:grid;grid-template-columns:repeat(4,1fr);gap:6mm;margin-bottom:7mm}',
'.sev-card{background:' + P.DECK_CARD + ';border-radius:1.5mm;padding:5mm;text-align:center}',
'.sev-n{font-size:28pt;font-weight:700;line-height:1}',
'.sev-l{font-size:10pt;font-weight:600;color:' + P.DECK_MUTED + ';margin-top:2mm;',
'  text-transform:uppercase;letter-spacing:.5pt}',

/* print chrome */
'.print-btn-bar{position:fixed;top:16px;right:16px;z-index:9999;display:flex;gap:10px;',
'  align-items:center}',
'.print-hint{background:rgba(43,52,69,.92);color:#fff;font:400 11px/1.4 "Segoe UI",Arial;',
'  padding:7px 11px;border-radius:6px;max-width:230px}',
'.print-btn{background:' + P.DECK_BLUE + ';color:#fff;border:0;border-radius:6px;padding:10px 20px;',
'  font:600 .88rem/1 "Segoe UI",Arial;cursor:pointer;box-shadow:0 2px 10px rgba(16,119,199,.35)}',
'.print-btn.close-btn{background:' + P.DECK_DARK + '}',

'@media screen{body{background:#DFE3E8;padding:16px 0}',
'  .slide{box-shadow:0 2px 22px rgba(0,0,0,.18);margin:0 auto 16px}}',
'@media print{body{background:#fff;padding:0}',
'  .slide{box-shadow:none;margin:0}',
'  .print-btn-bar{display:none !important}',
'  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}}',
  ].join('\n');

  // The Reflex "X" mark, approximated as two crossing round-capped bars.
  // public/img/ holds only the wordmark PNG, which would read as a grey smear
  // at this size. If a true vector turns up, swapping these two lines for its
  // paths is the whole change.
  var WATERMARK_X =
    '<svg class="cover-wm" viewBox="0 0 100 100" aria-hidden="true">' +
      '<g stroke="#ffffff" stroke-width="19" stroke-linecap="round" fill="none">' +
        '<line x1="20" y1="14" x2="80" y2="86"/>' +
        '<line x1="80" y1="14" x2="20" y2="86"/>' +
      '</g>' +
    '</svg>';

  function esc(s) { return S.esc(s); }

  /**
   * Footer chrome: dots, date, rule, page number. The reference deck carries the
   * copyright on the cover only, so content slides omit it.
   */
  function slideFooter(pageNo, dateStr) {
    return '<div class="sl-foot">' +
        '<span class="sl-dots"><i class="sl-dot"></i><i class="sl-dot"></i><i class="sl-dot lg"></i></span>' +
        '<span>' + esc(dateStr) + '</span>' +
        '<span class="sl-foot-rule"></span>' +
        '<span class="sl-page">' + pageNo + '</span>' +
      '</div>';
  }

  /** Header chrome: blue title, underline rule, logo top-right. */
  function slideHeader(title, logoDataUri) {
    return '<div class="sl-head">' +
        '<div style="flex:1 1 auto;min-width:0">' +
          '<div class="sl-title">' + esc(title) + '</div>' +
        '</div>' +
        (logoDataUri ? '<img class="sl-logo" src="' + logoDataUri + '" alt="Reflex">' : '') +
      '</div>' +
      '<div class="sl-rule"></div>';
  }

  /** Wrap a body fragment in a full content slide. */
  function slide(opts) {
    var ctx = opts.ctx || {};
    return '<div class="slide">' +
        slideHeader(opts.title, ctx.logoDataUri) +
        '<div class="sl-body">' + opts.body + '</div>' +
        slideFooter(opts.pageNo, ctx.dateStr) +
      '</div>';
  }

  /** The full-bleed blue cover. Always page 1. */
  function coverSlide(ctx) {
    return '<div class="slide cover">' +
        WATERMARK_X +
        '<div class="cover-inner">' +
          (ctx.logoDataUri ? '<img class="cover-logo" src="' + ctx.logoDataUri + '" alt="Reflex">' : '') +
          '<div class="cover-mid">' +
            '<div class="cover-title">' + esc(ctx.clientName) + ' Managed Cybersecurity</div>' +
            '<div class="cover-sub">Managed Detection and Response Reports</div>' +
            '<div class="cover-hr"></div>' +
            '<div class="cover-author">By ' + esc(ctx.author) + '</div>' +
            '<div class="cover-hr2"></div>' +
          '</div>' +
          '<div class="cover-copy">&copy; Reflex&trade; ' + esc(ctx.year) + '</div>' +
          slideFooter(1, ctx.dateStr) +
        '</div>' +
      '</div>';
  }

  /**
   * A blue-header, zebra-striped table.
   * cols:      [{ label, key, cls?, width? }]
   * rows:      array of objects
   * totalRow:  optional object rendered as a bold "Total" row
   * totalRows: optional [{ _label, ...values }] for several summary rows
   */
  function dataTable(opts) {
    var cols = opts.cols || [];
    var rows = opts.rows || [];

    var totals = opts.totalRows
      ? opts.totalRows.slice()
      : (opts.totalRow ? [Object.assign({ _label: 'Total' }, opts.totalRow)] : []);

    if (!rows.length) {
      return (opts.caption ? '<div class="dt-cap">' + esc(opts.caption) + '</div>' : '') +
             '<div class="dt-empty">No data for this period.</div>';
    }

    var colgroup = cols.some(function (c) { return c.width; })
      ? '<colgroup>' + cols.map(function (c) {
          return '<col' + (c.width ? ' style="width:' + c.width + '"' : '') + '>';
        }).join('') + '</colgroup>'
      : '';

    function cell(col, row, tag) {
      var v = row[col.key];
      var raw = col.raw ? col.raw(row) : null;
      return '<' + tag + (col.cls ? ' class="' + col.cls + '"' : '') + '>' +
             (raw != null ? raw : esc(v == null ? '' : v)) +
             '</' + tag + '>';
    }

    return (opts.caption ? '<div class="dt-cap">' + esc(opts.caption) + '</div>' : '') +
      '<table class="dt">' + colgroup +
        '<thead><tr>' + cols.map(function (c) {
          return '<th' + (c.cls ? ' class="' + c.cls + '"' : '') + '>' + esc(c.label) + '</th>';
        }).join('') + '</tr></thead>' +
        '<tbody>' +
          rows.map(function (r) {
            return '<tr>' + cols.map(function (c) { return cell(c, r, 'td'); }).join('') + '</tr>';
          }).join('') +
          totals.map(function (t) {
            return '<tr class="total">' + cols.map(function (c, i) {
              if (i === 0) return '<td>' + esc(t._label) + '</td>';
              if (!(c.key in t)) return '<td></td>';
              return cell(c, t, 'td');
            }).join('') + '</tr>';
          }).join('') +
        '</tbody>' +
      '</table>';
  }

  /** Assemble a complete printable document from pre-rendered slide HTML. */
  function renderDeck(slidesHtml, ctx) {
    return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
      '<meta charset="UTF-8">\n' +
      '<title>' + esc(ctx.clientName) + ' — Managed Cybersecurity — ' + esc(ctx.periodLabel) + '</title>\n' +
      '<style>\n' + DECK_CSS + '\n</style>\n' +
      '</head>\n<body>\n' +
      // Must precede the slides: it is position:fixed, and anything after the
      // final .slide reintroduces a trailing blank page.
      '<div class="print-btn-bar">' +
        // "Headers and footers" is the setting that prints "about:blank" and a
        // date across the top of every page — it is a browser setting, so the
        // document itself cannot switch it off.
        '<span class="print-hint">In the print dialog: <b>Margins: None</b>, ' +
        '<b>Headers and footers: off</b>, <b>Background graphics: on</b>, ' +
        '<b>Paper size: default</b>.</span>' +
        '<button class="print-btn" onclick="window.print()">Print / Save as PDF</button>' +
        '<button class="print-btn close-btn" onclick="window.close()">Close</button>' +
      '</div>\n' +
      slidesHtml.join('\n') +
      '\n</body>\n</html>';
  }

  return {
    DECK_CSS:     DECK_CSS,
    WATERMARK_X:  WATERMARK_X,
    slideHeader:  slideHeader,
    slideFooter:  slideFooter,
    slide:        slide,
    coverSlide:   coverSlide,
    dataTable:    dataTable,
    renderDeck:   renderDeck,
  };
})();
