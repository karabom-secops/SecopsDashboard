'use strict';

/**
 * Shared primitives for every printable report in the dashboard.
 *
 * Deliberately layout-agnostic — no page CSS lives here. The A4 portrait report
 * (tab-secure-score.js) and the 16:9 slide deck (report-deck.js) own their own
 * geometry; this module only holds what is provably identical between them.
 *
 * Loaded by index.html AND manager.html — manager.html pulls in tab-awareness.js
 * on its own, so anything tab-awareness.js calls must be available there too.
 */
window.ReportShell = (function () {

  var LOGO_PATH = 'img/reflex-logo.png';

  var PALETTE = {
    // Legacy A4 report palette. tab-secure-score.js still inlines these values
    // literally inside its CSS string — kept here for new code, not templated
    // back into the old string.
    BLUE:  '#1565C0',
    DARK:  '#2B3445',
    GREY:  '#B0BEC5',
    LIGHT: '#EEF2F7',

    // 16:9 deck palette, matched to the reference Reflex PowerPoint.
    DECK_BLUE:       '#1077C7',
    DECK_TABLE_HEAD: '#2E75B6',
    DECK_NAVY:       '#12294A',
    DECK_CARD:       '#EEEEEE',
    DECK_GREEN:      '#2E9E5B',
    DECK_AMBER:      '#E08A1E',
    DECK_MAROON:     '#8B1A2B',
    DECK_TRACK:      '#D9D9D9',
    DECK_INK:        '#262626',
    DECK_MUTED:      '#595959',
    DECK_FOOT:       '#7F7F7F',
    DECK_DARK:       '#2B3445',
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function hexToRgba(hex, alpha) {
    var r = parseInt(hex.slice(1, 3), 16);
    var g = parseInt(hex.slice(3, 5), 16);
    var b = parseInt(hex.slice(5, 7), 16);
    return 'rgba(' + r + ',' + g + ',' + b + ',' + alpha + ')';
  }

  /**
   * Fetch the Reflex logo and return it as a base64 data URI, so report popups
   * (which are about:blank and have no base URL) render it without a network hop.
   * Resolves to null on any failure — callers must treat the logo as optional.
   */
  async function logoToDataUri(path) {
    try {
      var res = await fetch(path || LOGO_PATH);
      if (!res.ok) return null;
      var blob = await res.blob();
      return new Promise(function (resolve) {
        var reader = new FileReader();
        reader.onload  = function () { resolve(reader.result); };
        reader.onerror = function () { resolve(null); };
        reader.readAsDataURL(blob);
      });
    } catch (_) { return null; }
  }

  /**
   * Open a report document in a new window. Returns the window, or null if the
   * popup was blocked (an alert is shown in that case).
   */
  function openReportWindow(html, opts) {
    var o = opts || {};
    var width  = o.width  || 1060;
    var height = o.height || 860;
    var win = window.open('', '_blank', 'width=' + width + ',height=' + height + ',scrollbars=yes');
    if (!win) {
      alert('Pop-up blocked. Please allow pop-ups for this site and try again.');
      return null;
    }
    win.document.open();
    win.document.write(html);
    win.document.close();
    return win;
  }


  /**
   * Trigger a file download.
   *
   * Two details that decide whether this works at all:
   *
   *   1. The anchor MUST be in the document. A synthetic click on a detached
   *      <a download> is ignored by Firefox and by Chrome under some settings,
   *      so every export in this app silently did nothing.
   *   2. The object URL must NOT be revoked synchronously after .click().
   *      Revoking it in the same task can cancel the download before the
   *      browser has read the blob — a race that fails on slower machines and
   *      larger files while appearing to work locally.
   */
  function downloadFile(filename, content, mime) {
    var blob = content instanceof Blob
      ? content
      : new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);

    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    // Give the browser a turn to start reading the blob before releasing it.
    setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
  }

  /** Quote a value for CSV: wrap in quotes and double any embedded quote. */
  function csvCell(v) {
    return '"' + String(v === null || v === undefined ? '' : v).replace(/"/g, '""') + '"';
  }

  /** Rows (array of arrays) to a CSV string with a UTF-8 BOM for Excel. */
  function toCsv(rows) {
    var BOM = String.fromCharCode(0xFEFF);
    var CRLF = String.fromCharCode(13) + String.fromCharCode(10);
    return BOM + rows.map(function (row) {
      return row.map(csvCell).join(",");
    }).join(CRLF);
  }

  /**
   * Reserve a popup window NOW, fill it in later.
   *
   * A browser only allows window.open while the page has transient user
   * activation. Awaiting anything — a fetch for the logo, a data call — spends
   * that activation, so a window opened after an await is treated as
   * unrequested and blocked. Every report in this app opened its window after
   * at least one await, which is why the buttons appeared dead.
   *
   * Call this synchronously inside the click handler, then write() once the
   * content is ready.
   */
  function reserveReportWindow(opts) {
    var o = opts || {};
    var width  = o.width  || 1060;
    var height = o.height || 860;
    var win = window.open('', '_blank',
      'width=' + width + ',height=' + height + ',scrollbars=yes');

    if (!win) {
      alert('Pop-up blocked. Please allow pop-ups for this site and try again.');
      return null;
    }

    // Something to look at while the caller assembles the document.
    try {
      win.document.open();
      win.document.write(
        '<!doctype html><meta charset="utf-8"><title>' +
        esc(o.title || 'Preparing report…') +
        '</title><body style="font:15px -apple-system,Segoe UI,sans-serif;' +
        'color:#5B5B60;display:flex;align-items:center;justify-content:center;' +
        'height:100vh;margin:0">Preparing report…</body>');
      win.document.close();
    } catch (_) { /* cross-origin shim, nothing to show */ }

    return {
      win: win,
      write: function (html) {
        if (win.closed) return null;
        win.document.open();
        win.document.write(html);
        win.document.close();
        return win;
      },
      fail: function (msg) {
        if (win.closed) return;
        win.document.open();
        win.document.write(
          '<!doctype html><meta charset="utf-8"><body style="font:15px ' +
          '-apple-system,Segoe UI,sans-serif;color:#C7000F;padding:2rem">' +
          esc(msg || 'The report could not be generated.') + '</body>');
        win.document.close();
      },
    };
  }

  return {
    LOGO_PATH:       LOGO_PATH,
    PALETTE:         PALETTE,
    esc:             esc,
    hexToRgba:       hexToRgba,
    logoToDataUri:   logoToDataUri,
    openReportWindow: openReportWindow,
    reserveReportWindow: reserveReportWindow,
    downloadFile:     downloadFile,
    toCsv:            toCsv,
    csvCell:          csvCell,
  };
})();
