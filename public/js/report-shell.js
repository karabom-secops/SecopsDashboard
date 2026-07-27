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

  return {
    LOGO_PATH:       LOGO_PATH,
    PALETTE:         PALETTE,
    esc:             esc,
    hexToRgba:       hexToRgba,
    logoToDataUri:   logoToDataUri,
    openReportWindow: openReportWindow,
  };
})();
