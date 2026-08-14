/* modal-a11y.js — dialog semantics, focus management and dismissal.
 *
 * The app's modals were each wired by hand, and most ended up missing some
 * combination of Esc, backdrop click, focus trapping and focus restore. Two of
 * the nine carry role="dialog"; the rest are a bare <div> that sighted mouse
 * users can operate and nobody else can.
 *
 * This is deliberately small and does not own opening or closing — the tab
 * modules already do that, including reparenting to <body>. It layers the
 * accessible behaviour on top:
 *
 *   ModalA11y.open(overlayEl, { labelledBy, onClose })
 *   ModalA11y.close(overlayEl)
 *
 * `onClose` is what the caller already uses to hide the element, so this never
 * fights the module over visibility.
 */
const ModalA11y = (() => {
  'use strict';

  // Focusable descendants, in DOM order. :not([disabled]) matters here — the
  // read-only path disables every control, and a trap that cycles through
  // disabled fields traps the user for real.
  const FOCUSABLE = [
    'a[href]', 'button:not([disabled])', 'input:not([disabled])',
    'select:not([disabled])', 'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(',');

  let _active = null;   // { el, onClose, returnTo, onKeydown, onPointer }

  function focusable(el) {
    return Array.prototype.filter.call(
      el.querySelectorAll(FOCUSABLE),
      // offsetParent is null for display:none subtrees; a hidden Delete button
      // must not be a tab stop.
      (n) => n.offsetParent !== null || n === document.activeElement
    );
  }

  function onKeydown(e) {
    if (!_active) return;

    if (e.key === 'Escape') {
      e.preventDefault();
      close(_active.el);
      return;
    }

    if (e.key !== 'Tab') return;

    const items = focusable(_active.el);
    if (items.length === 0) { e.preventDefault(); return; }

    const first = items[0];
    const last  = items[items.length - 1];
    // Focus can sit outside the dialog if something stole it; pull it back.
    if (!_active.el.contains(document.activeElement)) {
      e.preventDefault();
      first.focus();
      return;
    }
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function onPointer(e) {
    // Backdrop only: a click that starts inside the box and drags out (e.g.
    // selecting text) must not dismiss, so test the actual target.
    if (_active && e.target === _active.el) close(_active.el);
  }

  /**
   * @param {HTMLElement} el        the .modal-overlay element
   * @param {Object}      [opts]
   * @param {string}      [opts.labelledBy]  id of the element naming the dialog
   * @param {Function}    [opts.onClose]     caller's own hide routine
   */
  function open(el, opts) {
    if (!el) return;
    const o = opts || {};

    // Only one at a time; releasing first keeps listeners from stacking.
    if (_active) release();

    el.setAttribute('role', 'dialog');
    el.setAttribute('aria-modal', 'true');
    if (o.labelledBy) el.setAttribute('aria-labelledby', o.labelledBy);

    _active = {
      el,
      onClose: o.onClose,
      // Restore focus here on close, so the keyboard user lands back where
      // they were rather than at the top of the document.
      returnTo: document.activeElement,
    };

    document.addEventListener('keydown', onKeydown, true);
    el.addEventListener('mousedown', onPointer);

    // Focus the first meaningful control, not the close button.
    const items = focusable(el);
    const target = items.find((n) => !n.classList.contains('modal-close')) || items[0];
    if (target) target.focus();
  }

  function release() {
    if (!_active) return;
    document.removeEventListener('keydown', onKeydown, true);
    _active.el.removeEventListener('mousedown', onPointer);
    _active = null;
  }

  function close(el) {
    const cur = _active;
    if (!cur || (el && el !== cur.el)) return;

    const { onClose, returnTo } = cur;
    release();
    if (typeof onClose === 'function') onClose();
    // Only restore if it is still in the document and focusable.
    if (returnTo && document.contains(returnTo) && typeof returnTo.focus === 'function') {
      returnTo.focus();
    }
  }

  return { open, close };
})();

window.ModalA11y = ModalA11y;
