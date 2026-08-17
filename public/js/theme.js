/* theme.js — appearance control.
 *
 * Apple's model, and the one this follows: the SYSTEM decides by default, and
 * the app only overrides when a person explicitly asks it to. So there are
 * three states, not two — Light, Dark, and Automatic — and Automatic is the
 * default. An app that ships a plain light/dark switch has quietly opted every
 * user out of their own OS setting.
 *
 * The CSS does the actual work:
 *   - @media (prefers-color-scheme: dark) :root:not([data-theme="light"])
 *   - :root[data-theme="dark"]
 * This module only sets/clears the data-theme attribute and remembers it.
 *
 * NOTE: the pre-paint bootstrap that avoids a light flash lives inline in
 * index.html, because it has to run before first paint — by the time this
 * file loads, the page has already been painted once.
 */
const Theme = (() => {
  'use strict';

  const KEY = 'secops.theme.v1';
  const MODES = ['auto', 'light', 'dark'];

  function stored() {
    try {
      const v = localStorage.getItem(KEY);
      return MODES.indexOf(v) !== -1 ? v : 'auto';
    } catch (_) {
      return 'auto';   // private browsing / storage disabled
    }
  }

  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  /** The scheme actually being rendered, after resolving 'auto'. */
  function effective() {
    const m = stored();
    return m === 'auto' ? (systemPrefersDark() ? 'dark' : 'light') : m;
  }

  function apply(mode) {
    const root = document.documentElement;
    if (mode === 'auto') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', mode);
  }

  function set(mode) {
    if (MODES.indexOf(mode) === -1) mode = 'auto';
    try { localStorage.setItem(KEY, mode); } catch (_) {}
    apply(mode);
    render();
    // Let anything canvas-based (Chart.js) restyle itself.
    document.dispatchEvent(new CustomEvent('theme:changed', {
      detail: { mode, effective: effective() },
    }));
  }

  /** Cycle Auto → Light → Dark → Auto, which is what the single button does. */
  function cycle() {
    const order = ['auto', 'light', 'dark'];
    set(order[(order.indexOf(stored()) + 1) % order.length]);
  }

  const ICONS = {
    // Half-filled circle: the system-standard "automatic" glyph.
    auto:  '<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18z" fill="currentColor" stroke="none"/>',
    light: '<circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    dark:  '<path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5z"/>',
  };
  const LABELS = { auto: 'Appearance: Automatic', light: 'Appearance: Light', dark: 'Appearance: Dark' };

  function render() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    const mode = stored();
    btn.innerHTML = '<svg class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      ICONS[mode] + '</svg>';
    btn.setAttribute('aria-label', LABELS[mode]);
    btn.setAttribute('title', LABELS[mode] + ' — click to change');
  }

  function init() {
    apply(stored());
    render();

    const btn = document.getElementById('theme-toggle');
    if (btn && !btn._wired) { btn._wired = true; btn.addEventListener('click', cycle); }

    // While in Automatic, track the OS changing under us (macOS/iOS do this on
    // a schedule). No re-apply needed — the media query handles the colours —
    // but listeners still want to know.
    if (window.matchMedia) {
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      const onChange = () => {
        if (stored() !== 'auto') return;
        document.dispatchEvent(new CustomEvent('theme:changed', {
          detail: { mode: 'auto', effective: effective() },
        }));
      };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  return { set, cycle, effective, current: stored };
})();

window.Theme = Theme;
