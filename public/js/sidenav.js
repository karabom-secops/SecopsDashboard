/* sidenav.js — sidebar state machine: category accordion, icon rail, rail
   flyout, and persistence.

   State is modelled as TWO ORTHOGONAL AXES rather than three flat states:

     mode    ∈ {expanded, rail}   — written only by the dock button
     visible ∈ {true, false}      — written only by the header hamburger
     effective = visible ? mode : 'hidden'

   Three flat states would force an arbitrary answer to "the hamburger from
   hidden restores... what?". Two axes answer it for free: it restores whichever
   mode you were last in. Docking while hidden forces visible=true, because a
   pin button that produces no visible change is a bug report.

   Loaded BEFORE app.js. The inline bootstrap in index.html has already stamped
   the state class onto <html> by the time this runs — this file owns every
   change after that. */
(function () {
  'use strict';

  var LS_KEY   = 'secops.sidenav.v1';
  var OPEN_MS  = 80;    // hover dwell before a flyout opens
  var CLOSE_MS = 260;   // grace period so a diagonal mouse path survives
  var MQ       = window.matchMedia('(max-width: 768px)');

  var root     = document.documentElement;
  var menu     = document.getElementById('sideMenu');
  var nav      = menu && menu.querySelector('.side-nav');
  var footer   = menu && menu.querySelector('.side-nav-footer');
  var dockBtn  = document.getElementById('navDock');
  var burger   = document.getElementById('navBurger');
  var flyout   = document.getElementById('navFlyout');
  var flyIn    = flyout && flyout.querySelector('.nav-flyout-inner');
  var overlay  = document.getElementById('navOverlay');

  if (!menu || !nav || !flyout) return; // not the dashboard shell

  // Persisted. openGroup rides along so a returning user does not watch the
  // accordion re-derive itself on every load.
  var state = { mode: 'expanded', visible: true, openGroup: null };

  // Runtime only, DELIBERATELY never persisted — see effective()/setMobileOpen.
  var mobileOpen = false;
  var lastFocus  = null;

  // ── Persistence ──────────────────────────────────────────────────────────

  function load() {
    try {
      var p = JSON.parse(localStorage.getItem(LS_KEY));
      if (p && typeof p === 'object') {
        if (p.mode === 'rail' || p.mode === 'expanded') state.mode = p.mode;
        if (typeof p.visible === 'boolean') state.visible = p.visible;
        if (typeof p.openGroup === 'string') state.openGroup = p.openGroup;
      }
    } catch (_) { /* unreadable or absent — defaults stand */ }
  }

  // setItem throws too (Safari private mode, quota) — not just getItem.
  function save() {
    try { localStorage.setItem(LS_KEY, JSON.stringify(state)); } catch (_) {}
  }

  // ── Effective state ──────────────────────────────────────────────────────

  function isMobile() { return MQ.matches; }

  /* Note the order: the mobile branch is taken BEFORE `state` is consulted, so
     narrow viewports never read — and setMobileOpen never writes — the stored
     desktop preference. Rotate a tablet back to landscape and the desktop state
     is byte-identical to how it was left. */
  function effective() {
    if (root.classList.contains('nav-empty')) return 'hidden';
    if (isMobile()) return mobileOpen ? 'expanded' : 'hidden';
    return state.visible ? state.mode : 'hidden';
  }

  function isRail() { return effective() === 'rail'; }

  function applyState() {
    var eff = effective();
    root.classList.toggle('nav-mobile',   isMobile());
    root.classList.toggle('nav-expanded', eff === 'expanded');
    root.classList.toggle('nav-rail',     eff === 'rail');
    root.classList.toggle('nav-hidden',   eff === 'hidden');

    if (burger) {
      burger.setAttribute('aria-expanded', eff === 'hidden' ? 'false' : 'true');
      burger.setAttribute('aria-label', eff === 'hidden' ? 'Show navigation' : 'Hide navigation');
    }
    if (dockBtn) {
      dockBtn.setAttribute('aria-pressed', state.mode === 'rail' ? 'true' : 'false');
      dockBtn.setAttribute('aria-label',
        state.mode === 'rail' ? 'Expand sidebar' : 'Collapse sidebar to icons');
      var dockText = dockBtn.querySelector('.side-nav-text');
      if (dockText) dockText.textContent = state.mode === 'rail' ? 'Expand' : 'Collapse';
    }
    if (overlay) overlay.classList.toggle('open', isMobile() && mobileOpen);

    if (eff !== 'rail') closeFlyout();
    if (eff === 'expanded') renderAccordion(); // re-sync panels on leaving rail
  }

  // ── Accordion ────────────────────────────────────────────────────────────

  function groups() { return nav.querySelectorAll('.side-nav-group'); }

  function cssEsc(s) {
    return (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\]/g, '\\$&');
  }

  function groupOf(tab) {
    var el = nav.querySelector('.side-nav-item[data-tab="' + cssEsc(tab) + '"]');
    return el ? el.closest('.side-nav-group') : null;
  }

  function renderAccordion() {
    Array.prototype.forEach.call(groups(), function (g) {
      var open = !g.hidden && g.dataset.group === state.openGroup;
      g.classList.toggle('is-open', open);
      var btn = g.querySelector('.side-nav-group-btn');
      var panel = g.querySelector('.side-nav-group-items');
      if (btn)   btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      if (panel) panel.hidden = !open;
    });
  }

  /** Click on a category header: open it, or close it if it was already open. */
  function setOpenGroup(key) {
    state.openGroup = (state.openGroup === key) ? null : key;
    renderAccordion();
    save();
  }

  /* Called from switchTab. Never closes anything — and never opens a group the
     user cannot see, which is what keeps an invisible group from silently
     claiming the single "open" slot. */
  function openGroupForTab(tab) {
    var g = groupOf(tab);
    if (!g || g.hidden) return;   // pinned Admin/Upload, or permission-hidden
    if (state.openGroup !== g.dataset.group) {
      state.openGroup = g.dataset.group;
      renderAccordion();
      save();
    }
  }

  // ── Rail flyout ──────────────────────────────────────────────────────────

  var openTimer = null, closeTimer = null, activeGroup = null;

  /* Set while closeFlyout() hands focus back to the group button. Without it,
     the focusin handler below — whose whole job is to open a flyout when its
     button receives focus — instantly re-opens the one Escape just closed, and
     Escape becomes a no-op. focus() dispatches synchronously, so a plain
     boolean around the call is enough. */
  var restoringFocus = false;

  function collapseBtn(g) {
    var b = g && g.querySelector('.side-nav-group-btn');
    if (b) b.setAttribute('aria-expanded', 'false');
  }

  function openFlyout(g) {
    clearTimeout(closeTimer); closeTimer = null;
    if (!isRail() || !g || g.hidden) return;
    if (activeGroup === g) return;
    if (activeGroup) collapseBtn(activeGroup);

    var btn  = g.querySelector('.side-nav-group-btn');
    var src  = g.querySelector('.side-nav-group-items');
    if (!btn || !src) return;

    var list = src.cloneNode(true);
    list.removeAttribute('hidden');
    list.removeAttribute('role');
    list.removeAttribute('aria-labelledby');
    // Duplicate ids are invalid and break aria-labelledby lookups. Safe to strip
    // wholesale here: none of the nav SVGs use <defs>, <use> or gradients.
    list.removeAttribute('id');
    Array.prototype.forEach.call(list.querySelectorAll('[id]'), function (n) {
      n.removeAttribute('id');
    });

    flyIn.innerHTML = '';
    var title = document.createElement('div');
    title.className = 'nav-flyout-title';
    title.textContent = btn.dataset.label || '';
    flyIn.appendChild(title);
    flyIn.appendChild(list);

    flyout.setAttribute('aria-labelledby', btn.id);
    flyout.style.top = '0px';
    flyout.hidden = false;

    // Measure only after unhiding, then clamp against the viewport bottom so a
    // long category becomes an internally-scrolling panel instead of running
    // off the screen.
    var r = btn.getBoundingClientRect();
    var h = flyout.offsetHeight;
    var top = r.top;
    var maxBottom = window.innerHeight - 8;
    if (top + h > maxBottom) top = Math.max(8, maxBottom - h);
    flyout.style.left = Math.round(r.right) + 'px';
    flyout.style.top  = Math.round(top) + 'px';

    btn.setAttribute('aria-expanded', 'true');
    activeGroup = g;
  }

  function closeFlyout(opts) {
    clearTimeout(openTimer);  openTimer  = null;
    clearTimeout(closeTimer); closeTimer = null;
    if (!activeGroup) { flyout.hidden = true; return; }
    var btn = activeGroup.querySelector('.side-nav-group-btn');
    collapseBtn(activeGroup);
    activeGroup = null;
    flyout.hidden = true;
    flyIn.innerHTML = '';
    if (opts && opts.restoreFocus && btn) {
      restoringFocus = true;
      btn.focus();
      restoringFocus = false;
    }
  }

  function scheduleClose() {
    clearTimeout(closeTimer);
    closeTimer = setTimeout(function () { closeFlyout(); }, CLOSE_MS);
  }

  function firstFlyoutItem() {
    return flyIn.querySelector('.side-nav-item:not([hidden])');
  }

  nav.addEventListener('mouseover', function (e) {
    if (!isRail()) return;
    var btn = e.target.closest && e.target.closest('.side-nav-group-btn');
    if (!btn) return;
    var g = btn.closest('.side-nav-group');
    clearTimeout(closeTimer); closeTimer = null;
    // Moving between categories while one is already open swaps instantly —
    // the dwell delay only guards the cold open.
    if (activeGroup && activeGroup !== g) { openFlyout(g); return; }
    clearTimeout(openTimer);
    openTimer = setTimeout(function () { openFlyout(g); }, OPEN_MS);
  });

  nav.addEventListener('mouseleave', function () {
    clearTimeout(openTimer); openTimer = null;
    if (activeGroup) scheduleClose();
  });

  flyout.addEventListener('mouseenter', function () {
    clearTimeout(closeTimer); closeTimer = null;
  });
  flyout.addEventListener('mouseleave', scheduleClose);

  // Both stale the anchor rect the flyout was positioned from.
  menu.addEventListener('scroll', function () { closeFlyout(); }, { passive: true });
  window.addEventListener('resize', function () { closeFlyout(); });

  // ── Keyboard ─────────────────────────────────────────────────────────────

  nav.addEventListener('focusin', function (e) {
    if (restoringFocus) return;   // Escape just closed this one — do not reopen
    var btn = e.target.closest && e.target.closest('.side-nav-group-btn');
    if (btn && isRail()) openFlyout(btn.closest('.side-nav-group'));
  });

  // Tabbing away from the flyout dismisses it. Necessary because the flyout is
  // a body-level sibling: its DOM position is after everything else, so a plain
  // Tab out of it would otherwise jump to the end of the document.
  document.addEventListener('focusin', function (e) {
    if (!activeGroup) return;
    if (flyout.contains(e.target)) return;
    if (activeGroup.contains(e.target)) return;
    closeFlyout();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      if (activeGroup) { e.preventDefault(); closeFlyout({ restoreFocus: true }); return; }
      if (isMobile() && mobileOpen) { e.preventDefault(); setMobileOpen(false); return; }
    }
    if (!isRail()) return;
    var btn = e.target.closest && e.target.closest('.side-nav-group-btn');
    if (btn && (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      openFlyout(btn.closest('.side-nav-group'));
      var first = firstFlyoutItem();
      if (first) first.focus();
    }
  });

  flyout.addEventListener('keydown', function (e) {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    var items = Array.prototype.filter.call(
      flyIn.querySelectorAll('.side-nav-item'), function (n) { return !n.hidden; });
    if (!items.length) return;
    e.preventDefault();
    var i = items.indexOf(document.activeElement);
    var next = e.key === 'ArrowDown'
      ? items[(i + 1 + items.length) % items.length]
      : items[(i - 1 + items.length) % items.length];
    if (next) next.focus();
  });

  // ── Clicks ───────────────────────────────────────────────────────────────

  nav.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.side-nav-group-btn');
    if (!btn) return;
    var g = btn.closest('.side-nav-group');
    // In rail mode the inline panel is display:none, so a click has to open the
    // flyout — otherwise the header button looks dead.
    if (isRail()) {
      openFlyout(g);
      var first = firstFlyoutItem();
      if (first) first.focus();
    } else {
      setOpenGroup(g.dataset.group);
    }
  });

  /* Delegated on `document`, not on the nav: that is what makes the same
     handler cover both the real items and the body-level flyout clones. */
  document.addEventListener('click', function (e) {
    var item = e.target.closest && e.target.closest('.side-nav-item[data-tab]');
    if (!item || item.hidden) return;
    e.preventDefault();
    if (typeof window.switchTab === 'function') window.switchTab(item.dataset.tab);
    closeFlyout();
    if (isMobile()) setMobileOpen(false);
  });

  if (dockBtn) {
    dockBtn.addEventListener('click', function () {
      state.mode = state.mode === 'rail' ? 'expanded' : 'rail';
      state.visible = true;   // docking from hidden must produce a visible change
      save();
      applyState();
      syncActive();
    });
  }

  if (burger) {
    burger.addEventListener('click', function () {
      if (isMobile()) { setMobileOpen(!mobileOpen); return; }
      state.visible = !state.visible;
      save();
      // Move focus out before hiding, or it lands on <body> and the next Tab
      // restarts from the top of the document.
      if (!state.visible && menu.contains(document.activeElement)) burger.focus();
      applyState();
    });
  }

  if (overlay) overlay.addEventListener('click', function () { setMobileOpen(false); });

  function setMobileOpen(v) {
    mobileOpen = v;   // never saved — see effective()
    applyState();
    if (v) {
      lastFocus = document.activeElement;
      var first = menu.querySelector('.side-nav-group-btn, .side-nav-item:not([hidden])');
      if (first) first.focus();
    } else {
      if (menu.contains(document.activeElement)) (lastFocus || burger || document.body).focus();
      lastFocus = null;
    }
  }

  function onMQ() { mobileOpen = false; applyState(); }
  if (MQ.addEventListener) MQ.addEventListener('change', onMQ);
  else if (MQ.addListener) MQ.addListener(onMQ);

  // ── Permissions ──────────────────────────────────────────────────────────

  function firstVisibleTab() {
    var el = nav.querySelector('.side-nav-group:not([hidden]) .side-nav-item[data-tab]:not([hidden])')
      || (footer && footer.querySelector('.side-nav-item[data-tab]:not([hidden])'));
    return el ? el.dataset.tab : null;
  }

  /* Runs after auth.js has hidden the items the user cannot view. Repairs, in
     order: category visibility, the "nothing at all" case, a stale active tab,
     and a stale persisted openGroup. */
  function refresh() {
    var any = false;
    Array.prototype.forEach.call(groups(), function (g) {
      var vis = !!g.querySelector('.side-nav-item[data-tab]:not([hidden])');
      g.hidden = !vis;
      if (vis) any = true;
    });
    if (footer && footer.querySelector('.side-nav-item[data-tab]:not([hidden])')) any = true;

    root.classList.toggle('nav-empty', !any);

    /* Load-bearing, not defensive padding: switchTab fires before auth.js
       resolves, so the first-painted tab can be one this user cannot see. */
    var cur = document.querySelector('.side-nav-item.active[data-tab]');
    var curGroup = cur && cur.closest('.side-nav-group');
    if (any && (!cur || cur.hidden || (curGroup && curGroup.hidden))) {
      var t = firstVisibleTab();
      if (t && typeof window.switchTab === 'function') window.switchTab(t);
    }

    if (state.openGroup) {
      var g = nav.querySelector('.side-nav-group[data-group="' + cssEsc(state.openGroup) + '"]');
      if (!g || g.hidden) state.openGroup = null;
    }
    if (!state.openGroup) {
      var c = document.querySelector('.side-nav-item.active[data-tab]');
      if (c) openGroupForTab(c.dataset.tab);
    }

    renderAccordion();
    applyState();
    closeFlyout();
  }

  /** Mark the active tab everywhere — real items AND any open flyout clone. */
  function syncActive(tab) {
    var key = tab;
    if (!key) {
      var cur = document.querySelector('.side-nav-item.active[data-tab]');
      key = cur ? cur.dataset.tab : null;
    }
    if (!key) return;
    Array.prototype.forEach.call(
      document.querySelectorAll('.side-nav-item[data-tab]'), function (el) {
        var on = el.dataset.tab === key;
        el.classList.toggle('active', on);
        if (on) el.setAttribute('aria-current', 'page');
        else    el.removeAttribute('aria-current');
      });
    openGroupForTab(key);
  }

  document.addEventListener('nav:permissions-updated', refresh);

  window.SideNav = {
    refresh: refresh,
    syncActive: syncActive,
    openGroupForTab: openGroupForTab,
    firstVisibleTab: firstVisibleTab,
    closeFlyout: closeFlyout,
  };

  // ── Boot ─────────────────────────────────────────────────────────────────

  load();
  applyState();
  renderAccordion();
  // Two frames: one for the state class to paint, one before re-enabling
  // transitions, so nothing animates from its pre-bootstrap position.
  requestAnimationFrame(function () {
    requestAnimationFrame(function () { root.classList.remove('nav-boot'); });
  });
})();
