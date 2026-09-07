/* ms-secure-score.js — the Microsoft Secure Score panel on the Secure Score tab.
 *
 * ══ WHY THIS IS A SEPARATE MODULE AND A SEPARATE PANEL ══
 *
 * Microsoft's score is reported ALONGSIDE our composite, never inside it. The
 * server-side reasoning is in the /api/ms-secure-score comment and in
 * db/migrate-ms-secure-score.sql; the consequence here is presentational and
 * just as deliberate:
 *
 *   - it is labelled as Microsoft's, with the directory it came from, so nobody
 *     reads it as a number we computed and can defend line by line;
 *   - it is shown as points-out-of-points FIRST and a percentage second,
 *     because the percentage moves when Microsoft publishes new controls and a
 *     client who reads only the percentage will think their posture slipped;
 *   - the two scores are allowed to disagree on screen. A Microsoft score of
 *     71% beside a composite of 48% is not a bug to reconcile — it says the
 *     Microsoft tenancy is in better shape than the rest of the estate, which
 *     is exactly the sort of thing a vISO is paid to point out.
 *
 * Kept out of tab-secure-score.js because that file is already 1,500 lines and
 * this panel is independently loadable — it renders, or explains why it can't,
 * without any of that file's state.
 */
const MsSecureScorePanel = (() => {
  'use strict';

  // Microsoft publishes roughly one snapshot a day. Past this, the gauge is a
  // claim about a live tenancy made from stale evidence, and it says so.
  const STALE_DAYS = 3;

  // Remediation items shown before "show all". Enough to be a week's work.
  const TOP_GAPS = 10;

  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * A number for display, or an em dash.
   *
   * The dash is load-bearing. Every null that reaches this panel means
   * "Microsoft did not report it", and rendering that as 0 would turn a
   * reporting gap into a measured failure — the exact confusion the adapter and
   * the schema go to some length to preserve.
   */
  function n(v, digits) {
    if (v === null || v === undefined) return '—';
    const num = Number(v);
    if (!isFinite(num)) return '—';
    return digits ? num.toFixed(digits) : String(Math.round(num * 10) / 10);
  }

  function pctText(v) {
    return v === null || v === undefined ? '—' : n(v) + '%';
  }

  function colorFor(pct) {
    if (pct === null || pct === undefined) return 'var(--text-muted, #888)';
    if (pct >= 80) return '#27ae60';
    if (pct >= 60) return '#f39c12';
    if (pct >= 40) return '#e67e22';
    return '#e74c3c';
  }

  async function fetchPanel() {
    try {
      const res = await fetch('api/ms-secure-score', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return await res.json();
    } catch (err) {
      console.error('[MsSecureScore] fetch error:', err.message);
      return null;
    }
  }

  /**
   * The empty states, told apart.
   *
   * Four different nothings reach here and each needs a different action from
   * whoever is looking. Collapsing them into one "no data" panel is how an
   * operator spends an afternoon debugging a connection that was never
   * configured, or waits a week for a sync that is failing every night.
   */
  function renderUnavailable(el, data) {
    const reason = data && data.reason;

    const MESSAGES = {
      not_migrated: {
        title: 'Not set up',
        body: 'The Microsoft Secure Score tables have not been created yet. Run <code>db/migrate-ms-secure-score.sql</code>.',
      },
      not_configured: {
        title: 'Not connected',
        body: 'No Microsoft Graph integration is configured for this client. Add one under Admin → Integrations to pull their Microsoft Secure Score.',
      },
      never_synced: {
        title: 'Never synced',
        body: 'The Microsoft Graph integration is configured but has not synced yet. Use <strong>Sync Now</strong> on the integration, or wait for the daily run.',
      },
      no_snapshots: {
        title: 'No snapshots published',
        body: 'The connection works, but Microsoft has published no Secure Score snapshots for this directory. That is normal for a tenant provisioned in the last 24–48 hours; otherwise check the tenant has licensed workloads Secure Score can assess.',
      },
    };

    const m = MESSAGES[reason] || {
      title: 'Unavailable',
      body: 'Microsoft Secure Score could not be loaded.',
    };

    // A failing sync is the case most worth surfacing: the panel is empty AND
    // something is actively broken, and only last_sync_message says what.
    const syncNote = (data && data.lastSyncStatus === 'error' && data.lastSyncMessage)
      ? `<p class="ms-ss-error">Last sync failed: ${esc(data.lastSyncMessage)}</p>` : '';

    const disabledNote = (data && data.isEnabled === false)
      ? '<p class="ms-ss-error">This integration is currently disabled — enable it under Admin → Integrations.</p>' : '';

    el.innerHTML = `
      <div class="ms-ss-panel ms-ss-empty">
        <h3 class="secure-score-section-title">Microsoft Secure Score</h3>
        <p class="ms-ss-empty-title">${esc(m.title)}</p>
        <p class="ms-ss-empty-body">${m.body}</p>
        ${syncNote}${disabledNote}
      </div>`;
  }

  function renderGaps(gaps) {
    if (!gaps.length) {
      return '<p class="ms-ss-empty-body">No outstanding point gaps — every applicable control is fully credited.</p>';
    }

    const rows = gaps.slice(0, TOP_GAPS).map(g => `
      <tr>
        <td>
          <div class="ms-ss-gap-title">${esc(g.title || g.controlName)}</div>
          ${g.remediation ? `<div class="ms-ss-gap-rem">${esc(g.remediation)}</div>` : ''}
        </td>
        <td>${esc(g.category || '—')}</td>
        <td>${esc(g.tier || '—')}</td>
        <td>${esc(g.userImpact || '—')}</td>
        <td class="ms-ss-gap-points"><strong>+${n(g.gap)}</strong> <span class="ms-ss-of">of ${n(g.maxScore)}</span></td>
      </tr>`).join('');

    const more = gaps.length > TOP_GAPS
      ? `<p class="ms-ss-empty-body">${gaps.length - TOP_GAPS} further control(s) with outstanding points are not shown.</p>`
      : '';

    return `
      <div class="ms-ss-table-wrap">
        <table class="ms-ss-table">
          <thead>
            <tr>
              <th>Control</th><th>Category</th><th>Tier</th><th>User impact</th>
              <th>Points available</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>${more}`;
  }

  function renderCategories(categories) {
    if (!categories.length) return '';
    return `
      <div class="ms-ss-cats">
        ${categories.map(c => `
          <div class="ms-ss-cat">
            <div class="ms-ss-cat-name">${esc(c.category)}</div>
            <div class="ms-ss-cat-score" style="color:${colorFor(c.percentage)}">${pctText(c.percentage)}</div>
            <div class="ms-ss-cat-sub">${n(c.score)} / ${n(c.maxScore)} pts</div>
            ${c.unmeasured ? `<div class="ms-ss-cat-sub ms-ss-warn">${c.unmeasured} control(s) unscored</div>` : ''}
          </div>`).join('')}
      </div>`;
  }

  /**
   * Controls the client has excluded, surfaced rather than hidden.
   *
   * 'Ignored' is a risk ACCEPTANCE and 'ThirdParty' is a claim that something
   * else covers the control. Both are legitimate and both are dropped from the
   * remediation list — but an acceptance nobody ever revisits is a risk nobody
   * owns, and a third-party claim made two years ago may name a product the
   * client no longer runs. Naming the counts is what makes them auditable at
   * the next review.
   */
  function renderExclusions(accepted, thirdParty) {
    if (!accepted.length && !thirdParty.length) return '';
    const bits = [];
    if (accepted.length) {
      bits.push(`<strong>${accepted.length}</strong> control(s) marked <em>Ignored</em> in Microsoft 365 — these are risk acceptances and belong in the risk register`);
    }
    if (thirdParty.length) {
      bits.push(`<strong>${thirdParty.length}</strong> marked <em>Third party</em> — covered by a non-Microsoft product, worth re-confirming at review`);
    }
    return `<p class="ms-ss-exclusions">Excluded from the list above: ${bits.join('; ')}.</p>`;
  }

  function renderPanel(el, d) {
    const L = d.latest;
    const pct = L.percentage;

    const stale = d.ageDays !== null && d.ageDays !== undefined && d.ageDays > STALE_DAYS;

    /*
     * Microsoft's peer comparison, where it published one. Shown because it is
     * the one number here a board reliably reacts to, and captioned as
     * Microsoft's own benchmark so nobody attributes the comparison to us.
     */
    const comps = (L.comparative || []).map(c => {
      const basis = c.basis || c.Basis || '';
      const avg = c.averageScore !== undefined ? c.averageScore : c.AverageScore;
      if (avg === null || avg === undefined) return '';
      const label = basis === 'AllTenants' ? 'All tenants'
        : basis === 'TotalSeats' ? 'Similar seat count'
        : basis === 'IndustryTypes' ? 'Same industry' : esc(basis || 'Peers');
      return `<span class="ms-ss-comp"><span class="ms-ss-comp-label">${label}</span>
                <span class="ms-ss-comp-val">${n(avg)} pts</span></span>`;
    }).filter(Boolean).join('');

    el.innerHTML = `
      <div class="ms-ss-panel">
        <div class="ms-ss-head">
          <h3 class="secure-score-section-title">Microsoft Secure Score</h3>
          <span class="ms-ss-attrib">Microsoft's own measure of this client's Microsoft 365 tenancy —
            reported alongside, and not included in, the Secure Score above.</span>
        </div>

        <div class="ms-ss-headline">
          <div class="ms-ss-points">
            <span class="ms-ss-points-val" style="color:${colorFor(pct)}">${n(L.currentScore)}</span>
            <span class="ms-ss-points-max">/ ${n(L.maxScore)} points</span>
          </div>
          <div class="ms-ss-pct" style="color:${colorFor(pct)}">${pctText(pct)}</div>
          <div class="ms-ss-meta">
            <div>Snapshot: <strong>${esc(L.date)}</strong>${stale ? ` <span class="ms-ss-warn">(${d.ageDays} days old)</span>` : ''}</div>
            <div>Directory: <code>${esc(L.azureTenantId || 'unknown')}</code></div>
            <div>${L.licensedUserCount === null ? '' : esc(L.licensedUserCount) + ' licensed · '}${L.activeUserCount === null ? '' : esc(L.activeUserCount) + ' active users'}</div>
          </div>
        </div>

        ${stale ? `<p class="ms-ss-error">
          Microsoft publishes a snapshot roughly daily. This one is ${d.ageDays} days old,
          so the figures above describe the tenancy as it was then, not as it is now.
          Check the Microsoft Graph integration under Admin → Integrations.</p>` : ''}

        ${comps ? `<div class="ms-ss-comps">
          <span class="ms-ss-comps-label">Microsoft's peer benchmark:</span>${comps}</div>` : ''}

        ${renderCategories(d.categories || [])}

        <h4 class="ms-ss-subhead">Where the points are — ${(d.gaps || []).length} control(s) with outstanding points</h4>
        ${renderGaps(d.gaps || [])}
        ${renderExclusions(d.accepted || [], d.thirdParty || [])}
      </div>`;
  }

  /**
   * Render into `el`. Never throws: this is one panel on a tab that has to
   * survive it, and a Microsoft outage must not take the client's own posture
   * report down with it.
   */
  async function render(el) {
    if (!el) return null;
    el.innerHTML = '<div class="ms-ss-panel ms-ss-loading">Loading Microsoft Secure Score…</div>';

    const data = await fetchPanel();
    if (!data) {
      el.innerHTML = `
        <div class="ms-ss-panel ms-ss-empty">
          <h3 class="secure-score-section-title">Microsoft Secure Score</h3>
          <p class="ms-ss-empty-body">Could not be loaded. The rest of this report is unaffected.</p>
        </div>`;
      return null;
    }

    try {
      if (!data.available) renderUnavailable(el, data);
      else renderPanel(el, data);
    } catch (err) {
      console.error('[MsSecureScore] render error:', err);
      el.innerHTML = `
        <div class="ms-ss-panel ms-ss-empty">
          <h3 class="secure-score-section-title">Microsoft Secure Score</h3>
          <p class="ms-ss-empty-body">Could not be displayed.</p>
        </div>`;
    }
    return data;
  }

  return {
    render,
    // Exported so the renderers can be asserted without a live tab or a fetch.
    renderPanel,
    renderUnavailable,
    renderGaps,
    STALE_DAYS,
  };
})();

window.MsSecureScorePanel = MsSecureScorePanel;
