// tab-secure-score.js — Secure Score tab implementation

const SecureScoreTab = (() => {
  let currentScore = null;
  let _trendChart   = null;
  let _cachedHistory = null;
  let _cachedGrcData = null;

  async function fetchSecureScore() {
    try {
      const res = await fetch('api/secure-score');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[SecureScore] fetch error:', err.message);
      return null;
    }
  }

  async function fetchScoreHistory() {
    try {
      const res = await fetch('api/secure-score/history');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[SecureScore] history fetch error:', err.message);
      return null;
    }
  }

  /**
   * Full five-character escape.
   *
   * The values below come from lib/services.js constants rather than user
   * input, so nothing here is currently attacker-controlled — but a helper
   * that is correct only while an assumption holds is the kind that outlives
   * the assumption. The four-character version elsewhere in this codebase
   * leaves single quotes live, which is a real hole inside an attribute.
   */
  function escHtml(v) {
    return String(v === null || v === undefined ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function getScoreColor(score) {
    if (score >= 80) return '#27ae60'; // Green - Excellent
    if (score >= 70) return '#f39c12'; // Orange - Good
    if (score >= 50) return '#e67e22'; // Dark Orange - Fair
    return '#e74c3c'; // Red - Poor
  }

  function getScoreRating(score) {
    if (score >= 80) return 'Excellent';
    if (score >= 70) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
  }

  function renderScoreGauge(container, score, delta) {
    const w = 220, h = 130;
    const cx = w / 2, cy = h - 10;
    const r = 90;
    const startX = cx - r, endX = cx + r, endY = cy;
    const color  = getScoreColor(score);
    const arcLen = Math.PI * r;
    const targetOffset = arcLen * (1 - score / 100);

    let deltaEl = '';
    if (typeof delta === 'number' && delta !== 0) {
      const sign = delta > 0 ? '+' : '';
      const dColor = delta > 0 ? '#27ae60' : '#e74c3c';
      deltaEl = `<text x="${cx}" y="${cy - 2}" text-anchor="middle"
        font-size="11" font-weight="600" fill="${dColor}" font-family="Manrope,sans-serif">
        ${sign}${delta} vs last month
      </text>`;
    }

    const svg = `
      <div class="grc-indicator-label" style="text-align:center;margin-bottom:4px">Secure Score</div>
      <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" class="score-gauge" style="overflow:visible">
        <defs>
          <filter id="gauge-shadow">
            <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.15"/>
          </filter>
        </defs>
        <path d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${endY}"
              fill="none" stroke="#dde8f0" stroke-width="12" stroke-linecap="round"/>
        <path id="gauge-arc" d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${endY}"
              fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
              stroke-dasharray="${arcLen}" stroke-dashoffset="${arcLen}"
              filter="url(#gauge-shadow)"/>
        <text x="${cx}" y="${cy - 20}" text-anchor="middle"
              font-size="42" font-weight="700" fill="${color}" font-family="Manrope,sans-serif">
          ${Math.round(score)}
        </text>
        ${deltaEl}
      </svg>
    `;

    container.innerHTML = svg;

    const arc = container.querySelector('#gauge-arc');
    if (arc) {
      requestAnimationFrame(() => {
        arc.style.transition = 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)';
        arc.style.strokeDashoffset = targetOffset;
      });
    }
  }

  /**
   * The three scores, side by side.
   *
   *   In scope   how the services they buy are performing.
   *   Coverage   how much of their weighted posture those services reach.
   *   Overall    their whole posture, counting every control that applies.
   *
   * Deliberately three separate figures rather than one clever number. They
   * answer different questions and are NOT related by a formula: a client who
   * runs their own vulnerability programme is measured but not covered, so
   * their overall legitimately exceeds anything coverage would predict.
   *
   * Hidden entirely when no service mix has been recorded — there is no
   * coverage statement to make, and an empty strip would imply one is missing.
   */
  function renderScopeStrip(el, scoreData) {
    if (!el) return;
    const scope = scoreData && scoreData.scope;
    if (!scope || !scope.recorded) { el.hidden = true; el.innerHTML = ''; return; }

    const svc = scoreData.serviceScore;
    const cov = scoreData.coverage;
    const all = scoreData.overall != null ? scoreData.overall : scoreData.score;

    const cell = (value, label, sub, tone) =>
      `<div class="ss-scope-cell">
         <div class="ss-scope-v"${tone ? ` style="color:${tone}"` : ''}>${escHtml(value)}</div>
         <div class="ss-scope-l">${escHtml(label)}</div>
         ${sub ? `<div class="ss-scope-s">${escHtml(sub)}</div>` : ''}
       </div>`;

    const gaps = (scope.uncovered || []);
    const blind = scope.blindSpotPoints || 0;

    /*
     * ── ARCTIC WOLF SENSOR REACH ───────────────────────────────────────────
     *
     * Somebody else's number, so it is labelled with their name, dated, and
     * kept in its own cell. It adjusts how much of the posture the MDR service
     * is credited with REACHING; it changes no score, and the sentence below
     * the grid says so outright.
     *
     * The cell is shown to an MDR client even when the link is missing —
     * "not linked" is the actionable state, and a tile that silently vanished
     * would hide the one thing a staff member can fix.
     */
    const mdrCov = scope.mdrCoverage || null;
    const showVendor = !!mdrCov &&
      (mdrCov.linked || (scope.covered || []).indexOf('incidentResponse') >= 0);

    const REASON_TEXT = {
      not_linked:         'Not linked to an Arctic Wolf organisation — no discount applied.',
      org_not_found:      'Name on file is not in the report — no discount applied.',
      no_score_in_report: 'Report carries no Coverage Score — no discount applied.',
      no_report:          'No weekly report on file — no discount applied.',
    };

    const bandTone = (bnd) =>
      bnd === 'good' ? '#27ae60' : bnd === 'fair' ? '#f39c12' : '#e74c3c';

    el.innerHTML =
      '<div class="ss-scope-grid' + (showVendor ? ' has-vendor' : '') + '">' +
        cell(svc == null ? 'n/a' : String(svc), 'Secure Score — services in scope',
             svc == null ? 'No scored service consumed' : getScoreRating(svc),
             svc == null ? null : getScoreColor(svc)) +
        cell(cov == null ? '—' : cov + '%', 'Service coverage of posture',
             gaps.length ? gaps.length + ' control' + (gaps.length === 1 ? '' : 's') + ' outside our services'
                         : 'All scored controls covered') +
        cell(all == null ? '—' : String(all), 'Overall Secure Score',
             blind ? blind + ' points not measured by anyone' : 'Counting every control that applies',
             all == null ? null : getScoreColor(all)) +
        (showVendor
          ? cell(mdrCov.available ? mdrCov.score + '%' : '—',
                 'Arctic Wolf MDR coverage',
                 mdrCov.available
                   ? mdrCov.matchedOrg + ' · w/c ' + (mdrCov.weekCommencing || mdrCov.weekKey) +
                     (mdrCov.stale ? ' · ' + mdrCov.ageDays + ' days old' : '')
                   : (REASON_TEXT[mdrCov.reason] || 'Unavailable — no discount applied.'),
                 mdrCov.available ? bandTone(mdrCov.band) : null)
          : '') +
      '</div>';

    el.hidden = false;
  }

  /**
   * The prose that qualifies the coverage figure: the vendor-discount
   * arithmetic, and which controls sit outside the services in scope.
   *
   * SEPARATED FROM THE STRIP ON PURPOSE. These lines used to sit directly under
   * the four tiles, inside a flex row that also held the unmeasured banner, the
   * estate note and the data-age box — six blocks of prose in narrow columns
   * either side of the gauge, none of them readable and the screen unusable.
   * The tiles are the answer; this is the working, and the working belongs
   * behind the explain panel where somebody who wants it can read it at a
   * sensible width.
   *
   * Returns a string so the caller decides where it goes — the strip renders
   * the same either way, which is what keeps this splittable at all.
   */
  function scopeDetailHtml(scoreData) {
    const scope = scoreData && scoreData.scope;
    if (!scope || !scope.recorded) return '';

    const cov = scoreData.coverage;
    const gaps = scope.uncovered || [];
    const mdrCov = scope.mdrCoverage || null;
    const discounted = scope.discountedPoints || 0;
    const nominal = scope.coverageNominal;

    return (
      /*
       * The arithmetic, spelled out. A coverage figure that moved for reasons a
       * reader cannot reconstruct is one they are entitled to dispute — and the
       * last clause is there because the commonest question about any vendor
       * number on this page is "did this change our score?".
       */
      (discounted > 0 && nominal != null && mdrCov && mdrCov.available
        ? '<p class="ss-scope-discount">Coverage ' + escHtml(String(cov)) + '% is ' +
            escHtml(String(nominal)) + '% of weighted posture covered by the services ' +
            'in scope, less ' + escHtml(String(discounted)) + ' points for Arctic Wolf ' +
            'MDR coverage of ' + escHtml(String(mdrCov.score)) + '%' +
            (mdrCov.matchedOrg ? ' (' + escHtml(mdrCov.matchedOrg) + ', w/c ' +
              escHtml(String(mdrCov.weekCommencing || mdrCov.weekKey)) + ')' : '') +
            '. The Overall Secure Score is unaffected.</p>'
        : '') +
      (gaps.length
        ? '<ul class="ss-scope-gaps">' + gaps.map(u =>
            `<li><strong>${escHtml(u.label)}</strong> — ${escHtml(String(u.pointsForfeited))} points, ` +
            (u.evidence === 'measured'
              ? 'measured, outside this engagement'
              : '<span class="ss-scope-blind">not measured</span>') +
            (u.closedBy && u.closedBy.length
              ? '. Covered by ' + escHtml(u.closedBy.join(' or ')) + '.' : '.') +
            '</li>').join('') + '</ul>'
        : ''));
  }

  /**
   * Banner naming the components with no data behind them and the score
   * ceiling they impose. Hidden entirely when everything is measured.
   */
  function renderUnmeasuredNote(el, scoreData) {
    if (!el) return;
    const missing = scoreData.unmeasured || [];
    if (!missing.length) { el.hidden = true; el.innerHTML = ''; return; }

    const names = missing.map(u => u.label).join(', ');
    const lost  = missing.reduce((n, u) => n + (u.pointsForfeited || 0), 0);
    const ceil  = scoreData.maxAchievable != null ? scoreData.maxAchievable : (100 - lost);

    el.hidden = false;
    el.innerHTML =
      '<strong>' + missing.length + ' component' + (missing.length > 1 ? 's have' : ' has') +
      ' no data: ' + names + '.</strong> ' +
      'These score zero rather than being excluded, because an unmeasured control ' +
      'is an unmanaged one. Until data is supplied the score cannot exceed ' +
      '<strong>' + ceil + '/100</strong> (' + lost + ' points unavailable).';
  }

  /**
   * A component's weight, from the payload rather than a constant.
   *
   * Weights follow the client's exposure now, so nothing may hardcode 40/35/25:
   * a card reading "40%" beside a score the engine weighted at 18% would not
   * reconcile with the composite printed above it. The fallbacks cover payloads
   * from an older server, where the weights really were fixed.
   */
  function pctOf(comp, fallback) {
    const w = comp && comp.weight;
    return (typeof w === 'number' && isFinite(w)) ? Math.round(w * 100) + '%' : fallback;
  }

  /** The same weight expressed as score points, for "recover up to N points". */
  function ptsOf(comp, fallback) {
    const w = comp && comp.weight;
    return (typeof w === 'number' && isFinite(w)) ? Math.round(w * 100) : fallback;
  }

  /**
   * The vulnerability card, which is now three different cards depending on
   * what the client actually has. Showing an endpoint-only client a breakdown
   * of infrastructure scan findings — or telling them to upload a scan — is
   * advice for somebody else's estate.
   *
   * `basis` is absent on payloads from an older server, in which case this
   * falls back to the infrastructure wording, matching previous behaviour.
   */
  function vulnCard(c) {
    const comp = c || {};
    const d = comp.detail || {};
    const basis = comp.basis || 'infrastructure';
    const measured = comp.measured !== false;
    const n = (v) => (v == null ? '—' : v);

    if (basis === 'endpoint') {
      return {
        label: 'Endpoint Hygiene', weight: pctOf(comp, '40%'),
        score: comp.score, measured,
        desc: d.endpoints
          ? n(d.currencyPct) + '% of ' + d.endpoints + ' endpoints patched and reporting'
          : 'Endpoint patch currency and agent health',
        missing: 'This client has endpoints and no in-scope infrastructure, so patch ' +
                 'currency is the measure — but no EDR agent data is available. ' +
                 'Connect the EDR feed to recover up to ' + ptsOf(comp, 40) + ' points.',
        tooltip: 'This client has <strong>no servers, public-facing assets or cloud ' +
                 'tenancies</strong> recorded, so an infrastructure scan is not expected ' +
                 'and its absence is not penalised.<br><br>' +
                 'Scored instead on endpoint hygiene:<br>' +
                 '• Base = % of agents up to date<br>' +
                 '• Agents not seen for 7 days deduct up to 30 pts<br>' +
                 '• Active threats deduct 5 pts each, up to 25<br><br>' +
                 'Change the estate on the Admin tab to switch measure.',
      };
    }

    if (basis === 'unknown') {
      return {
        label: 'Vulnerabilities', weight: pctOf(comp, '40%'),
        score: comp.score, measured: false,
        desc: 'Estate not recorded',
        missing: 'No estate has been recorded for this client, so the right measure ' +
                 'cannot be chosen. Record the server, public-facing asset and endpoint ' +
                 'counts on the Admin tab, then upload a scan or connect EDR.',
        tooltip: 'The vulnerability measure depends on what the client has. With no ' +
                 'estate recorded and no data supplied, this cannot be assessed and ' +
                 'scores 0.<br><br><strong>Record the estate on the Admin tab</strong> to ' +
                 'choose between infrastructure scanning and endpoint patch currency.',
      };
    }

    const scale = d.assets
      ? ' across ' + d.assets + ' asset' + (d.assets === 1 ? '' : 's') + ' scanned'
      : '';
    // A coverage ceiling and a criticals ceiling are different problems, and the
    // card must not describe one as the other: no amount of remediation lifts a
    // score that is held down by assets nobody looked at.
    const covPct = d.coverage != null ? Math.round(d.coverage * 100) : null;
    const ceiling = d.coverageCapped && covPct != null
      ? ' — held at ' + covPct + '/100 by scan coverage'
      : (d.capped ? ' — capped by open criticals' : '');
    return {
      label: 'Vulnerabilities', weight: pctOf(comp, '40%'),
      score: comp.score, measured,
      desc: d.density != null
        ? d.density + ' weighted findings per asset' + scale + ceiling
        : 'Based on critical, high, medium, and low findings',
      missing: 'No vulnerability scan uploaded. An unscanned estate is treated ' +
               'as unknown, not clean — upload a scan to recover up to ' +
               ptsOf(comp, 40) + ' points.',
      tooltip: 'Scored on finding <strong>density</strong>, so estate size does not ' +
               'decide the result:<br>' +
               '• Weighted findings = Critical×10, High×5, Medium×2, Low×0.5<br>' +
               '• Density = weighted findings ÷ assets in scope<br>' +
               '• Score = 100 ÷ (1 + density ÷ 3)<br><br>' +
               'Open criticals then cap the score regardless of estate size ' +
               '(1 critical caps at 65, 3 at 50, 5 at 40, 10 at 30), so a dangerous ' +
               'finding cannot be diluted away by a large estate.<br><br>' +
               '<strong>Scan coverage caps it too:</strong> the score cannot exceed ' +
               'the share of the <strong>external-facing</strong> assets the scan ' +
               'actually reached. An unscanned asset is unexamined, not clean — and ' +
               'it is usually the same asset missing from managed patching and the ' +
               'MDR feed.<br><br>' +
               'The scan is external-facing only. Servers and cloud tenancies are ' +
               'never in its scope, so they do not count against coverage here — ' +
               'their patch state is covered by managed patching instead.<br><br>' +
               '<strong>No data scores 0</strong>, because an unmeasured control is an ' +
               'unmanaged one.',
    };
  }

  /**
   * A line under the component cards naming the estate the score was computed
   * against, and where each number came from. The denominator is doing real
   * work now, so it has to be visible and challengeable.
   */
  function renderEstateNote(el, scoreData) {
    if (!el) return;
    const e = scoreData && scoreData.estate;
    if (!e) { el.hidden = true; el.innerHTML = ''; return; }

    const FIELDS = [
      ['servers', 'servers'],
      ['publicAssets', 'public-facing assets'],
      ['endpoints', 'endpoints'],
      ['cloudTenancies', 'cloud tenancies'],
    ];
    const parts = FIELDS
      .filter(([k]) => e[k] != null)
      .map(([k, label]) => {
        const src = (e.sources || {})[k];
        const tag = src === 'derived' ? ' <span class="estate-src">(detected)</span>' : '';
        return '<strong>' + e[k] + '</strong> ' + label + tag;
      });

    // Computed before the no-estate branch: an awareness declaration is a claim
    // about a control, not about assets, so it applies to a client who has
    // declared nothing else — and that is exactly when it needs explaining.
    const w = scoreData.weights;
    let awareness = '';
    if (w && w.awarenessProgram === 'internal') {
      // No longer a weighting claim. The relief that used to halve the
      // awareness weight is gone — a dropdown must not move a weight — so this
      // says what is actually true: we have no figures, and that is a gap in
      // evidence rather than a finding about their training.
      awareness = ' This client runs their <strong>own awareness programme</strong> ' +
        'and no completion figures have been recorded, so it scores zero at full ' +
        'weight. That is a gap in evidence, not a verdict on their training — ' +
        'record their figures to recover the points.';
    }

    if (!parts.length) {
      el.hidden = false;
      el.innerHTML = 'No estate recorded for this client, so the vulnerability measure ' +
        'cannot be sized. <strong>Record it on the Admin tab.</strong>' + awareness;
      el.className = 'score-estate-note warn';
      return;
    }

    // Scan scope, and what it leaves unexamined. Stating the gap in assets
    // rather than only as a percentage keeps it concrete: "12 assets nobody
    // looked at" is actionable in a way that "76% coverage" is not.
    // Scan scope, against the EXTERNAL estate — the only population the scan
    // addresses. Measuring it against servers would cap a client at 11/100 for
    // owning infrastructure the scan was never going to touch.
    let extra = '';
    if (e.scannedHosts != null) {
      extra = ' Last scan reached <strong>' + e.scannedHosts + '</strong> host' +
        (e.scannedHosts === 1 ? '' : 's');
      const ext = e.scannableAssets || 0;
      const gap = ext - e.scannedHosts;
      const derived = (e.sources || {}).publicAssets === 'derived';
      extra += (gap > 0)
        ? ' of <strong>' + ext + '</strong> external-facing assets recorded — <strong>' +
          gap + '</strong> unexamined, which caps this component at ' +
          Math.round((e.scannedHosts / ext) * 100) + '/100.'
        // Derived: the external estate IS the scan's reach, so coverage is
        // complete by construction. Say so, rather than showing a silent 100%
        // that looks like a verified result.
        : (derived
            ? ', which is what the external estate is taken to be. ' +
              '<span class="estate-src">(no declared asset count to check it against)</span>'
            : '.');
    }

    // The scan found internet-facing hosts the client has not recorded. Not a
    // scoring problem — but an unrecorded internet-facing host is one nobody owns.
    if (e.undeclaredExternal > 0) {
      extra += ' <strong>' + e.undeclaredExternal + '</strong> scanned host' +
        (e.undeclaredExternal === 1 ? ' is' : 's are') + ' not in the recorded asset ' +
        'inventory.';
    }

    // The internal estate the scan cannot reach at all. Stated separately so a
    // clean external scan is never read as a clean estate.
    if (e.unscannableAssets > 0) {
      extra += ' <strong>' + e.unscannableAssets + '</strong> internal asset' +
        (e.unscannableAssets === 1 ? '' : 's') + ' (servers, cloud) sit outside the ' +
        'external scan entirely — their patch state is covered by managed patching, ' +
        'not by this component.';
    }

    // The weighting is the part a client is most likely to challenge, so state
    // it plainly: what each component is worth, and on what basis.
    //
    // It used to describe an exposure figure, a headcount split, a managed-
    // patching relief and a ticket-load pull — four moving parts, all driven by
    // numbers typed into the Client Profile, any of which could move the
    // composite by double digits. There is now one thing to say, and a client
    // can check it against their own contract.
    let weighting = '';
    if (w && w.basis) {
      const trio = Math.round(w.vulnerabilities * 100) + '% vulnerability management / ' +
        Math.round(w.awareness * 100) + '% security awareness / ' +
        Math.round(w.incidentResponse * 100) + '% incident response';

      if (w.basis === 'services') {
        // Plain text, NOT pre-escaped: the list goes through escHtml() below, so
        // an "&amp;" here was escaped a second time and printed literally as
        // "Managed Detection &amp;amp; Response" on the client's screen.
        const names = {
          vuln: 'Vulnerability Management',
          awareness: 'Security Awareness Training',
          mdr: 'Managed Detection & Response',
        };
        const bought = (w.weightedServices || []).map(function (k) { return names[k] || k; });
        const list = bought.length > 1
          ? bought.slice(0, -1).join(', ') + ' and ' + bought[bought.length - 1]
          : (bought[0] || '');
        weighting = ' Weighted for a client on <strong>' + escHtml(list) + '</strong>: ' +
          trio + '. These weights follow the service mix and do not move with the estate.';
      } else if (w.basis === 'none') {
        weighting = ' This client is recorded as buying none of the three scored ' +
          'services, so the standard ' + trio + ' applies and service coverage is 0%.';
      } else {
        // 'not-recorded' — the default, and NOT a claim that they buy nothing.
        weighting = ' No service mix is recorded, so the standard ' + trio +
          ' applies. That is the default, not a statement that this client buys ' +
          'nothing — <strong>record the mix on the Client Profile.</strong>';
      }
    }

    /*
     * How old the estate is, and where it disagrees with the telemetry.
     *
     * BOTH ARE CAVEATS ON THE NUMBER ABOVE, NOT ADJUSTMENTS TO IT. The score
     * was computed from the declaration exactly as recorded — an old figure is
     * not discounted and a disputed one is not overridden — so the wording has
     * to say that plainly. An analyst who reads this as "the score has been
     * reduced for staleness" would be wrong, and would explain it wrongly in
     * front of a client.
     */
    const age = e.age || {};
    const stale = age.stale
      ? ' <span class="score-estate-stale">This estate was last confirmed ' +
        age.days + ' days ago and has been used exactly as recorded — ' +
        'nothing was discounted for age. Review it on the Client Profile tab.</span>'
      : '';

    const conflicts = (e.conflicts || []).filter(c => c.severity === 'high');
    const disputed = conflicts.length
      ? ' <span class="score-estate-stale">' + conflicts.length +
        ' recorded figure' + (conflicts.length === 1 ? '' : 's') +
        ' disagree' + (conflicts.length === 1 ? 's' : '') +
        ' with what we can see. The recorded figures were used. ' +
        'See the Client Profile tab.</span>'
      : '';

    el.hidden = false;
    el.className = 'score-estate-note';
    el.innerHTML = 'Scored against an estate of ' + parts.join(', ') + '.' + extra +
      weighting + awareness + stale + disputed;
  }

  /**
   * What to say on an awareness card with no figures behind it.
   *
   * A client running their own programme must not be told to "upload training
   * records" as though they had none — that is advice for someone else's
   * problem, and it hides the thing they can actually do.
   */
  function awarenessMissingText(comp, weights) {
    const pts = ptsOf(comp, 35);
    if (weights && weights.awarenessProgram === 'internal') {
      return 'This client runs their own awareness programme, and no completion ' +
             'figures have been recorded, so this component scores zero at full ' +
             'weight. That is a gap in evidence, not a verdict on their training. ' +
             'Record their completion figures on the Awareness tab to recover up ' +
             'to ' + pts + ' points.';
    }
    if (weights && weights.awarenessProgram === 'none') {
      return 'No awareness programme is in place, so this scores zero at full ' +
             'weight (' + pts + ' points).';
    }
    return 'No awareness training data uploaded — upload training records, or ' +
           'record an internally run programme on the Admin tab, to recover up ' +
           'to ' + pts + ' points.';
  }

  /**
   * The caption under the Incident Response score: which month, and how many
   * tickets it was drawn from.
   *
   * The score used to be computed over the entire uploaded feed, so "Ticket
   * resolution & speed" was the whole story anyone was given about a number
   * that might have covered two years. It is now one month's cohort, and a
   * reader who cannot see which month cannot check the figure.
   *
   * Falls back to the old caption on a payload from a server that predates
   * this, rather than printing a month it does not have.
   */
  function mdrCohortText(comp) {
    const c = comp || {};
    const d = c.detail;
    if (!c.period || !d) return 'Ticket resolution & speed';

    const when = monthLabel(c.period);
    if (!d.raised) {
      // Not a gap in the data — a month in which nothing needed responding to.
      // Saying "no tickets" beside a score of 100 stops it reading as a fault.
      return 'No tickets raised in ' + when + ' — nothing to respond to';
    }
    return d.resolved + ' of ' + d.raised + ' ticket' + (d.raised === 1 ? '' : 's') +
           ' raised in ' + when + ' resolved';
  }

  /** 'YYYY-MM' as a readable month. Returns the key itself if it is malformed. */
  function monthLabel(key) {
    const m = /^(\d{4})-(\d{2})$/.exec(String(key || ''));
    if (!m) return String(key || '');
    const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, 1));
    return d.toLocaleDateString('en-ZA', { month: 'long', year: 'numeric', timeZone: 'UTC' });
  }

  function renderComponentScores(container, components, weights) {
    // `measured` comes from the scoring engine. A component with no data
    // scores 0 by design — an unmeasured control is an unmanaged one — but the
    // card MUST say so, or a client reads "0/100" as a scan they failed rather
    // than one nobody uploaded. Older payloads without the flag are treated as
    // measured, which keeps the previous behaviour.
    const wasMeasured = (c) => c && c.measured !== false;

    const items = [
      vulnCard(components.vulnerabilities),
      {
        label: 'Security Awareness', weight: pctOf(components.awareness, '35%'),
        score: components.awareness.score,
        measured: wasMeasured(components.awareness),
        desc: 'Training completion rate',
        missing: awarenessMissingText(components.awareness, weights),
        tooltip: 'Score = % of training sessions completed (phishing simulations excluded).<br>100% completion = 100/100.<br><br><strong>No data scores 0</strong>, because an unmeasured control is an unmanaged one.',
      },
      {
        label: 'Incident Response', weight: pctOf(components.incidentResponse, '25%'),
        score: components.incidentResponse.score,
        measured: wasMeasured(components.incidentResponse),
        desc: mdrCohortText(components.incidentResponse),
        missing: 'No MDR or incident data available — connect the MDR feed to ' +
                 'recover up to ' + ptsOf(components.incidentResponse, 25) + ' points.',
        tooltip: 'Scored on the tickets <strong>raised in the last complete ' +
                 'calendar month</strong>, followed through to whenever they ' +
                 'were resolved — one cohort, so the resolution rate cannot ' +
                 'exceed 100%.<br>• Resolution rate forms the base score.<br>' +
                 '• Avg resolution &gt; 24 hrs deducts up to 20 pts.<br>' +
                 '• A month with no tickets scores 100 — nothing needed doing.' +
                 '<br><br>This used to score the <em>whole uploaded feed</em>, ' +
                 'so a client who exported two years of history was judged on ' +
                 'two years of it.<br><br><strong>No data scores 0</strong>, ' +
                 'because an unmeasured control is an unmanaged one.',
      },
    ];

    const html = `
      <div class="component-scores">
        ${items.map(item => `
          <div class="component-card${item.measured ? '' : ' component-unmeasured'}">
            <div class="component-header">
              <h4>${item.label}</h4>
              <div class="component-header-right">
                <span class="component-weight">(${item.weight})</span>
                <div class="score-tooltip-wrap">
                  <button class="score-info-btn" aria-label="How is this calculated?">?</button>
                  <div class="score-tooltip" role="tooltip">${item.tooltip}</div>
                </div>
              </div>
            </div>
            <div class="component-score-bar">
              <div class="score-bar-fill" data-score="${item.score}"
                   style="width: 0%; background-color: ${getScoreColor(item.score)};"></div>
            </div>
            <div class="component-score-text">
              ${item.score}/100${item.measured ? '' : ' <span class="component-nodata-tag">No data</span>'}
            </div>
            <small>${item.measured ? item.desc : item.missing}</small>
          </div>
        `).join('')}
      </div>
    `;
    container.innerHTML = html;

    // Animate bars in after paint
    setTimeout(() => {
      container.querySelectorAll('.score-bar-fill').forEach(bar => {
        bar.style.width = bar.dataset.score + '%';
      });
    }, 60);
  }

  function renderRecommendations(container, recommendations) {
    if (!recommendations || recommendations.length === 0) {
      container.innerHTML = '<p>No recommendations at this time.</p>';
      return;
    }

    const html = recommendations
      .map(rec => {
        const priorityClass = `priority-${rec.priority}`;
        const icon =
          rec.priority === 'high' ? '🔴' :
          rec.priority === 'medium' ? '🟡' :
          '✅';

        return `
          <div class="recommendation-card ${priorityClass}">
            <div class="recommendation-header">
              <span class="recommendation-icon">${icon}</span>
              <div>
                <h5>${rec.area}</h5>
                <small>${rec.priority.toUpperCase()} | Impact: ${rec.impact}</small>
              </div>
            </div>
            <p>${rec.suggestion}</p>
          </div>
        `;
      })
      .join('');

    container.innerHTML = html;
  }

  function formatMonthLabel(monthKey) {
    const [year, month] = monthKey.split('-');
    const d = new Date(parseInt(year), parseInt(month) - 1, 1);
    return d.toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
  }

  function renderTrendChart(container, history, grcScore) {
    if (!history || history.length === 0) {
      container.innerHTML = '<p style="color:var(--muted);padding:1rem 0">Insufficient data for trend chart.</p>';
      return;
    }

    container.innerHTML = '<canvas id="secure-score-chart" style="max-height:220px"></canvas>';
    const canvas = container.querySelector('canvas');

    if (_trendChart) { _trendChart.destroy(); _trendChart = null; }

    // Reverse so oldest is on the left
    const sorted = [...history].reverse();

    const datasets = [{
      label: 'Secure Score',
      data: sorted.map(h => h.score),
      borderColor: '#00b4d8',
      backgroundColor: 'rgba(0,180,216,0.06)',
      tension: 0.35,
      pointRadius: 5,
      pointBackgroundColor: sorted.map(h => getScoreColor(h.score)),
      pointBorderColor: '#fff',
      pointBorderWidth: 2,
      fill: true,
    }];

    // Add Insurability Score line when GRC score is available
    if (grcScore !== null) {
      datasets.push({
        label: 'Insurability Score',
        data: sorted.map(h => Math.round(h.score * 0.6 + grcScore * 0.4)),
        borderColor: '#6366f1',
        backgroundColor: 'rgba(99,102,241,0.04)',
        tension: 0.35,
        pointRadius: 4,
        pointBackgroundColor: '#6366f1',
        pointBorderColor: '#fff',
        pointBorderWidth: 2,
        borderDash: [4, 3],
        fill: false,
      });
    }

    _trendChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: sorted.map(h => formatMonthLabel(h.monthKey)),
        datasets,
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        scales: {
          y: {
            min: 0,
            max: 100,
            ticks: { stepSize: 25, color: '#7a9bb0' },
            grid: { color: 'rgba(0,0,0,0.06)' },
          },
          x: {
            ticks: { color: '#7a9bb0' },
            grid: { display: false },
          },
        },
        plugins: {
          legend: { display: grcScore !== null, labels: { color: '#7a9bb0', boxWidth: 12, padding: 16 } },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.dataset.label}: ${ctx.parsed.y}/100`,
            },
          },
        },
      },
    });
  }

  function renderInsurabilityPanel(container, scoreData, history, grcData) {
    const ssScore  = Math.round(scoreData.score);
    const grcAsmt  = grcData && grcData.assessment;
    const grcScore = grcAsmt ? (grcAsmt.grc_score || 0) : null;
    const hasGrc   = grcScore !== null;

    const insScore = hasGrc
      ? Math.round(ssScore * 0.6 + grcScore * 0.4)
      : ssScore;

    // 3-month trend (uses secure score history, index 0 = most recent)
    let trend = 0;
    if (history.length >= 2) {
      const recent = history.slice(0, Math.min(3, history.length)).map(h => h.score);
      const avgRecent = recent.reduce((s, v) => s + v, 0) / recent.length;
      trend = Math.round(ssScore - avgRecent);
    }

    // Determine direction
    let dirKey, dirArrow, dirLabel;
    if (insScore >= 75 && trend >= 3) {
      dirKey = 'reduce';  dirArrow = '↓'; dirLabel = 'Premium Reduction Likely';
    } else if (insScore >= 75) {
      dirKey = 'stable';  dirArrow = '→'; dirLabel = 'Premium Likely Maintained';
    } else if (insScore >= 60 && trend >= -3) {
      dirKey = 'neutral'; dirArrow = '→'; dirLabel = 'Neutral — Monitor Position';
    } else if (insScore >= 50 || trend < -3) {
      dirKey = 'risk';    dirArrow = '↑'; dirLabel = 'Premium Increase Risk';
    } else {
      dirKey = 'likely';  dirArrow = '↑↑'; dirLabel = 'Premium Increase Likely';
    }

    const insColor = getScoreColor(insScore);

    // Trend note
    const trendAbs = Math.abs(trend);
    const trendDir = trend > 0 ? 'improved' : trend < 0 ? 'declined' : 'unchanged';
    const trendNote = history.length >= 2
      ? `Score has ${trendDir}${trendAbs > 0 ? ` by ${trendAbs} points` : ''} over the last ${Math.min(3, history.length)} months.`
      : 'Insufficient history for trend analysis.';

    // Risk drivers — pick top 3 weakest signals
    const drivers = [];
    const comp = scoreData.components || {};
    const compItems = [
      { label: 'Vulnerabilities',    score: (comp.vulnerabilities || {}).score || 0,    weight: pctOf(comp.vulnerabilities, '40%') },
      { label: 'Security Awareness', score: (comp.awareness || {}).score || 0,          weight: pctOf(comp.awareness, '35%') },
      { label: 'Incident Response',  score: (comp.incidentResponse || {}).score || 0,   weight: pctOf(comp.incidentResponse, '25%') },
    ];
    compItems.sort((a, b) => a.score - b.score).forEach(c => {
      const dotCls = c.score >= 70 ? 'driver-dot-green' : c.score >= 40 ? 'driver-dot-amber' : 'driver-dot-red';
      drivers.push({ dot: dotCls, text: `${c.label}: ${c.score}/100 (${c.weight} of Secure Score)` });
    });

    // Add GRC note if missing
    if (!hasGrc) {
      drivers.unshift({ dot: 'driver-dot-amber', text: 'GRC assessment not completed — adds 40% weight to Insurability Score' });
    }

    const breakdownNote = hasGrc
      ? `Secure Score (${ssScore}) × 60% + GRC Score (${grcScore}) × 40%`
      : `Based on Secure Score only — complete GRC assessment for full insurability score`;

    container.innerHTML = `
      <div class="insurability-panel">
        <h3 class="secure-score-section-title">Insurability Score &amp; Premium Outlook</h3>
        <div class="insurability-body">
          <div class="insurability-score-block">
            <div class="insurability-score-number" style="color:${insColor}">${insScore}</div>
            <div class="insurability-score-label">Insurability Score</div>
            <div class="insurability-score-breakdown">${breakdownNote}</div>
          </div>
          <div class="insurability-direction-block">
            <div class="insurability-direction-badge direction-${dirKey}">
              <span class="direction-icon">${dirArrow}</span>
              <span class="direction-label">${dirLabel}</span>
            </div>
            <p class="insurability-trend-note">${trendNote}</p>
            <div class="insurability-drivers">
              <div class="drivers-title">Key Risk Drivers</div>
              ${drivers.slice(0, 3).map(d => `
                <div class="driver-item">
                  <span class="driver-dot ${d.dot}"></span>
                  <span>${d.text}</span>
                </div>`).join('')}
            </div>
          </div>
        </div>
      </div>`;
  }

  async function fetchGrcSummary() {
    try {
      const res = await fetch('api/grc/assessment');
      if (!res.ok) return null;
      return await res.json();
    } catch (_) { return null; }
  }

  async function loadAndRender() {
    const container = document.getElementById('secure-score-container');
    if (container) {
      container.innerHTML = '<div class="loading-overlay"><div class="loading-spinner"></div><span>Loading score…</span></div>';
    }

    const [scoreData, historyData, grcData] = await Promise.all([
      fetchSecureScore(), fetchScoreHistory(), fetchGrcSummary(),
    ]);

    if (!scoreData) {
      if (container) container.innerHTML = '<div class="error-message" style="padding:2rem;color:var(--red)">Failed to load Secure Score data.</div>';
      return;
    }

    // Compute month-over-month delta
    // Tolerate both {history:[...]} and a bare array. A truthy payload without
    // a `history` key threw here and took the whole tab down with it.
    const history = (historyData && (historyData.history ||
      (Array.isArray(historyData) ? historyData : null))) || [];
    let delta = null;
    if (history.length >= 2) {
      delta = Math.round(scoreData.score) - Math.round(history[1].score);
    }

    // Build report header info
    const reportDate = new Date().toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });
    const user = window.currentUser || {};
    const tenantLabel = user.username ? `Prepared by: ${user.username}` : '';

    // Restore the original inner structure (wipe spinner)
    if (container) {
      container.innerHTML = `
        <div class="print-report-header">
          <div class="print-report-logo">Security Posture Report</div>
          <div class="print-report-meta">
            ${tenantLabel ? `<span>${tenantLabel}</span>` : ''}
            <span>Generated: ${reportDate}</span>
          </div>
        </div>
        <div class="score-header-bar">
          <button id="secure-score-refresh" class="score-action-btn" title="Refresh score">&#x21BB; Refresh</button>
          <button id="secure-score-report" class="score-action-btn score-report-btn" title="Generate Exco report">&#128196; Generate Report</button>
          <button id="secure-score-print" class="score-action-btn" title="Print or save as PDF">&#x2399; Export</button>
        </div>
        <!--
          THE SCREEN IS THE FIGURES; THE WORKING IS ONE HOVER AWAY.

          This row previously held the gauge, the scope tiles, the unmeasured
          banner, the estate-and-weighting note and the data-age box as six
          flex children. On any real screen that squeezed four paragraphs of
          prose into columns a few words wide beside the gauge — unreadable,
          and it pushed the component cards below the fold.

          None of that prose was deleted: every client-facing number on this
          page still has to be explainable line by line, and it all moved into
          #secure-score-explain, which opens on hover or focus and prints
          expanded. What changed is that you now choose when to read it.
        -->
        <div class="secure-score-main">
          <div class="ss-headline">
            <div class="ss-explain-wrap">
              <div id="secure-score-gauge" class="score-gauge-container"></div>
              <button id="secure-score-explain-btn" class="ss-explain-btn"
                      type="button" aria-expanded="false"
                      aria-controls="secure-score-explain">How this score is calculated</button>
              <div id="secure-score-explain" class="ss-explain" role="tooltip">
                <div id="secure-score-unmeasured" class="score-unmeasured-note" hidden></div>
                <div id="secure-score-scope-detail" class="ss-scope-detail"></div>
                <div id="secure-score-estate" class="score-estate-note" hidden></div>
                <div id="secure-score-data-age" class="data-age-info"></div>
              </div>
            </div>
          </div>
          <div id="secure-score-scope" class="ss-scope" hidden></div>
          <div id="secure-score-grc-indicator"></div>
        </div>
        <div id="secure-score-insurability" class="secure-score-section"></div>
        <div id="secure-score-components" class="secure-score-section"></div>
        <div class="secure-score-section">
          <h3 class="secure-score-section-title">6-Month Trend</h3>
          <div id="secure-score-trend" class="trend-chart-container"></div>
        </div>
        <div class="secure-score-section">
          <h3 class="secure-score-section-title">Improvement Recommendations</h3>
          <div id="secure-score-recommendations" class="recommendations-container"></div>
        </div>
        <div id="ms-secure-score" class="secure-score-section"></div>
      `;

      document.getElementById('secure-score-refresh').addEventListener('click', loadAndRender);
      document.getElementById('secure-score-report').addEventListener('click', async () => {
        // Reserved before any await — see reserveReportWindow().
        const _handle = window.ReportShell.reserveReportWindow({
          width: 1060, height: 860, title: 'Executive Report',
        });
        if (!_handle) return;
        let data = currentScore, hist = _cachedHistory, grc = _cachedGrcData;
        if (!data) {
          const btn = document.getElementById('secure-score-report');
          const origText = btn.textContent;
          btn.textContent = 'Generating…';
          btn.disabled = true;
          [data, hist, grc] = await Promise.all([fetchSecureScore(), fetchScoreHistory(), fetchGrcSummary()]);
          btn.textContent = origText;
          btn.disabled = false;
          if (!data) {
            _handle.fail('Unable to load score data. Please refresh and try again.');
            return;
          }
        }
        await generateExcoReport(_handle, data, hist || [], grc);
      });
      /*
       * The explain panel opens on hover through CSS alone, which covers the
       * mouse. This is the keyboard and touch path: hover does not exist on a
       * phone, and a pointer-driven-only disclosure would put the entire
       * explanation of a client-facing score out of reach for anyone not using
       * a mouse. `aria-expanded` drives a class so the CSS has one selector to
       * honour for both routes.
       */
      const explainBtn = document.getElementById('secure-score-explain-btn');
      if (explainBtn) {
        const wrap = explainBtn.closest('.ss-explain-wrap');
        explainBtn.addEventListener('click', () => {
          const open = explainBtn.getAttribute('aria-expanded') === 'true';
          explainBtn.setAttribute('aria-expanded', open ? 'false' : 'true');
          if (wrap) wrap.classList.toggle('is-open', !open);
        });
        // Escape closes it, because a panel this tall can cover the tiles
        // beneath it and a keyboard user needs a way out that is not a click.
        explainBtn.addEventListener('keydown', (ev) => {
          if (ev.key !== 'Escape') return;
          explainBtn.setAttribute('aria-expanded', 'false');
          if (wrap) wrap.classList.remove('is-open');
        });
      }

      document.getElementById('secure-score-print').addEventListener('click', () => {
        // Temporarily remove hidden attribute so CSS can show the panel even if another tab is active
        const panel = document.getElementById('tab-secure-score');
        const wasHidden = panel && panel.hasAttribute('hidden');
        if (wasHidden) panel.removeAttribute('hidden');

        const restore = () => {
          if (wasHidden) panel.setAttribute('hidden', '');
          window.removeEventListener('afterprint', restore);
        };
        window.addEventListener('afterprint', restore);
        window.print();
      });
    }

    currentScore = scoreData;

    /*
     * The gauge shows the IN-SCOPE score where a service mix is on file.
     *
     * The composite counts controls the client never bought as zero, so an
     * awareness-only client's gauge read 35 while the service they pay for
     * scored 100. Coverage and the overall figure sit beneath it, named, so
     * all three are visible and none of them has to carry two meanings.
     *
     * The delta is dropped when scoped: history stores composites, and an
     * arrow comparing an in-scope score against a past overall would be
     * pointing at a difference in measure rather than in posture.
     */
    const scoped = !!(scoreData.scope && scoreData.scope.recorded &&
                      scoreData.serviceScore != null);
    const gaugeValue = scoped ? scoreData.serviceScore : scoreData.score;

    const gaugeContainer = document.getElementById('secure-score-gauge');
    renderScoreGauge(gaugeContainer, gaugeValue, scoped ? null : delta);

    renderScopeStrip(document.getElementById('secure-score-scope'), scoreData);

    // The coverage working, behind the explain panel with the rest of the prose.
    const scopeDetailEl = document.getElementById('secure-score-scope-detail');
    if (scopeDetailEl) scopeDetailEl.innerHTML = scopeDetailHtml(scoreData);

    // State the ceiling explicitly when components have no data behind them.
    // Without this the score looks like a verdict on the client's security,
    // when part of it is really a verdict on what has been uploaded.
    renderUnmeasuredNote(document.getElementById('secure-score-unmeasured'), scoreData);
    renderEstateNote(document.getElementById('secure-score-estate'), scoreData);

    // Render insurability panel
    const insurabilityContainer = document.getElementById('secure-score-insurability');
    if (insurabilityContainer) renderInsurabilityPanel(insurabilityContainer, scoreData, history, grcData);

    // Render component scores
    const componentContainer = document.getElementById('secure-score-components');
    renderComponentScores(componentContainer, scoreData.components, scoreData.weights);

    // Render trend chart (pass grc score for insurability overlay line)
    const trendContainer = document.getElementById('secure-score-trend');
    const grcScoreVal = (grcData && grcData.assessment) ? (grcData.assessment.grc_score || 0) : null;
    renderTrendChart(trendContainer, history, grcScoreVal);

    // Render recommendations
    const recommendationContainer = document.getElementById('secure-score-recommendations');
    renderRecommendations(recommendationContainer, scoreData.recommendations);

    /*
     * Render data age.
     *
     * `dataAge` is defaulted and each field escaped, matching buildAppendix()
     * further down — which already guarded and so kept working while this copy
     * did not. An unguarded read here threw mid-render, after the gauge had
     * drawn and before the GRC indicator, leaving a half-built screen with no
     * error on it. That is the same failure the history payload caused earlier
     * in this function, and it is guarded for the same reason.
     */
    const dataAgeContainer = document.getElementById('secure-score-data-age');
    if (dataAgeContainer) {
      const da = scoreData.dataAge || {};
      const age = v => escHtml(v === null || v === undefined ? 'Unknown' : v);
      dataAgeContainer.innerHTML = `
        <div class="data-age">
          <small>
            <strong>Last Updated:</strong><br>
            Vulnerabilities: ${age(da.vulns)}<br>
            Awareness: ${age(da.awareness)}<br>
            Incidents: ${age(da.mdr)}
          </small>
        </div>
      `;
    }

    // Cache for report generation
    _cachedHistory = history;
    _cachedGrcData = grcData;

    // Render GRC indicator
    const grcEl = document.getElementById('secure-score-grc-indicator');
    if (grcEl) {
      const grcAsmt = grcData && grcData.assessment;
      if (grcAsmt) {
        const grcScore = grcAsmt.grc_score || 0;
        /*
         * One colour scale for the whole screen.
         *
         * This used to band at 80/60/40 while getScoreColor() — which paints
         * the gauge, the component cards and the trend directly above it —
         * bands at 80/70/50. Two 0-100 security scores sat side by side in the
         * same four colours meaning different things: a GRC score of 65 read
         * amber, a composite of 65 read dark orange, and nothing on screen said
         * the scales differed. Whichever banding is right, the answer cannot be
         * "both on one screen".
         */
        const grcColor = getScoreColor(grcScore);
        const grcDate  = new Date(grcAsmt.assessed_at).toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
        grcEl.innerHTML = `
          <div class="grc-indicator-card">
            <div class="grc-indicator-score" style="color:${grcColor}">${grcScore}<span>/100</span></div>
            <div class="grc-indicator-label">GRC Score</div>
            <div class="grc-indicator-sub">Assessed: ${grcDate}</div>
            <a class="grc-indicator-link" href="#" onclick="event.preventDefault();window.switchTab('grc')">View assessment →</a>
          </div>`;
      } else {
        grcEl.innerHTML = `
          <div class="grc-indicator-card grc-indicator-empty">
            <div class="grc-indicator-label">GRC Score</div>
            <div class="grc-indicator-sub">Not yet assessed</div>
            <a class="grc-indicator-link" href="#" onclick="event.preventDefault();window.switchTab('grc')">Start assessment →</a>
          </div>`;
      }
    }

    /*
     * Microsoft Secure Score, last and deliberately unawaited.
     *
     * Unawaited because it is an independent panel that renders its own empty
     * and error states — blocking the client's own posture report on a second
     * round trip would make our score slower to appear for the benefit of a
     * number that is explicitly not part of it.
     *
     * The optional-chain guard is not defensive padding: the module is a
     * separate script tag, and a deployment that ships this file without it
     * must degrade to "no Microsoft panel", not to a tab that throws on load.
     */
    const msEl = document.getElementById('ms-secure-score');
    if (msEl && window.MsSecureScorePanel) {
      window.MsSecureScorePanel.render(msEl);
    }
  }

  // ── Exco Report Generation ────────────────────────────────────────────────

  function hexToRgba(hex, alpha) {
    return window.ReportShell.hexToRgba(hex, alpha);
  }

  function buildGaugeSvg(score) {
    const color = getScoreColor(score);
    const w = 220, h = 130, cx = 110, cy = 122, r = 92;
    const arcLen = Math.PI * r;
    const fillOffset = arcLen * (1 - score / 100);
    return `
      <svg width="100%" viewBox="0 0 ${w} ${h}" style="display:block;max-width:${w}px;margin:0 auto">
        <path d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}"
              fill="none" stroke="#dde8f0" stroke-width="13" stroke-linecap="round"/>
        <path d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}"
              fill="none" stroke="${color}" stroke-width="13" stroke-linecap="round"
              stroke-dasharray="${arcLen}" stroke-dashoffset="${fillOffset}"/>
        <text x="${cx}" y="${cy - 24}" text-anchor="middle"
              font-size="46" font-weight="700" fill="${color}"
              font-family="Segoe UI,Arial,sans-serif">${score}</text>
        <text x="${cx}" y="${cy - 6}" text-anchor="middle"
              font-size="12" fill="#6b7c93"
              font-family="Segoe UI,Arial,sans-serif">out of 100</text>
      </svg>`;
  }

  function buildTrendSvg(hist) {
    if (!hist || hist.length < 2) {
      return '<p style="color:#999;font-style:italic;padding:12px 0">Insufficient history data.</p>';
    }
    const sorted = [...hist].reverse();
    const W = 580, H = 120, pad = 40;
    const xs = sorted.map((_, i) => pad + (i / (sorted.length - 1)) * (W - pad * 2));
    const ys = sorted.map(h => H - pad / 2 - ((h.score / 100) * (H - pad)));
    const pts = xs.map((x, i) => `${x},${ys[i]}`).join(' ');
    const gridLines = [25, 50, 75, 100].map(v => {
      const y = H - pad / 2 - ((v / 100) * (H - pad));
      return `<line x1="${pad}" y1="${y}" x2="${W - pad}" y2="${y}" stroke="#e8edf2" stroke-width="1"/>
              <text x="${pad - 6}" y="${y + 4}" text-anchor="end" font-size="10" fill="#9aacba">${v}</text>`;
    }).join('');
    const dots = sorted.map((h, i) => {
      return `<circle cx="${xs[i]}" cy="${ys[i]}" r="5"
                      fill="${getScoreColor(h.score)}" stroke="#fff" stroke-width="2"/>`;
    }).join('');
    const labels = sorted.map((h, i) =>
      `<text x="${xs[i]}" y="${H + 15}" text-anchor="middle" font-size="10" fill="#6b7c93"
             font-family="Segoe UI,Arial,sans-serif">${formatMonthLabel(h.monthKey)}</text>`
    ).join('');
    return `
      <svg width="100%" viewBox="0 0 ${W} ${H + 24}" style="overflow:visible;display:block">
        ${gridLines}
        <polyline points="${pts}" fill="none" stroke="#00b4d8"
                  stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>
        ${dots}
        ${labels}
      </svg>`;
  }

  function buildComponentBar(score) {
    const color = getScoreColor(score);
    return `<div style="background:#eef2f6;border-radius:4px;height:9px;margin:6px 0 2px;overflow:hidden">
              <div style="width:${score}%;height:100%;background:${color};border-radius:4px"></div>
            </div>`;
  }

  function buildCompCard(label, weight, score, desc) {
    const color = getScoreColor(score);
    return `
      <div style="border:1px solid #CFD8DC;border-radius:10px;padding:20px;page-break-inside:avoid;break-inside:avoid;border-top:3px solid #1565C0">
        <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#78909C;margin-bottom:6px">
          ${label} <span style="font-size:0.68rem;background:#EEF2F7;border-radius:3px;padding:2px 6px;margin-left:4px">${weight}</span>
        </div>
        <div style="font-size:2rem;font-weight:800;color:${color};line-height:1">${score}</div>
        ${buildComponentBar(score)}
        <div style="font-size:0.78rem;color:#90A4AE;margin-top:4px">${desc}</div>
      </div>`;
  }

  function buildHeadline(score, rating, delta) {
    if (score >= 80) return 'Strong security posture — your organisation is well-positioned against cyber threats.';
    if (score >= 70) return 'Good security posture with targeted areas requiring improvement.';
    if (score >= 50) return 'Moderate security posture — attention is required on key risk drivers.';
    return 'Security posture is below acceptable threshold and requires immediate remediation.';
  }

  function buildExecSummaryText(score, rating, vulnScore, awarScore, mdrScore, delta) {
    const scores = [
      { name: 'Vulnerability Management', val: vulnScore },
      { name: 'Security Awareness Training', val: awarScore },
      { name: 'Incident Response', val: mdrScore },
    ].sort((a, b) => a.val - b.val);
    const weakest = scores[0];
    const trendSentence = delta === null ? '' :
      delta > 3 ? ` The score has improved by ${delta} points compared to last month, indicating positive momentum.` :
      delta < -3 ? ` The score has declined by ${Math.abs(delta)} points compared to last month, warranting review.` :
      ' The score has remained stable compared to last month.';
    return `The organisation's current Secure Score stands at ${score}/100, rated <strong>${rating}</strong>.${trendSentence} ` +
      `The primary area for improvement is <strong>${weakest.name}</strong> (currently ${weakest.val}/100), ` +
      `which has the greatest potential to lift the overall security posture score when addressed.`;
  }

  function buildInsurabilitySection(ssScore, insScore, grcScore, hist) {
    const insColor = getScoreColor(insScore);
    let trend = 0;
    if (hist.length >= 2) {
      const recent = hist.slice(0, Math.min(3, hist.length)).map(h => h.score);
      const avg = recent.reduce((s, v) => s + v, 0) / recent.length;
      trend = Math.round(ssScore - avg);
    }
    let dirKey, dirArrow, dirLabel;
    if (insScore >= 75 && trend >= 3)        { dirKey = 'reduce';  dirArrow = '↓';  dirLabel = 'Premium Reduction Likely'; }
    else if (insScore >= 75)                  { dirKey = 'stable';  dirArrow = '→';  dirLabel = 'Premium Likely Maintained'; }
    else if (insScore >= 60 && trend >= -3)   { dirKey = 'neutral'; dirArrow = '→';  dirLabel = 'Neutral — Monitor Position'; }
    else if (insScore >= 50 || trend < -3)    { dirKey = 'risk';    dirArrow = '↑';  dirLabel = 'Premium Increase Risk'; }
    else                                      { dirKey = 'likely';  dirArrow = '↑↑'; dirLabel = 'Premium Increase Likely'; }

    const dirColors = { reduce: '#27ae60', stable: '#27ae60', neutral: '#d68910', risk: '#e67e22', likely: '#e74c3c' };
    const dirColor = dirColors[dirKey];

    const trendAbs = Math.abs(trend);
    const trendDir = trend > 0 ? 'improved' : trend < 0 ? 'declined' : 'unchanged';
    const trendNote = hist.length >= 2
      ? `Score has ${trendDir}${trendAbs > 0 ? ` by ${trendAbs} points` : ''} over the last ${Math.min(3, hist.length)} months.`
      : 'Insufficient history for trend analysis.';

    const breakdownNote = grcScore !== null
      ? `Secure Score (${ssScore}) × 60% + GRC Score (${grcScore}) × 40%`
      : `Based on Secure Score only — complete GRC assessment for full calculation`;

    return `
      <div style="display:grid;grid-template-columns:180px 1fr;gap:28px;align-items:flex-start">
        <div style="background:#EEF2F7;border-radius:10px;padding:20px;text-align:center;border-top:3px solid #1565C0">
          <div style="font-size:3rem;font-weight:800;color:${insColor};line-height:1">${insScore}</div>
          <div style="font-size:0.8rem;color:#6b7c93;font-weight:600;margin-top:4px">Insurability Score</div>
          <div style="font-size:0.7rem;color:#9aacba;margin-top:8px;line-height:1.5">${breakdownNote}</div>
        </div>
        <div>
          <div style="display:inline-flex;align-items:center;gap:8px;padding:8px 18px;border-radius:999px;
                      font-weight:700;font-size:0.9rem;margin-bottom:12px;
                      background:${hexToRgba(dirColor, 0.12)};color:${dirColor}">
            <span style="font-size:1.1em">${dirArrow}</span> ${dirLabel}
          </div>
          <p style="font-size:0.88rem;color:#3d5166;margin:0 0 14px">${trendNote}</p>
          <div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:#9aacba;margin-bottom:8px">Key Risk Drivers</div>
          ${grcScore === null ? `<div style="display:flex;align-items:center;gap:8px;font-size:0.88rem;color:#3d5166;margin-bottom:6px">
            <span style="width:9px;height:9px;border-radius:50%;background:#f39c12;flex-shrink:0;display:inline-block"></span>
            GRC assessment not completed — adds 40% weight to Insurability Score
          </div>` : ''}
        </div>
      </div>`;
  }

  function buildGrcSection(grcData) {
    const grcAsmt = grcData && grcData.assessment;
    if (!grcAsmt) {
      return `<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:18px 20px;color:#92400e;font-size:0.92rem">
        <strong>GRC Assessment Not Completed</strong><br>
        Complete the GRC self-assessment in the GRC Compliance tab to include governance risk and compliance scoring in this report and improve the accuracy of the Insurability Score.
      </div>`;
    }
    const grcScore = grcAsmt.grc_score || 0;
    const grcColor = getScoreColor(grcScore);
    const grcDate = new Date(grcAsmt.assessed_at).toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });
    return `
      <div style="display:flex;align-items:center;gap:28px;background:#EEF2F7;border-radius:10px;padding:24px;border-left:4px solid #1565C0">
        <div style="text-align:center;flex-shrink:0">
          <div style="font-size:3rem;font-weight:800;color:${grcColor};line-height:1">${grcScore}</div>
          <div style="font-size:0.8rem;color:#6b7c93;font-weight:600;margin-top:4px">GRC Score</div>
          <div style="font-size:0.72rem;color:#9aacba;margin-top:6px">Assessed: ${grcDate}</div>
        </div>
        <div style="font-size:0.88rem;color:#3d5166;line-height:1.7">
          The GRC score reflects the organisation's governance, risk and compliance posture based on a structured self-assessment.<br>
          <em style="color:#9aacba">Detailed domain breakdown is available in the GRC Compliance tab.</em>
        </div>
      </div>`;
  }

  function buildRecommendationsSection(recommendations) {
    if (!recommendations || recommendations.length === 0) {
      return '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:16px 20px;color:#166534;font-size:0.92rem">✅ No recommendations at this time — all components are performing well.</div>';
    }
    const order = ['high', 'medium', 'info'];
    const sorted = [...recommendations].sort((a, b) => order.indexOf(a.priority) - order.indexOf(b.priority));
    const borderColors = { high: '#e74c3c', medium: '#f39c12', info: '#27ae60' };
    const bgColors     = { high: 'rgba(231,76,60,0.04)', medium: 'rgba(245,158,11,0.04)', info: 'rgba(39,174,96,0.04)' };
    const badgeBg      = { high: 'rgba(231,76,60,0.12)', medium: 'rgba(245,158,11,0.12)', info: 'rgba(39,174,96,0.12)' };
    const badgeFg      = { high: '#c0392b', medium: '#d68910', info: '#1e8449' };
    return sorted.map(rec => `
      <div style="border-left:4px solid ${borderColors[rec.priority] || '#e2eaf2'};
                  border-radius:0 8px 8px 0;padding:14px 18px;margin-bottom:12px;
                  background:${bgColors[rec.priority] || '#fafbfc'};
                  page-break-inside:avoid;break-inside:avoid">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;
                       padding:2px 8px;border-radius:3px;
                       background:${badgeBg[rec.priority]};color:${badgeFg[rec.priority]}">${rec.priority}</span>
          <span style="font-size:0.95rem;font-weight:700;color:#1a2a3a">${rec.area}</span>
          <span style="font-size:0.78rem;color:#6b7c93;margin-left:auto">Impact: ${rec.impact}</span>
        </div>
        <p style="font-size:0.88rem;color:#3d5166;line-height:1.6;margin:0">${rec.suggestion}</p>
      </div>`).join('');
  }

  function buildAppendix(scoreData, reportDate) {
    const da = scoreData.dataAge || {};
    const rows = [
      ['Vulnerability Findings', da.vulns || 'N/A', 'Nessus / Arctic Wolf scan data'],
      ['Security Awareness', da.awareness || 'N/A', 'Training platform export'],
      ['Incident Response (MDR)', da.mdr || 'N/A', 'Arctic Wolf MDR ticket data'],
    ];
    return `
      <p style="font-size:0.88rem;color:#3d5166;margin-bottom:16px">
        The Secure Score is a composite 0–100 index calculated from three weighted components:
        <strong>Vulnerability Management (40%)</strong>, <strong>Security Awareness (35%)</strong>,
        and <strong>Incident Response (25%)</strong>. The Insurability Score combines the Secure Score
        (60%) with the GRC Assessment Score (40%) to reflect overall cyber insurance risk positioning.
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:0.82rem">
        <thead>
          <tr style="background:#EEF2F7">
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #1565C0;color:#2B3445">Data Source</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #1565C0;color:#2B3445">Last Updated</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #1565C0;color:#2B3445">Origin</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(([src, date, origin]) => `
            <tr>
              <td style="padding:8px 12px;border-bottom:1px solid #eef2f6;color:#1a2a3a;font-weight:600">${src}</td>
              <td style="padding:8px 12px;border-bottom:1px solid #eef2f6;color:#3d5166">${date}</td>
              <td style="padding:8px 12px;border-bottom:1px solid #eef2f6;color:#6b7c93">${origin}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }

  async function logoToDataUri() {
    return window.ReportShell.logoToDataUri();
  }

  async function generateExcoReport(_handle, scoreData, history, grcData) {
    const score     = Math.round(scoreData.score);
    const rating    = scoreData.rating;
    const comp      = scoreData.components || {};
    const vulnScore = Math.round((comp.vulnerabilities    || {}).score || 0);
    const awarScore = Math.round((comp.awareness          || {}).score || 0);
    const mdrScore  = Math.round((comp.incidentResponse   || {}).score || 0);

    /*
     * This is a CLIENT-FACING report, so it shows only the components the
     * client's services cover.
     *
     * It previously captioned the vulnerability card "Endpoint Hygiene —
     * endpoint patch currency and agent health" for an endpoint-only estate.
     * That is the right name for the internal tab, which is an analyst's view
     * of how the score was arrived at, and the wrong thing entirely on a
     * document that goes to a client: it names a measure no contracted service
     * delivers. The card is omitted rather than renamed.
     */
    const a4Scope = scoreData.scope;
    const a4Covered = (key) => !a4Scope || !a4Scope.recorded
      || (a4Scope.covered || []).indexOf(key) >= 0;

    const vulnBasisA4 = (comp.vulnerabilities || {}).basis || 'infrastructure';
    const vulnDesc  = vulnBasisA4 === 'unknown'
      ? 'Estate not recorded — measure cannot be selected'
      : 'Finding density across the assets in scope';

    const hist = Array.isArray(history) ? history : (history && history.history ? history.history : []);
    let delta = null;
    if (hist.length >= 2) delta = score - Math.round(hist[1].score);

    const trendLabel = delta === null ? 'No prior data' : delta > 3 ? 'Improving' : delta < -3 ? 'Declining' : 'Stable';
    const trendArrow = delta === null ? '' : delta > 3 ? '▲' : delta < -3 ? '▼' : '→';
    const trendColor = delta === null ? '#6b7c93' : delta > 3 ? '#27ae60' : delta < -3 ? '#e74c3c' : '#f39c12';

    const grcAsmt  = grcData && grcData.assessment;
    const grcScore = grcAsmt ? (grcAsmt.grc_score || 0) : null;
    const insScore = grcScore !== null ? Math.round(score * 0.6 + grcScore * 0.4) : score;

    const user       = window.currentUser || {};
    const tenantName = user.username || 'SecOps Dashboard';
    const reportDate = new Date().toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });
    const reportYear = new Date().getFullYear();
    const scoreColor = getScoreColor(score);

    const logoDataUri = await logoToDataUri();

    /* Reflex brand palette */
    const RX_BLUE    = '#1565C0';
    const RX_DARK    = '#2B3445';
    const RX_GREY    = '#B0BEC5';
    const RX_LIGHT   = '#EEF2F7';

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Posture Executive Report — ${reportDate}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px; color: #1a2a3a; background: #fff; line-height: 1.6; }
  @page { size: A4 portrait; margin: 0; }
  @page :first { margin: 0; }

  /* ── Cover page — fixed A4 portrait ── */
  .cover {
    position: relative; overflow: hidden;
    width: 210mm; height: 297mm;
    background: #ffffff;
    display: flex; flex-direction: column;
    page-break-after: always; break-after: page;
    margin: 0 auto;
  }
  /* Top-right grey diagonal shape */
  .cover::before {
    content: ''; position: absolute; top: -80px; right: -100px;
    width: 320px; height: 460px;
    background: #CFD8DC;
    transform: rotate(-18deg);
    border-radius: 14px;
    z-index: 0;
  }
  /* Bottom-right dark charcoal shape */
  .cover::after {
    content: ''; position: absolute; bottom: -80px; right: -50px;
    width: 260px; height: 420px;
    background: #2B3445;
    transform: rotate(-18deg);
    border-radius: 14px;
    z-index: 1;
  }
  .cover-top { padding: 36px 44px 0; position: relative; z-index: 2; }
  .cover-logo { display: flex; align-items: center; margin-bottom: 12px; }

  /* Blue arrow/chevron title band */
  .cover-title-band {
    position: relative; z-index: 2;
    margin: 70px 0 0;
    background: #1565C0;
    padding: 40px 44px 40px 56px;
    clip-path: polygon(0 0, calc(100% - 56px) 0, 100% 50%, calc(100% - 56px) 100%, 0 100%);
    width: 80%;
  }
  .cover-eyebrow { font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 3px; color: rgba(255,255,255,0.65); margin-bottom: 10px; }
  .cover-title    { font-size: 1.75rem; font-weight: 800; color: #fff; line-height: 1.2; }

  .cover-meta {
    position: relative; z-index: 2;
    padding: 28px 44px 0 56px;
    display: grid; grid-template-columns: 1fr 1fr; gap: 18px; max-width: 460px;
  }
  .cover-meta-label { font-size: 0.63rem; text-transform: uppercase; letter-spacing: 1.5px; color: #90A4AE; margin-bottom: 3px; }
  .cover-meta-value { font-size: 0.88rem; font-weight: 700; color: #2B3445; }

  .cover-footer {
    position: relative; z-index: 2;
    margin-top: auto; padding: 24px 44px 32px;
    display: flex; justify-content: space-between; align-items: flex-end;
  }
  .cover-classification {
    display: inline-block; border: 1.5px solid #B0BEC5; border-radius: 4px;
    padding: 4px 14px; font-size: 0.68rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 2px; color: #90A4AE;
  }
  .cover-footer-right { text-align: right; font-size: 0.78rem; color: #90A4AE; line-height: 1.8; }
  .cover-footer-right strong { color: #2B3445; }

  /* ── Content pages ── */
  .page { padding: 18mm 16mm; width: 210mm; margin: 0 auto; }

  .section-heading {
    font-size: 1.15rem; font-weight: 800; color: #2B3445;
    border-bottom: 3px solid #1565C0; padding-bottom: 8px;
    margin-bottom: 20px; margin-top: 36px;
    page-break-after: avoid; break-after: avoid;
  }
  .section-heading:first-child { margin-top: 0; }

  /* Blue stripe at top of content section */
  .page-header-stripe { background: #1565C0; height: 6px; width: 100%; }

  .exec-grid { display: grid; grid-template-columns: 220px 1fr; gap: 28px; align-items: center; margin-bottom: 24px; }
  .exec-gauge-block { text-align: center; background: #EEF2F7; border-radius: 12px; padding: 18px 14px; border-top: 4px solid #1565C0; overflow: hidden; }
  .exec-gauge-rating { font-size: 1.1rem; font-weight: 700; margin-top: 5px; }
  .exec-headline { font-size: 1.2rem; font-weight: 800; color: #2B3445; margin-bottom: 10px; line-height: 1.3; }
  .exec-body { font-size: 0.88rem; color: #455A64; line-height: 1.65; margin-bottom: 12px; }
  .trend-badge {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 7px 16px; border-radius: 999px; font-weight: 700; font-size: 0.9rem;
  }

  .comp-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 24px; }

  .trend-box { background: #EEF2F7; border-radius: 10px; padding: 18px; margin-bottom: 24px; page-break-inside: avoid; break-inside: avoid; border-left: 4px solid #1565C0; }

  .page-footer {
    margin-top: 36px; padding-top: 10px; border-top: 2px solid #1565C0;
    display: flex; justify-content: space-between; font-size: 0.68rem; color: #90A4AE;
  }

  .print-btn-bar { position: fixed; top: 20px; right: 20px; z-index: 999; display: flex; gap: 10px; }
  .print-btn {
    background: #1565C0; color: #fff; border: none; border-radius: 6px;
    padding: 10px 22px; font-size: 0.88rem; font-weight: 600; cursor: pointer;
    box-shadow: 0 2px 10px rgba(21,101,192,0.35);
  }
  .print-btn:hover { background: #0D47A1; }
  .print-btn.close-btn { background: #2B3445; }
  .print-btn.close-btn:hover { background: #1a2535; }

  @media screen {
    body { background: #e8ecf0; }
    .cover, .page-header-stripe, .page { box-shadow: 0 2px 20px rgba(0,0,0,0.15); }
    .page { background: #fff; }
  }

  @media print {
    body { background: #fff; }
    .print-btn-bar { display: none !important; }
    * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>

<div class="print-btn-bar">
  <button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button>
  <button class="print-btn close-btn" onclick="window.close()">✕ Close</button>
</div>

<!-- COVER PAGE -->
<div class="cover">
  <div class="cover-top">
    <div class="cover-logo">
      ${logoDataUri
        ? `<img src="${logoDataUri}" alt="Reflex" style="height:60px;width:auto">`
        : `<div style="font-size:1.4rem;font-weight:800;color:#1565C0">reflex</div>`}
    </div>
  </div>

  <div class="cover-title-band">
    <div class="cover-eyebrow">Executive Security Report</div>
    <div class="cover-title">Security Posture<br>Executive Report</div>
  </div>

  <div class="cover-meta">
    <div><div class="cover-meta-label">Report Date</div><div class="cover-meta-value">${reportDate}</div></div>
    <div><div class="cover-meta-label">Prepared By</div><div class="cover-meta-value">${tenantName}</div></div>
    <div><div class="cover-meta-label">Overall Score</div><div class="cover-meta-value" style="color:#1565C0">${score}/100 — ${rating}</div></div>
    <div><div class="cover-meta-label">30-Day Trend</div><div class="cover-meta-value" style="color:${trendColor}">${trendArrow} ${trendLabel}</div></div>
  </div>

  <div class="cover-footer">
    <div class="cover-classification">Confidential</div>
    <div class="cover-footer-right">
      ${reportDate}<br>
      Version: 1.0<br>
      <strong>Prepared by Reflex</strong>
    </div>
  </div>
</div>

<!-- Blue stripe at top of content section -->
<div class="page-header-stripe"></div>

<!-- CONTENT -->
<div class="page">

  <h2 class="section-heading">1. Executive Summary</h2>
  <div class="exec-grid">
    <div class="exec-gauge-block">
      ${buildGaugeSvg(score)}
      <div class="exec-gauge-rating" style="color:${scoreColor}">${rating}</div>
      <div style="font-size:0.75rem;color:#78909C;margin-top:3px">Security Posture Score</div>
    </div>
    <div>
      <div class="exec-headline">${buildHeadline(score, rating, delta)}</div>
      <p class="exec-body">${buildExecSummaryText(score, rating, vulnScore, awarScore, mdrScore, delta)}</p>
      <div class="trend-badge" style="background:${hexToRgba(trendColor, 0.1)};color:${trendColor}">
        <span style="font-size:1.1em">${trendArrow || '→'}</span>
        <span>${trendLabel}${delta !== null ? ` (${delta > 0 ? '+' : ''}${delta} pts vs. prior month)` : ''}</span>
      </div>
    </div>
  </div>

  <h2 class="section-heading">2. Security Posture Breakdown</h2>
  <div class="comp-grid">
    ${a4Covered('vulnerabilities') ? buildCompCard('Vulnerabilities', pctOf(comp.vulnerabilities, '40%'), vulnScore, vulnDesc) : ''}
    ${a4Covered('awareness') ? buildCompCard('Security Awareness', pctOf(comp.awareness, '35%'), awarScore, 'Training completion rate across all sessions') : ''}
    ${a4Covered('incidentResponse') ? buildCompCard('Incident Response', pctOf(comp.incidentResponse, '25%'), mdrScore, 'Ticket resolution rate and response speed') : ''}
  </div>

  <h2 class="section-heading">3. 6-Month Score Trend</h2>
  <div class="trend-box">
    ${buildTrendSvg(hist)}
  </div>

  <h2 class="section-heading">4. Cyber Insurability Assessment</h2>
  ${buildInsurabilitySection(score, insScore, grcScore, hist)}

  <h2 class="section-heading">5. GRC Compliance Summary</h2>
  ${buildGrcSection(grcData)}

  <h2 class="section-heading">6. Prioritised Recommendations</h2>
  ${buildRecommendationsSection(scoreData.recommendations)}

  <h2 class="section-heading">7. Appendix — Data Sources &amp; Methodology</h2>
  ${buildAppendix(scoreData, reportDate)}

  <div class="page-footer">
    <span>Security Posture Executive Report — ${reportDate}</span>
    <span>CONFIDENTIAL — Internal Use Only</span>
    <span>Prepared by Reflex &copy; ${reportYear}</span>
  </div>
</div>
</body>
</html>`;

    _handle.write(html);
  }

  return {
    loadAndRender,
    // Exposed so the scope strip can be rendered and read back in a test
    // harness without standing up the whole tab. Pure function of its
    // arguments; nothing else in the module depends on it being public.
    renderScopeStrip,
    // The coverage working that used to sit under the strip. Split out when it
    // moved into the explain panel, and exported for the same reason the strip
    // is: the gaps list is client-facing prose, and a test has to be able to
    // read it back rather than grep for the string that produces it.
    scopeDetailHtml,
    // Likewise. The estate note carries the staleness and conflict caveats,
    // and a source-level grep for its wording cannot tell whether the branch
    // that emits it still runs — deleting the condition left the string in the
    // file and the check green. This is the seam that makes it testable.
    renderEstateNote,
  };
})();

window.SecureScoreTab = SecureScoreTab;
