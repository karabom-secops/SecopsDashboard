// tab-grc.js — GRC & Insurability self-assessment tab

const GrcTab = (() => {
  'use strict';

  let _sections = {};   // { sectionName: [question, ...] }
  let _answers  = {};   // { questionId: { answer, notes } }
  let _assessment = null;
  let _questionsById = {}; // { questionId: question } — flattened across all sections

  const WEIGHT_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const WEIGHT_COLOR = { critical: 'var(--red)', high: 'var(--amber)', medium: 'var(--logo-cyan)', low: 'var(--green)' };
  const FRAMEWORK_LABEL = { NIST_CSF: 'NIST CSF', CIS_V8: 'CIS Controls v8' };

  function tenantParam(sep) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  function isReadonly() {
    return !window.canWrite('grc');
  }

  function getScoreColor(score) {
    if (score >= 80) return '#27ae60';
    if (score >= 60) return '#f39c12';
    if (score >= 40) return '#e67e22';
    return '#e74c3c';
  }

  function getScoreRating(score) {
    if (score >= 80) return 'Low Risk';
    if (score >= 60) return 'Moderate Risk';
    if (score >= 40) return 'Elevated Risk';
    return 'High Risk';
  }

  // ── Score gauge (same semi-circle pattern as Secure Score tab) ─────────────
  function renderGauge(container, score) {
    const w = 220, h = 130, cx = w / 2, cy = h - 10, r = 90;
    const startX = cx - r, endX = cx + r;
    const color  = getScoreColor(score);
    const arcLen = Math.PI * r;
    const targetOffset = arcLen * (1 - score / 100);

    container.innerHTML = `
      <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="overflow:visible">
        <path d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${cy}"
              fill="none" stroke="#dde8f0" stroke-width="12" stroke-linecap="round"/>
        <path id="grc-gauge-arc" d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${cy}"
              fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
              stroke-dasharray="${arcLen}" stroke-dashoffset="${arcLen}"/>
        <text x="${cx}" y="${cy - 20}" text-anchor="middle"
              font-size="42" font-weight="700" fill="${color}" font-family="Manrope,sans-serif">
          ${Math.round(score)}
        </text>
        <text x="${cx}" y="${cy - 2}" text-anchor="middle"
              font-size="12" font-weight="600" fill="#7a9bb0" font-family="Manrope,sans-serif">
          ${getScoreRating(score)}
        </text>
      </svg>`;

    const arc = container.querySelector('#grc-gauge-arc');
    if (arc) {
      requestAnimationFrame(() => {
        arc.style.transition = 'stroke-dashoffset 0.8s cubic-bezier(0.4,0,0.2,1)';
        arc.style.strokeDashoffset = targetOffset;
      });
    }
  }

  // ── Per-section score bars ─────────────────────────────────────────────────
  function calcSectionScore(sectionQuestions) {
    const pts = { critical: 5, high: 3, medium: 2, low: 1 };
    let possible = 0, earned = 0;
    sectionQuestions.forEach(q => {
      const a = (_answers[q.id] || {}).answer;
      if (!a || a === 'na') return;
      const p = pts[q.weight] || 2;
      possible += p;
      if (a === 'yes')     earned += p;
      if (a === 'partial') earned += p * 0.5;
    });
    return possible > 0 ? Math.round((earned / possible) * 100) : null;
  }

  // ── Per-framework score cards (NIST CSF, CIS Controls v8) ───────────────────
  function calcFrameworkScore(framework) {
    const pts = { critical: 5, high: 3, medium: 2, low: 1 };
    const seen = new Set();
    let possible = 0, earned = 0;
    Object.values(_questionsById).forEach(q => {
      if (seen.has(q.id)) return;
      const mapped = (q.frameworks || []).some(f => f.framework === framework);
      if (!mapped) return;
      seen.add(q.id);

      const a = (_answers[q.id] || {}).answer;
      if (!a || a === 'na') return;
      const p = pts[q.weight] || 2;
      possible += p;
      if (a === 'yes')     earned += p;
      if (a === 'partial') earned += p * 0.5;
    });
    return possible > 0 ? Math.round((earned / possible) * 100) : null;
  }

  function renderFrameworkBreakdown(container) {
    const frameworks = Object.keys(FRAMEWORK_LABEL);
    container.innerHTML = `
      <div class="grc-domain-grid">
        ${frameworks.map(fw => {
          const score = calcFrameworkScore(fw);
          const color = score !== null ? getScoreColor(score) : '#aaa';
          const label = score !== null ? `${score}/100` : '—';
          return `
            <div class="grc-domain-card">
              <div class="grc-domain-name">${FRAMEWORK_LABEL[fw]}</div>
              <div class="grc-domain-bar-wrap">
                <div class="grc-domain-bar">
                  <div class="grc-domain-bar-fill" data-score="${score || 0}"
                       style="width:0%;background:${color}"></div>
                </div>
                <span class="grc-domain-score" style="color:${color}">${label}</span>
              </div>
            </div>`;
        }).join('')}
      </div>`;

    setTimeout(() => {
      container.querySelectorAll('.grc-domain-bar-fill').forEach(el => {
        el.style.width = el.dataset.score + '%';
      });
    }, 60);
  }

  function renderDomainBreakdown(container) {
    const names = Object.keys(_sections);
    if (!names.length) { container.innerHTML = ''; return; }

    const items = names.map(name => {
      const score = calcSectionScore(_sections[name]);
      const answered = _sections[name].filter(q => (_answers[q.id] || {}).answer).length;
      const total    = _sections[name].length;
      return { name, score, answered, total };
    });

    container.innerHTML = `
      <div class="grc-domain-grid">
        ${items.map(it => {
          const score = it.score !== null ? it.score : 0;
          const color = it.score !== null ? getScoreColor(score) : '#aaa';
          const label = it.score !== null ? `${score}/100` : '—';
          return `
            <div class="grc-domain-card">
              <div class="grc-domain-name">${it.name}</div>
              <div class="grc-domain-bar-wrap">
                <div class="grc-domain-bar">
                  <div class="grc-domain-bar-fill" data-score="${score}"
                       style="width:0%;background:${color}"></div>
                </div>
                <span class="grc-domain-score" style="color:${color}">${label}</span>
              </div>
              <div class="grc-domain-progress">${it.answered}/${it.total} answered</div>
            </div>`;
        }).join('')}
      </div>`;

    setTimeout(() => {
      container.querySelectorAll('.grc-domain-bar-fill').forEach(el => {
        el.style.width = el.dataset.score + '%';
      });
    }, 60);
  }

  // ── Questionnaire ──────────────────────────────────────────────────────────
  function renderQuestionnaire(container) {
    const readonly = isReadonly();
    const names = Object.keys(_sections);

    container.innerHTML = names.map((section, si) => {
      const questions = _sections[section];
      const questionsHtml = questions.map(q => {
        const ans  = (_answers[q.id] || {}).answer || '';
        const notes = (_answers[q.id] || {}).notes || '';
        const unanswered = !ans;

        const opts = [
          { value: 'yes',     label: 'Yes' },
          { value: 'partial', label: 'Partial' },
          { value: 'no',      label: 'No' },
          { value: 'na',      label: 'N/A' },
        ];

        return `
          <div class="grc-question${unanswered ? ' grc-unanswered' : ''}" data-qid="${q.id}">
            <div class="grc-question-header">
              <span class="grc-question-weight" style="color:${WEIGHT_COLOR[q.weight]}">${WEIGHT_LABEL[q.weight]}</span>
              ${q.nist_ref ? `<span class="grc-question-ref">${q.nist_ref}</span>` : ''}
              ${(q.frameworks || []).filter(f => f.framework === 'CIS_V8').map(f =>
                `<span class="grc-question-ref grc-question-ref-cis" title="${f.controlTitle || ''}">CIS ${f.controlId}</span>`
              ).join('')}
            </div>
            <p class="grc-question-text">${q.text}</p>
            ${q.help_text ? `<p class="grc-question-help">${q.help_text}</p>` : ''}
            <div class="grc-answer-row" role="group">
              ${opts.map(opt => `
                <label class="grc-radio-label${ans === opt.value ? ' selected' : ''}">
                  <input type="radio" name="grc-q-${q.id}" value="${opt.value}"
                         ${ans === opt.value ? 'checked' : ''}
                         ${readonly ? 'disabled' : ''}>
                  ${opt.label}
                </label>`).join('')}
            </div>
            ${!readonly ? `
            <div class="grc-notes-wrap" style="${ans && ans !== 'na' ? '' : 'display:none'}">
              <input type="text" class="grc-notes-input" placeholder="Optional notes…"
                     data-qid="${q.id}" value="${notes.replace(/"/g, '&quot;')}" maxlength="300">
            </div>` : (notes ? `<p class="grc-notes-readonly">${notes}</p>` : '')}
          </div>`;
      }).join('');

      return `
        <div class="grc-section" id="grc-section-${si}">
          <button class="grc-section-toggle" data-target="grc-body-${si}" aria-expanded="false">
            <span class="grc-section-title">${section}</span>
            <span class="grc-section-count">${questions.length} questions</span>
            <span class="grc-toggle-arrow">▶</span>
          </button>
          <div class="grc-section-body" id="grc-body-${si}" hidden>
            ${questionsHtml}
          </div>
        </div>`;
    }).join('');

    // Wire radio changes
    container.querySelectorAll('input[type=radio]').forEach(radio => {
      radio.addEventListener('change', () => {
        const qid = parseInt(radio.name.replace('grc-q-', ''), 10);
        if (!_answers[qid]) _answers[qid] = {};
        _answers[qid].answer = radio.value;

        // Update label styling
        const group = radio.closest('.grc-answer-row');
        group.querySelectorAll('.grc-radio-label').forEach(l => l.classList.remove('selected'));
        radio.closest('.grc-radio-label').classList.add('selected');

        // Show/hide notes
        const qEl = radio.closest('.grc-question');
        const notesWrap = qEl.querySelector('.grc-notes-wrap');
        if (notesWrap) notesWrap.style.display = (radio.value !== 'na') ? '' : 'none';

        // Remove unanswered highlight
        qEl.classList.remove('grc-unanswered');

        // Refresh domain and framework breakdowns
        const breakdown = document.getElementById('grc-breakdown');
        if (breakdown) renderDomainBreakdown(breakdown);
        const fwBreakdown = document.getElementById('grc-framework-breakdown');
        if (fwBreakdown) renderFrameworkBreakdown(fwBreakdown);

        // Refresh "answered/total" progress text
        const progressEl = document.querySelector('.grc-progress-info');
        if (progressEl) {
          const totalQ   = Object.values(_sections).reduce((s, q) => s + q.length, 0);
          const answered = Object.values(_answers).filter(a => a.answer).length;
          const pctDone  = totalQ > 0 ? Math.round(answered / totalQ * 100) : 0;
          progressEl.textContent = `${answered}/${totalQ} questions answered (${pctDone}%)`;
        }
      });
    });

    // Wire notes inputs
    container.querySelectorAll('.grc-notes-input').forEach(input => {
      input.addEventListener('input', () => {
        const qid = parseInt(input.dataset.qid, 10);
        if (!_answers[qid]) _answers[qid] = {};
        _answers[qid].notes = input.value;
      });
    });

    // Wire section toggles
    container.querySelectorAll('.grc-section-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const body  = document.getElementById(btn.dataset.target);
        const open  = btn.getAttribute('aria-expanded') === 'true';
        body.hidden = open;
        btn.setAttribute('aria-expanded', String(!open));
        btn.querySelector('.grc-toggle-arrow').textContent = open ? '▶' : '▼';
      });
    });
  }

  // ── Save assessment ────────────────────────────────────────────────────────
  async function saveAssessment() {
    const saveBtn = document.getElementById('grc-save-btn');
    const statusEl = document.getElementById('grc-save-status');
    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving…'; }
    if (statusEl) { statusEl.textContent = ''; statusEl.className = 'grc-save-status'; }

    const answers = Object.entries(_answers).map(([qid, val]) => ({
      questionId: parseInt(qid, 10),
      answer: val.answer,
      notes: val.notes || '',
    })).filter(a => a.answer);

    const body = { answers };
    if (window.currentUser && window.currentUser.role === 'superadmin' && window.globalTenantId) {
      body.tenantId = window.globalTenantId;
    }

    try {
      const res = await fetch('api/grc/assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.status);

      _assessment = { grc_score: data.score, assessed_at: data.assessedAt };

      // Refresh gauge, "last assessed" date, and status
      const gaugeEl = document.getElementById('grc-gauge');
      if (gaugeEl) renderGauge(gaugeEl, data.score);
      const dateEl = document.querySelector('.grc-score-date');
      if (dateEl) {
        dateEl.textContent = 'Last assessed: ' + new Date(data.assessedAt).toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
      }
      if (statusEl) {
        statusEl.textContent = `Saved — GRC Score: ${data.score}/100`;
        statusEl.className = 'grc-save-status grc-save-ok';
      }
    } catch (err) {
      if (statusEl) {
        statusEl.textContent = 'Save failed: ' + err.message;
        statusEl.className = 'grc-save-status grc-save-err';
      }
    } finally {
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save Assessment'; }
    }
  }

  // ── GRC report — 16:9 deck, same chrome as the Reporting tab ───────────────
  //
  // Uses window.ReportDeck for all geometry and styling, so this deck and the
  // client deck stay visually identical. ReportDeck loads after this file in
  // index.html, hence every reference to it is resolved lazily at call time.

  const WEIGHT_POINTS = { critical: 5, high: 3, medium: 2, low: 1 };
  const ANSWER_LABEL  = { yes: 'Yes', partial: 'Partial', no: 'No', na: 'N/A' };

  // Slides are fixed-height with overflow:hidden, so an over-long table is
  // cropped silently — cap rows per slide and spill onto continuation slides.
  // Budget: ~130mm of body height. A control wraps to at most 3 lines at
  // MAX_CONTROL_CHARS in a ~42%-wide column, so these counts fit with headroom.
  const MAX_DOMAIN_ROWS   = 13;
  const MAX_GAP_ROWS      = 8;
  const MAX_APPENDIX_ROWS = 9;
  const MAX_CONTROL_CHARS = 160;
  const MAX_NOTE_CHARS    = 90;

  function esc(s) { return window.ReportShell.esc(s); }

  function truncate(str, n) {
    const s = String(str == null ? '' : str);
    return s.length > n ? s.slice(0, n).replace(/\s+\S*$/, '') + '…' : s;
  }

  function chunkRows(arr, n) {
    const out = [];
    for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
    return out;
  }

  /** Score → deck palette, so the report never uses the on-screen tab colours. */
  function deckScoreColor(score) {
    const P = window.ReportShell.PALETTE;
    if (score === null || score === undefined) return '#A6A6A6';
    if (score >= 80) return P.DECK_GREEN;
    if (score >= 60) return P.DECK_AMBER;
    if (score >= 40) return '#C2691A';
    return P.DECK_MAROON;
  }

  /** Answer → deck palette. A function because PALETTE resolves lazily. */
  const ANSWER_DECK_COLOR = () => {
    const P = window.ReportShell.PALETTE;
    return { yes: P.DECK_GREEN, partial: P.DECK_AMBER, no: P.DECK_MAROON, na: '#A6A6A6' };
  };

  /** Control weight → deck palette. */
  const WEIGHT_DECK_COLOR = () => {
    const P = window.ReportShell.PALETTE;
    return { critical: P.DECK_MAROON, high: '#C2691A', medium: P.DECK_BLUE, low: P.DECK_MUTED };
  };

  /** "ID.GV-1 · CIS 14.1" — the framework refs carried on a question. */
  function refText(q) {
    const refs = [];
    if (q.nist_ref) refs.push(q.nist_ref);
    (q.frameworks || [])
      .filter(f => f.framework === 'CIS_V8')
      .forEach(f => refs.push('CIS ' + f.controlId));
    return refs.length ? refs.join(' · ') : '—';
  }

  /** Inline progress bar sized for a .dt cell. */
  function barCell(score) {
    const color = deckScoreColor(score);
    const pct   = score === null ? 0 : score;
    const label = score === null ? '—' : score + '/100';
    return '<div style="display:flex;align-items:center;gap:2.5mm">' +
             '<span style="flex:1 1 auto;height:2.2mm;border-radius:1.1mm;background:#E6ECF2;overflow:hidden;display:block">' +
               '<span style="display:block;height:100%;width:' + pct + '%;border-radius:1.1mm;background:' + color + '"></span>' +
             '</span>' +
             '<span style="flex:0 0 auto;font-weight:700;color:' + color + '">' + label + '</span>' +
           '</div>';
  }

  function coloredCell(text, color) {
    return '<span style="font-weight:700;color:' + color + '">' + esc(text) + '</span>';
  }

  // ── Slides ────────────────────────────────────────────────────────────────

  /**
   * Full-bleed blue cover. ReportDeck.coverSlide() hardcodes the MDR deck's
   * title and subtitle, so this rebuilds it from the same CSS classes and
   * watermark rather than shipping a misleading heading.
   */
  function coverSlide(ctx) {
    const D = window.ReportDeck;
    return '<div class="slide cover">' +
        D.WATERMARK_X +
        '<div class="cover-inner">' +
          (ctx.logoDataUri ? '<img class="cover-logo" src="' + ctx.logoDataUri + '" alt="Reflex">' : '') +
          '<div class="cover-mid">' +
            '<div class="cover-title">' + esc(ctx.clientName) + ' GRC &amp; Insurability</div>' +
            '<div class="cover-sub">Governance, Risk and Compliance Assessment</div>' +
            '<div class="cover-hr"></div>' +
            '<div class="cover-author">By ' + esc(ctx.author) + '</div>' +
            '<div class="cover-hr2"></div>' +
          '</div>' +
          '<div class="cover-copy">&copy; Reflex&trade; ' + esc(ctx.year) + '</div>' +
          D.slideFooter(1, ctx.dateStr) +
        '</div>' +
      '</div>';
  }

  function narrativeText(score, answered, totalQ) {
    let body;
    if (score >= 80) {
      body = 'Governance, risk and compliance controls are broadly implemented and evidenced. The organisation presents a favourable risk profile to cyber insurers, with residual work concentrated in refinement rather than remediation.';
    } else if (score >= 60) {
      body = 'A workable governance baseline is in place, but several controls remain only partially implemented. Closing the highest-weighted gaps is the fastest route to improving both the GRC score and the resulting insurability position.';
    } else if (score >= 40) {
      body = 'Governance coverage is uneven — a material number of controls are absent or only partially implemented. Insurers are likely to query these gaps at renewal, and some may attach conditions or exclusions.';
    } else {
      body = 'Governance, risk and compliance coverage is significantly below expectation. The gaps identified in this deck cover controls that underwriters routinely treat as prerequisites, and should be prioritised accordingly.';
    }
    const coverage = totalQ > 0
      ? 'The assessment covers ' + totalQ + ' controls, of which ' + answered +
        ' (' + Math.round(answered / totalQ * 100) + '%) have been answered.'
      : 'No assessment questions were available at the time of generation.';
    return body + ' ' + coverage;
  }

  /** Three headline tiles plus the narrative, in the Overview slide's idiom. */
  function scoreSlide(ctx) {
    const D = window.ReportDeck;
    const P = window.ReportShell.PALETTE;
    const color = deckScoreColor(ctx.score);
    const pct   = ctx.totalQ > 0 ? Math.round(ctx.answered / ctx.totalQ * 100) : 0;

    const card = (title, desc, value, valueColor, sub) =>
      '<div class="ov-card">' +
        '<div class="ov-t">' + esc(title) + '</div>' +
        '<div class="ov-d">' + esc(desc) + '</div>' +
        '<div class="ov-num" style="color:' + valueColor + ';font-weight:700">' + value + '</div>' +
        '<div class="ov-sub" style="text-align:center">' + esc(sub) + '</div>' +
      '</div>';

    const body =
      '<div class="ov-stack">' +
        '<div class="ov-row three">' +
          card('GRC Score', 'Weighted self-assessment across all governance domains.',
               Math.round(ctx.score) + '<span style="font-size:16pt;color:' + P.DECK_MUTED + '">/100</span>',
               color, ctx.rating) +
          card('Assessment Coverage', 'Controls answered out of the total questionnaire.',
               ctx.answered + '<span style="font-size:16pt;color:' + P.DECK_MUTED + '">/' + ctx.totalQ + '</span>',
               P.DECK_INK, pct + '% complete') +
          card('Insurability Weighting', 'Share of the Cyber Insurability Score driven by GRC.',
               '40<span style="font-size:16pt;color:' + P.DECK_MUTED + '">%</span>',
               P.DECK_BLUE, 'Secure Score 60%') +
        '</div>' +
        '<p style="font-size:11pt;line-height:1.5;color:' + P.DECK_MUTED + ';margin:0">' +
          esc(narrativeText(ctx.score, ctx.answered, ctx.totalQ)) +
        '</p>' +
      '</div>';

    return D.slide({ title: 'GRC Posture', body: body, pageNo: ctx.pageNo, ctx: ctx });
  }

  /** NIST CSF and CIS v8, as the deck's component-breakdown cards. */
  function frameworkSlide(ctx) {
    const D = window.ReportDeck;
    const P = window.ReportShell.PALETTE;
    const keys = Object.keys(FRAMEWORK_LABEL);

    const cards = keys.map(fw => {
      const score = calcFrameworkScore(fw);
      const color = deckScoreColor(score);
      const mapped = Object.values(_questionsById)
        .filter(q => (q.frameworks || []).some(f => f.framework === fw)).length;
      return '<div class="cmp-card">' +
          '<div class="cmp-head">' +
            '<span class="cmp-t">' + esc(FRAMEWORK_LABEL[fw]) + '</span>' +
            '<span class="cmp-w">' + mapped + ' mapped control' + (mapped === 1 ? '' : 's') + '</span>' +
          '</div>' +
          '<div class="cmp-bar"><div class="cmp-fill" style="width:' + (score === null ? 0 : score) + '%;background:' + color + '"></div></div>' +
          '<div class="cmp-score" style="color:' + color + '">' + (score === null ? '—' : score + '/100') + '</div>' +
          '<div class="cmp-d">' + (score === null
            ? 'No answered controls map to this framework yet.'
            : esc(getScoreRating(score)) + ' — scored over the controls mapped to this framework only.') + '</div>' +
        '</div>';
    }).join('');

    const body =
      '<div class="cmp-row" style="grid-template-columns:repeat(' + Math.max(keys.length, 1) + ',1fr)">' + cards + '</div>' +
      '<p style="margin-top:7mm;font-size:10pt;line-height:1.5;color:' + P.DECK_MUTED + '">' +
        'Framework scores are calculated over the subset of controls mapped to each framework, so a single control may ' +
        'contribute to both. Controls marked N/A or left unanswered are excluded from the calculation.' +
      '</p>';

    return D.slide({ title: 'Framework Alignment', body: body, pageNo: ctx.pageNo, ctx: ctx });
  }

  /** One slide per MAX_DOMAIN_ROWS domains. */
  function domainSlides(ctx, startPage) {
    const D = window.ReportDeck;
    const names = Object.keys(_sections);

    const rows = names.map(name => {
      const qs       = _sections[name];
      const score    = calcSectionScore(qs);
      const answered = qs.filter(q => (_answers[q.id] || {}).answer).length;
      return {
        domain:   name,
        score:    score,
        answered: answered + ' / ' + qs.length,
        rating:   score === null ? '—' : getScoreRating(score),
      };
    });

    const cols = [
      { label: 'Domain',   key: 'domain',   width: '34%' },
      { label: 'Score',    key: 'score',    width: '30%', raw: r => barCell(r.score) },
      { label: 'Answered', key: 'answered', width: '18%', cls: 'num' },
      { label: 'Rating',   key: 'rating',   width: '18%', raw: r => coloredCell(r.rating, deckScoreColor(r.score)) },
    ];

    const pages = rows.length ? chunkRows(rows, MAX_DOMAIN_ROWS) : [[]];
    return pages.map((page, i) => D.slide({
      title:  'Domain Breakdown' + (pages.length > 1 ? ' (' + (i + 1) + ' of ' + pages.length + ')' : ''),
      body:   D.dataTable({ cols: cols, rows: page }),
      pageNo: startPage + i,
      ctx:    ctx,
    }));
  }

  /** Unresolved controls (No / Partial), heaviest weight first, No before Partial. */
  function gapSlides(ctx, startPage) {
    const D = window.ReportDeck;
    const C = ANSWER_DECK_COLOR();
    const W = WEIGHT_DECK_COLOR();

    const gaps = Object.values(_questionsById)
      .map(q => ({ q: q, a: _answers[q.id] || {} }))
      .filter(x => x.a.answer === 'no' || x.a.answer === 'partial')
      .sort((a, b) => {
        const pw = (WEIGHT_POINTS[b.q.weight] || 2) - (WEIGHT_POINTS[a.q.weight] || 2);
        if (pw !== 0) return pw;
        if (a.a.answer === b.a.answer) return 0;
        return a.a.answer === 'no' ? -1 : 1;
      })
      .map(x => ({
        weight:  WEIGHT_LABEL[x.q.weight] || x.q.weight || '—',
        control: truncate(x.q.text, MAX_CONTROL_CHARS),
        ref:     refText(x.q),
        status:  ANSWER_LABEL[x.a.answer],
        notes:   x.a.notes ? truncate(x.a.notes, MAX_NOTE_CHARS) : '—',
        _ans:    x.a.answer,
        _w:      x.q.weight,
      }));

    const cols = [
      { label: 'Weight',    key: 'weight',  width: '11%', raw: r => coloredCell(r.weight, W[r._w] || '#A6A6A6') },
      { label: 'Control',   key: 'control', width: '42%' },
      { label: 'Reference', key: 'ref',     width: '14%' },
      { label: 'Status',    key: 'status',  width: '10%', raw: r => coloredCell(r.status, C[r._ans]) },
      { label: 'Notes',     key: 'notes',   width: '23%' },
    ];

    if (!gaps.length) {
      const P = window.ReportShell.PALETTE;
      return [D.slide({
        title: 'Prioritised Gaps',
        body:  '<div style="background:#F7F9FB;border-left:1.6mm solid ' + P.DECK_GREEN + ';border-radius:1.5mm;padding:6mm 7mm">' +
                 '<div style="font-size:14pt;font-weight:700;color:' + P.DECK_INK + ';margin-bottom:2mm">No material gaps recorded</div>' +
                 '<div style="font-size:11pt;color:' + P.DECK_MUTED + ';line-height:1.5">Every answered control is fully implemented, or marked not applicable.</div>' +
               '</div>',
        pageNo: startPage,
        ctx:    ctx,
      })];
    }

    const pages = chunkRows(gaps, MAX_GAP_ROWS);
    return pages.map((page, i) => D.slide({
      title:  'Prioritised Gaps' + (pages.length > 1 ? ' (' + (i + 1) + ' of ' + pages.length + ')' : ''),
      body:   D.dataTable({ cols: cols, rows: page }),
      pageNo: startPage + i,
      ctx:    ctx,
    }));
  }

  /** Every control and its recorded answer, grouped by domain, paginated. */
  function appendixSlides(ctx, startPage) {
    const D = window.ReportDeck;
    const C = ANSWER_DECK_COLOR();

    const rows = [];
    Object.keys(_sections).forEach(name => {
      _sections[name].forEach(q => {
        const a = _answers[q.id] || {};
        rows.push({
          domain:  name,
          control: truncate(q.text, MAX_CONTROL_CHARS),
          ref:     refText(q),
          weight:  WEIGHT_LABEL[q.weight] || q.weight || '—',
          answer:  a.answer ? ANSWER_LABEL[a.answer] : 'Unanswered',
          notes:   a.notes ? truncate(a.notes, MAX_NOTE_CHARS) : '—',
          _ans:    a.answer,
        });
      });
    });

    if (!rows.length) return [];

    const cols = [
      { label: 'Domain',    key: 'domain',  width: '18%' },
      { label: 'Control',   key: 'control', width: '36%' },
      { label: 'Reference', key: 'ref',     width: '13%' },
      { label: 'Weight',    key: 'weight',  width: '10%' },
      { label: 'Answer',    key: 'answer',  width: '10%', raw: r => coloredCell(r.answer, r._ans ? C[r._ans] : '#A6A6A6') },
      { label: 'Notes',     key: 'notes',   width: '13%' },
    ];

    const pages = chunkRows(rows, MAX_APPENDIX_ROWS);
    return pages.map((page, i) => D.slide({
      title:  'Appendix — Responses' + (pages.length > 1 ? ' (' + (i + 1) + ' of ' + pages.length + ')' : ''),
      body:   D.dataTable({ cols: cols, rows: page }),
      pageNo: startPage + i,
      ctx:    ctx,
    }));
  }

  function methodologySlide(ctx) {
    const D = window.ReportDeck;
    const body =
      '<ul class="bl">' +
        '<li>Each control carries a weight: <b>Critical</b> 5 points, <b>High</b> 3, <b>Medium</b> 2, <b>Low</b> 1.</li>' +
        '<li>A <b>Yes</b> answer earns the full weight, <b>Partial</b> earns half, and <b>No</b> earns none.</li>' +
        '<li>Controls marked <b>N/A</b> or left unanswered are excluded from both the earned and the possible totals, so they neither help nor penalise the score.</li>' +
        '<li>A domain score is that domain\'s earned points divided by its possible points, expressed out of 100. Framework scores use the same formula over the controls mapped to each framework.</li>' +
        '<li>The overall GRC score feeds the Cyber Insurability Score at a 40% weighting, combined with the Secure Score at 60%.</li>' +
        '<li>Ratings band as <b>Low Risk</b> (80+), <b>Moderate Risk</b> (60–79), <b>Elevated Risk</b> (40–59) and <b>High Risk</b> (below 40).</li>' +
      '</ul>';
    return D.slide({ title: 'Methodology', body: body, pageNo: ctx.pageNo, ctx: ctx });
  }

  // ── Deck assembly ─────────────────────────────────────────────────────────

  /** The tenant this report is about — same precedence as tenantParam(). */
  function effectiveTenantId() {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) return window.globalTenantId;
    return (window.currentUser || {}).tenantId || null;
  }

  /**
   * Client label for the cover.
   *
   * Resolved from /api/tenants by id, not by reading the header dropdowns: the
   * superadmin selector opens on a "— Select tenant —" placeholder whose text is
   * not a tenant name, and it is hidden altogether for everyone else. The
   * dropdowns are only a fallback, and only when one holds a real value.
   */
  async function resolveClientName() {
    const id = effectiveTenantId();
    if (id) {
      try {
        const res = await fetch('api/tenants', { credentials: 'same-origin' });
        if (res.ok) {
          const rows = await res.json();
          const hit = (rows || []).find(t => String(t.id) === String(id));
          if (hit && hit.name) return hit.name;
        }
      } catch (_) { /* fall through */ }
    }
    // Placeholder options carry value="", so a truthy value means a real pick.
    for (const selId of ['globalTenantSelect', 'tenantSwitcher']) {
      const sel = document.getElementById(selId);
      if (!sel || !sel.value) continue;
      const opt = sel.options && sel.options[sel.selectedIndex];
      const txt = opt && (opt.textContent || '').trim();
      if (txt) return txt;
    }
    return 'Client';
  }

  async function generateGrcReport() {
    const S = window.ReportShell;
    const D = window.ReportDeck;
    if (!D) throw new Error('ReportDeck not loaded');

    const score    = _assessment ? (_assessment.grc_score || 0) : 0;
    const totalQ   = Object.values(_sections).reduce((s, q) => s + q.length, 0);
    const answered = Object.values(_answers).filter(a => a.answer).length;
    const now      = new Date();

    const ctx = {
      clientName:  await resolveClientName(),
      author:      (window.currentUser || {}).username || 'Reflex',
      dateStr:     now.toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' }),
      periodLabel: _assessment
        ? 'Assessed ' + new Date(_assessment.assessed_at).toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' })
        : 'Not yet assessed',
      year:        now.getFullYear(),
      score:       score,
      rating:      getScoreRating(score),
      totalQ:      totalQ,
      answered:    answered,
      logoDataUri: await S.logoToDataUri(),
    };

    const slides = [coverSlide(ctx)];
    const push = (s) => { slides.push(s); };

    ctx.pageNo = slides.length + 1;
    push(scoreSlide(ctx));

    ctx.pageNo = slides.length + 1;
    push(frameworkSlide(ctx));

    domainSlides(ctx, slides.length + 1).forEach(push);
    gapSlides(ctx, slides.length + 1).forEach(push);
    appendixSlides(ctx, slides.length + 1).forEach(push);

    ctx.pageNo = slides.length + 1;
    push(methodologySlide(ctx));

    S.openReportWindow(D.renderDeck(slides, ctx), { width: 1280, height: 820 });
  }

  /** Wired from the static header button — loads data first if the tab is cold. */
  async function handleGenerateReport() {
    const btn = document.getElementById('grc-report-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Building…'; }
    try {
      if (!Object.keys(_sections).length) await loadAndRender();
      await generateGrcReport();
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Generate Report'; }
    }
  }

  // ── Main render ────────────────────────────────────────────────────────────
  async function loadAndRender() {
    const container = document.getElementById('grc-container');
    if (!container) return;

    container.innerHTML = '<div class="loading-overlay"><div class="loading-spinner"></div><span>Loading GRC assessment…</span></div>';

    // Fetch questions and current assessment in parallel
    let sectionsData = {}, answersData = [], assessmentData = null;
    try {
      const [qRes, aRes] = await Promise.all([
        fetch('api/grc/questions' + tenantParam('?'), { credentials: 'same-origin' }),
        fetch('api/grc/assessment' + tenantParam('?'), { credentials: 'same-origin' }),
      ]);
      if (qRes.ok) { const d = await qRes.json(); sectionsData = d.sections || {}; }
      if (aRes.ok) { const d = await aRes.json(); answersData = d.answers || []; assessmentData = d.assessment; }
    } catch (_) {}

    _sections   = sectionsData;
    _assessment = assessmentData;
    _questionsById = {};
    Object.values(_sections).forEach(qs => qs.forEach(q => { _questionsById[q.id] = q; }));

    // Build _answers map from saved answers
    _answers = {};
    answersData.forEach(a => {
      _answers[a.question_id] = { answer: a.answer, notes: a.notes || '' };
    });

    const score    = assessmentData ? (assessmentData.grc_score || 0) : 0;
    const readonly = isReadonly();
    const assessedAt = assessmentData
      ? new Date(assessmentData.assessed_at).toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' })
      : null;

    const totalQ    = Object.values(_sections).reduce((s, q) => s + q.length, 0);
    const answered  = Object.values(_answers).filter(a => a.answer).length;
    const pctDone   = totalQ > 0 ? Math.round(answered / totalQ * 100) : 0;

    container.innerHTML = `
      <div class="grc-wrapper">

        <!-- Score panel -->
        <div class="grc-score-panel">
          <div class="grc-score-left">
            <div id="grc-gauge" class="grc-gauge-container"></div>
            <div class="grc-score-meta">
              <div class="grc-score-title">GRC Score</div>
              ${assessedAt ? `<div class="grc-score-date">Last assessed: ${assessedAt}</div>` : '<div class="grc-score-date">Not yet assessed</div>'}
              <div class="grc-progress-info">${answered}/${totalQ} questions answered (${pctDone}%)</div>
            </div>
          </div>
          <div id="grc-breakdown" class="grc-breakdown"></div>
        </div>

        <!-- Framework alignment -->
        <div class="grc-framework-panel">
          <div class="grc-framework-title">Framework Alignment</div>
          <div id="grc-framework-breakdown" class="grc-breakdown"></div>
        </div>

        <!-- Questionnaire -->
        <div class="grc-questionnaire">
          <div class="grc-questionnaire-header">
            <h3>Self-Assessment Questionnaire</h3>
            <p class="grc-questionnaire-subtitle">
              Answer each question honestly. <strong>Yes</strong> = fully implemented,
              <strong>Partial</strong> = in progress or partially implemented,
              <strong>No</strong> = not implemented, <strong>N/A</strong> = not applicable.
            </p>
          </div>
          <div id="grc-questions-wrap"></div>
        </div>

        <!-- Save bar -->
        ${!readonly ? `
        <div class="grc-save-bar">
          <span id="grc-save-status" class="grc-save-status"></span>
          <button id="grc-save-btn" class="btn btn-primary">Save Assessment</button>
        </div>` : ''}

      </div>`;

    // Render sub-components
    renderGauge(document.getElementById('grc-gauge'), score);
    renderDomainBreakdown(document.getElementById('grc-breakdown'));
    renderFrameworkBreakdown(document.getElementById('grc-framework-breakdown'));
    renderQuestionnaire(document.getElementById('grc-questions-wrap'));

    // Wire save button
    const saveBtn = document.getElementById('grc-save-btn');
    if (saveBtn) saveBtn.addEventListener('click', saveAssessment);

    // Wire the header report button. It lives outside #grc-container, so assign
    // rather than append — loadAndRender may run again on every tab switch.
    const reportBtn = document.getElementById('grc-report-btn');
    if (reportBtn) reportBtn.onclick = handleGenerateReport;
  }

  // Bind up front too, so the button works even if it is reached before
  // loadAndRender() has run (handleGenerateReport loads on demand).
  const _initBtn = document.getElementById('grc-report-btn');
  if (_initBtn) _initBtn.onclick = handleGenerateReport;

  return { loadAndRender, generateGrcReport };
})();

window.GrcTab = GrcTab;
