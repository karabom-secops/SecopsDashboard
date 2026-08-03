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

  // ── Printable GRC report ───────────────────────────────────────────────────

  const WEIGHT_POINTS = { critical: 5, high: 3, medium: 2, low: 1 };
  const ANSWER_LABEL  = { yes: 'Yes', partial: 'Partial', no: 'No', na: 'N/A' };
  const ANSWER_COLOR  = { yes: '#27ae60', partial: '#f39c12', no: '#e74c3c', na: '#90A4AE' };

  function esc(s) {
    return window.ReportShell.esc(s);
  }

  /** Static (unanimated) twin of renderGauge(), returned as an SVG string. */
  function buildGrcGaugeSvg(score) {
    const w = 220, h = 130, cx = w / 2, cy = h - 10, r = 90;
    const startX = cx - r, endX = cx + r;
    const color  = getScoreColor(score);
    const arcLen = Math.PI * r;
    const offset = arcLen * (1 - score / 100);
    return `
      <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
        <path d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${cy}"
              fill="none" stroke="#dde8f0" stroke-width="12" stroke-linecap="round"/>
        <path d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${cy}"
              fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
              stroke-dasharray="${arcLen}" stroke-dashoffset="${offset}"/>
        <text x="${cx}" y="${cy - 20}" text-anchor="middle"
              font-size="42" font-weight="700" fill="${color}" font-family="Segoe UI,Arial,sans-serif">${Math.round(score)}</text>
        <text x="${cx}" y="${cy - 2}" text-anchor="middle"
              font-size="12" font-weight="600" fill="#7a9bb0" font-family="Segoe UI,Arial,sans-serif">${getScoreRating(score)}</text>
      </svg>`;
  }

  /** One score row: label, filled bar, right-aligned score. */
  function buildScoreRow(label, score, meta) {
    const color = score !== null ? getScoreColor(score) : '#B0BEC5';
    const pct   = score !== null ? score : 0;
    return `
      <div style="margin-bottom:14px;page-break-inside:avoid;break-inside:avoid">
        <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:5px">
          <span style="font-size:0.88rem;font-weight:700;color:#2B3445">${esc(label)}</span>
          ${meta ? `<span style="font-size:0.72rem;color:#90A4AE">${esc(meta)}</span>` : ''}
          <span style="margin-left:auto;font-size:0.88rem;font-weight:700;color:${color}">${score !== null ? score + '/100' : '—'}</span>
        </div>
        <div style="height:9px;background:#EEF2F7;border-radius:5px;overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${color};border-radius:5px"></div>
        </div>
      </div>`;
  }

  function buildFrameworkSection() {
    return Object.keys(FRAMEWORK_LABEL)
      .map(fw => buildScoreRow(FRAMEWORK_LABEL[fw], calcFrameworkScore(fw), null))
      .join('');
  }

  function buildDomainSection() {
    const names = Object.keys(_sections);
    if (!names.length) return '<p style="font-size:0.88rem;color:#6b7c93">No assessment domains available.</p>';
    return names.map(name => {
      const qs       = _sections[name];
      const answered = qs.filter(q => (_answers[q.id] || {}).answer).length;
      return buildScoreRow(name, calcSectionScore(qs), `${answered}/${qs.length} answered`);
    }).join('');
  }

  /** Weight badge + NIST/CIS reference chips for a question. */
  function buildRefChips(q) {
    const cis = (q.frameworks || [])
      .filter(f => f.framework === 'CIS_V8')
      .map(f => `<span style="font-size:0.62rem;font-weight:600;color:#546E7A;background:#EEF2F7;border-radius:3px;padding:2px 6px">CIS ${esc(f.controlId)}</span>`)
      .join('');
    const nist = q.nist_ref
      ? `<span style="font-size:0.62rem;font-weight:600;color:#546E7A;background:#EEF2F7;border-radius:3px;padding:2px 6px">${esc(q.nist_ref)}</span>`
      : '';
    return nist + cis;
  }

  function weightBadge(weight) {
    const colors = { critical: '#c0392b', high: '#d68910', medium: '#1565C0', low: '#1e8449' };
    const bgs    = { critical: 'rgba(231,76,60,0.12)', high: 'rgba(245,158,11,0.12)', medium: 'rgba(21,101,192,0.10)', low: 'rgba(39,174,96,0.12)' };
    const c = colors[weight] || '#546E7A';
    return `<span style="font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;
                         padding:2px 8px;border-radius:3px;background:${bgs[weight] || '#EEF2F7'};color:${c}">${WEIGHT_LABEL[weight] || esc(weight || '')}</span>`;
  }

  /** Unresolved items (No / Partial), heaviest first, No before Partial. */
  function buildGapsSection() {
    const gaps = Object.values(_questionsById)
      .map(q => ({ q, a: (_answers[q.id] || {}) }))
      .filter(x => x.a.answer === 'no' || x.a.answer === 'partial')
      .sort((a, b) => {
        const pw = (WEIGHT_POINTS[b.q.weight] || 2) - (WEIGHT_POINTS[a.q.weight] || 2);
        if (pw !== 0) return pw;
        if (a.a.answer === b.a.answer) return 0;
        return a.a.answer === 'no' ? -1 : 1;
      });

    if (!gaps.length) {
      return `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:16px 20px;color:#166534;font-size:0.92rem">
        <strong>No material gaps recorded.</strong> Every answered control is fully implemented, or marked not applicable.
      </div>`;
    }

    return gaps.map(({ q, a }) => {
      const isNo   = a.answer === 'no';
      const border = isNo ? '#e74c3c' : '#f39c12';
      const bg     = isNo ? 'rgba(231,76,60,0.04)' : 'rgba(245,158,11,0.04)';
      return `
        <div style="border-left:4px solid ${border};border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:10px;
                    background:${bg};page-break-inside:avoid;break-inside:avoid">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
            ${weightBadge(q.weight)}
            ${buildRefChips(q)}
            <span style="margin-left:auto;font-size:0.72rem;font-weight:700;color:${ANSWER_COLOR[a.answer]}">${ANSWER_LABEL[a.answer]}</span>
          </div>
          <p style="font-size:0.88rem;color:#1a2a3a;line-height:1.55;margin:0">${esc(q.text)}</p>
          ${a.notes ? `<p style="font-size:0.8rem;color:#6b7c93;font-style:italic;margin:6px 0 0">${esc(a.notes)}</p>` : ''}
        </div>`;
    }).join('');
  }

  /** Every question, grouped by domain, with its recorded answer. */
  function buildQuestionAppendix() {
    const names = Object.keys(_sections);
    if (!names.length) return '<p style="font-size:0.88rem;color:#6b7c93">No questions available.</p>';

    return names.map(name => {
      const rows = _sections[name].map(q => {
        const a       = _answers[q.id] || {};
        const label   = a.answer ? ANSWER_LABEL[a.answer] : 'Unanswered';
        const color   = a.answer ? ANSWER_COLOR[a.answer] : '#B0BEC5';
        return `
          <div style="padding:9px 0;border-bottom:1px solid #eef2f6;page-break-inside:avoid;break-inside:avoid">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
              ${weightBadge(q.weight)}
              ${buildRefChips(q)}
              <span style="margin-left:auto;font-size:0.72rem;font-weight:700;color:${color}">${label}</span>
            </div>
            <p style="font-size:0.84rem;color:#1a2a3a;line-height:1.5;margin:0">${esc(q.text)}</p>
            ${a.notes ? `<p style="font-size:0.78rem;color:#6b7c93;font-style:italic;margin:4px 0 0">${esc(a.notes)}</p>` : ''}
          </div>`;
      }).join('');

      return `
        <div style="margin-bottom:22px">
          <div style="font-size:0.9rem;font-weight:800;color:#2B3445;background:#EEF2F7;border-left:4px solid #1565C0;
                      padding:8px 12px;margin-bottom:6px;page-break-after:avoid;break-after:avoid">${esc(name)}</div>
          ${rows}
        </div>`;
    }).join('');
  }

  function buildGrcNarrative(score, answered, totalQ) {
    const rating = getScoreRating(score);
    let body;
    if (score >= 80) {
      body = 'Governance, risk and compliance controls are broadly implemented and evidenced. The organisation presents a favourable risk profile to cyber insurers, with residual work concentrated in refinement rather than remediation.';
    } else if (score >= 60) {
      body = 'A workable governance baseline is in place, but several controls remain partially implemented. Closing the highest-weighted gaps below is the fastest route to improving both the GRC score and the resulting insurability position.';
    } else if (score >= 40) {
      body = 'Governance coverage is uneven — a material number of controls are absent or only partially implemented. Insurers are likely to query these gaps at renewal, and some may attach conditions or exclusions.';
    } else {
      body = 'Governance, risk and compliance coverage is significantly below expectation. The gaps listed below represent controls that underwriters routinely treat as prerequisites; addressing the critical-weighted items should be treated as a priority.';
    }
    const coverage = totalQ > 0
      ? `The assessment covers ${totalQ} controls, of which ${answered} (${Math.round(answered / totalQ * 100)}%) have been answered.`
      : 'No assessment questions were available at the time of generation.';
    return `The current GRC score is <strong>${Math.round(score)}/100</strong> — <strong>${rating}</strong>. ${body} ${coverage} The GRC score contributes 40% of the Cyber Insurability Score, with the Secure Score making up the remaining 60%.`;
  }

  async function generateGrcReport() {
    const score      = _assessment ? (_assessment.grc_score || 0) : 0;
    const scoreColor = getScoreColor(score);
    const rating     = getScoreRating(score);

    const totalQ   = Object.values(_sections).reduce((s, q) => s + q.length, 0);
    const answered = Object.values(_answers).filter(a => a.answer).length;

    const assessedAt = _assessment
      ? new Date(_assessment.assessed_at).toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' })
      : 'Not yet assessed';

    const user       = window.currentUser || {};
    const preparedBy = user.username || 'SecOps Dashboard';
    const reportDate = new Date().toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });
    const reportYear = new Date().getFullYear();

    const logoDataUri = await window.ReportShell.logoToDataUri();

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GRC &amp; Insurability Assessment Report — ${reportDate}</title>
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
  .cover::before {
    content: ''; position: absolute; top: -80px; right: -100px;
    width: 320px; height: 460px;
    background: #CFD8DC;
    transform: rotate(-18deg);
    border-radius: 14px;
    z-index: 0;
  }
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

  .page-header-stripe { background: #1565C0; height: 6px; width: 100%; }

  .exec-grid { display: grid; grid-template-columns: 220px 1fr; gap: 28px; align-items: center; margin-bottom: 24px; }
  .exec-gauge-block { text-align: center; background: #EEF2F7; border-radius: 12px; padding: 18px 14px; border-top: 4px solid #1565C0; overflow: hidden; }
  .exec-gauge-rating { font-size: 1.1rem; font-weight: 700; margin-top: 5px; }
  .exec-body { font-size: 0.88rem; color: #455A64; line-height: 1.65; }

  .score-box { background: #EEF2F7; border-radius: 10px; padding: 20px 22px; margin-bottom: 24px; border-left: 4px solid #1565C0; page-break-inside: avoid; break-inside: avoid; }

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
    <div class="cover-eyebrow">Governance, Risk &amp; Compliance</div>
    <div class="cover-title">GRC &amp; Insurability<br>Assessment Report</div>
  </div>

  <div class="cover-meta">
    <div><div class="cover-meta-label">Report Date</div><div class="cover-meta-value">${esc(reportDate)}</div></div>
    <div><div class="cover-meta-label">Prepared By</div><div class="cover-meta-value">${esc(preparedBy)}</div></div>
    <div><div class="cover-meta-label">GRC Score</div><div class="cover-meta-value" style="color:#1565C0">${Math.round(score)}/100 — ${rating}</div></div>
    <div><div class="cover-meta-label">Last Assessed</div><div class="cover-meta-value">${esc(assessedAt)}</div></div>
  </div>

  <div class="cover-footer">
    <div class="cover-classification">Confidential</div>
    <div class="cover-footer-right">
      ${esc(reportDate)}<br>
      Version: 1.0<br>
      <strong>Prepared by Reflex</strong>
    </div>
  </div>
</div>

<div class="page-header-stripe"></div>

<!-- CONTENT -->
<div class="page">

  <h2 class="section-heading">1. Executive Summary</h2>
  <div class="exec-grid">
    <div class="exec-gauge-block">
      ${buildGrcGaugeSvg(score)}
      <div class="exec-gauge-rating" style="color:${scoreColor}">${rating}</div>
      <div style="font-size:0.75rem;color:#78909C;margin-top:3px">GRC Score</div>
    </div>
    <div>
      <p class="exec-body">${buildGrcNarrative(score, answered, totalQ)}</p>
    </div>
  </div>

  <h2 class="section-heading">2. Framework Alignment</h2>
  <div class="score-box">
    ${buildFrameworkSection()}
  </div>

  <h2 class="section-heading">3. Domain Breakdown</h2>
  <div class="score-box">
    ${buildDomainSection()}
  </div>

  <h2 class="section-heading">4. Prioritised Gaps</h2>
  ${buildGapsSection()}

  <h2 class="section-heading">5. Appendix A — Full Questionnaire Responses</h2>
  ${buildQuestionAppendix()}

  <h2 class="section-heading">6. Appendix B — Methodology</h2>
  <p style="font-size:0.88rem;color:#3d5166;margin-bottom:14px">
    Each control carries a weight reflecting its importance: <strong>Critical (5 points)</strong>,
    <strong>High (3)</strong>, <strong>Medium (2)</strong> and <strong>Low (1)</strong>.
    A <em>Yes</em> answer earns the full weight, <em>Partial</em> earns half, and <em>No</em> earns none.
    Controls marked <em>N/A</em> or left unanswered are excluded from both the earned and the possible
    totals, so they neither help nor penalise the score.
  </p>
  <p style="font-size:0.88rem;color:#3d5166;margin-bottom:14px">
    A domain score is the earned points across that domain's controls divided by its possible points.
    Framework scores (NIST CSF, CIS Controls v8) are calculated the same way over the subset of controls
    mapped to that framework, so a single control may contribute to both. Each score is expressed out of 100.
  </p>
  <p style="font-size:0.88rem;color:#3d5166">
    The overall GRC score feeds the Cyber Insurability Score at a 40% weighting, combined with the
    Secure Score at 60%. Ratings are banded as Low Risk (80+), Moderate Risk (60–79),
    Elevated Risk (40–59) and High Risk (below 40).
  </p>

  <div class="page-footer">
    <span>GRC &amp; Insurability Assessment Report — ${esc(reportDate)}</span>
    <span>CONFIDENTIAL — Internal Use Only</span>
    <span>Prepared by Reflex &copy; ${reportYear}</span>
  </div>
</div>
</body>
</html>`;

    window.ReportShell.openReportWindow(html, { width: 1060, height: 860 });
  }

  /** Wired from the static header button — loads data first if the tab is cold. */
  async function handleGenerateReport() {
    const btn = document.getElementById('grc-report-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }
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

    // Wire the header report button (lives outside #grc-container, so assign
    // rather than append — loadAndRender may run again on tab switch).
    const reportBtn = document.getElementById('grc-report-btn');
    if (reportBtn) reportBtn.onclick = handleGenerateReport;
  }

  // Bind the header button up front too, so it works even if the user reaches
  // it before loadAndRender() has run (handleGenerateReport loads on demand).
  const _initBtn = document.getElementById('grc-report-btn');
  if (_initBtn) _initBtn.onclick = handleGenerateReport;

  return { loadAndRender, generateGrcReport };
})();

window.GrcTab = GrcTab;
