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
    return window.currentUser && window.currentUser.role === 'readonly';
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
  }

  return { loadAndRender };
})();

window.GrcTab = GrcTab;
