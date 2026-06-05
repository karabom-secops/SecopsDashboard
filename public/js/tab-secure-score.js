// tab-secure-score.js — Secure Score tab implementation

const SecureScoreTab = (() => {
  let currentScore = null;
  let _trendChart = null;

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
      <div style="text-align:center;font-size:13px;font-weight:600;color:#7a9bb0;font-family:Manrope,sans-serif;margin-bottom:4px;letter-spacing:0.04em">Secure Score</div>
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

  function renderComponentScores(container, components) {
    const items = [
      {
        label: 'Vulnerabilities', weight: '40%',
        score: components.vulnerabilities.score,
        desc: 'Based on critical, high, medium, and low findings',
        tooltip: 'Score starts at 100. Each finding deducts points:<br>• Critical: −20 pts<br>• High: −10 pts<br>• Medium: −5 pts<br>• Low: −1 pt<br>Minimum score is 0.',
      },
      {
        label: 'Security Awareness', weight: '35%',
        score: components.awareness.score,
        desc: 'Training completion rate',
        tooltip: 'Score = % of training sessions completed (phishing simulations excluded).<br>100% completion = 100/100.',
      },
      {
        label: 'Incident Response', weight: '25%',
        score: components.incidentResponse.score,
        desc: 'Ticket resolution & speed',
        tooltip: 'Score based on ticket resolution rate minus a speed penalty.<br>• Resolution rate forms the base score.<br>• Avg resolution &gt; 24 hrs deducts up to 20 pts.',
      },
    ];

    const html = `
      <div class="component-scores">
        ${items.map(item => `
          <div class="component-card">
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
            <div class="component-score-text">${item.score}/100</div>
            <small>${item.desc}</small>
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
      { label: 'Vulnerabilities',    score: (comp.vulnerabilities || {}).score || 0,    weight: '40%' },
      { label: 'Security Awareness', score: (comp.awareness || {}).score || 0,          weight: '35%' },
      { label: 'Incident Response',  score: (comp.incidentResponse || {}).score || 0,   weight: '25%' },
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
    const history = historyData ? historyData.history : [];
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
          <button id="secure-score-print" class="score-action-btn" title="Print or save as PDF">&#x2399; Export</button>
        </div>
        <div class="secure-score-main">
          <div id="secure-score-gauge" class="score-gauge-container"></div>
          <div id="secure-score-data-age" class="data-age-info"></div>
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
      `;

      document.getElementById('secure-score-refresh').addEventListener('click', loadAndRender);
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

    // Render main gauge with delta
    const gaugeContainer = document.getElementById('secure-score-gauge');
    renderScoreGauge(gaugeContainer, scoreData.score, delta);

    // Render insurability panel
    const insurabilityContainer = document.getElementById('secure-score-insurability');
    if (insurabilityContainer) renderInsurabilityPanel(insurabilityContainer, scoreData, history, grcData);

    // Render component scores
    const componentContainer = document.getElementById('secure-score-components');
    renderComponentScores(componentContainer, scoreData.components);

    // Render trend chart (pass grc score for insurability overlay line)
    const trendContainer = document.getElementById('secure-score-trend');
    const grcScoreVal = (grcData && grcData.assessment) ? (grcData.assessment.grc_score || 0) : null;
    renderTrendChart(trendContainer, history, grcScoreVal);

    // Render recommendations
    const recommendationContainer = document.getElementById('secure-score-recommendations');
    renderRecommendations(recommendationContainer, scoreData.recommendations);

    // Render data age
    const dataAgeContainer = document.getElementById('secure-score-data-age');
    const dataAgeHtml = `
      <div class="data-age">
        <small>
          <strong>Last Updated:</strong><br>
          Vulnerabilities: ${scoreData.dataAge.vulns}<br>
          Awareness: ${scoreData.dataAge.awareness}<br>
          Incidents: ${scoreData.dataAge.mdr}
        </small>
      </div>
    `;
    dataAgeContainer.innerHTML = dataAgeHtml;

    // Render GRC indicator
    const grcEl = document.getElementById('secure-score-grc-indicator');
    if (grcEl) {
      const grcAsmt = grcData && grcData.assessment;
      if (grcAsmt) {
        const grcScore = grcAsmt.grc_score || 0;
        const grcColor = grcScore >= 80 ? '#27ae60' : grcScore >= 60 ? '#f39c12' : grcScore >= 40 ? '#e67e22' : '#e74c3c';
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
  }

  return {
    loadAndRender,
  };
})();

window.SecureScoreTab = SecureScoreTab;
