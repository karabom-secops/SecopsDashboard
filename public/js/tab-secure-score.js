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
    } else {
      deltaEl = `<text x="${cx}" y="${cy - 2}" text-anchor="middle"
        font-size="12" font-weight="600" fill="#7a9bb0" font-family="Manrope,sans-serif">
        ${getScoreRating(score)}
      </text>`;
    }

    const svg = `
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

  function renderTrendChart(container, history) {
    if (!history || history.length === 0) {
      container.innerHTML = '<p style="color:var(--muted);padding:1rem 0">Insufficient data for trend chart.</p>';
      return;
    }

    container.innerHTML = '<canvas id="secure-score-chart" style="max-height:220px"></canvas>';
    const canvas = container.querySelector('canvas');

    if (_trendChart) { _trendChart.destroy(); _trendChart = null; }

    // Reverse so oldest is on the left
    const sorted = [...history].reverse();

    _trendChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: sorted.map(h => formatMonthLabel(h.monthKey)),
        datasets: [{
          label: 'Security Score',
          data: sorted.map(h => h.score),
          borderColor: '#00b4d8',
          backgroundColor: 'rgba(0,180,216,0.08)',
          tension: 0.35,
          pointRadius: 5,
          pointBackgroundColor: sorted.map(h => getScoreColor(h.score)),
          pointBorderColor: '#fff',
          pointBorderWidth: 2,
          fill: true,
        }],
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
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => ` Score: ${ctx.parsed.y}/100 (${getScoreRating(ctx.parsed.y)})`,
            },
          },
        },
      },
    });
  }

  async function loadAndRender() {
    const container = document.getElementById('secure-score-container');
    if (container) {
      container.innerHTML = '<div class="loading-overlay"><div class="loading-spinner"></div><span>Loading score…</span></div>';
    }

    const [scoreData, historyData] = await Promise.all([fetchSecureScore(), fetchScoreHistory()]);

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
        </div>
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
      document.getElementById('secure-score-print').addEventListener('click', () => window.print());
    }

    currentScore = scoreData;

    // Render main gauge with delta
    const gaugeContainer = document.getElementById('secure-score-gauge');
    renderScoreGauge(gaugeContainer, scoreData.score, delta);

    // Render component scores
    const componentContainer = document.getElementById('secure-score-components');
    renderComponentScores(componentContainer, scoreData.components);

    // Render trend chart
    const trendContainer = document.getElementById('secure-score-trend');
    renderTrendChart(trendContainer, history);

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
  }

  return {
    loadAndRender,
  };
})();

window.SecureScoreTab = SecureScoreTab;
