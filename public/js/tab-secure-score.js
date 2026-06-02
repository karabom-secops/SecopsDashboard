// tab-secure-score.js — Secure Score tab implementation

const SecureScoreTab = (() => {
  let currentScore = null;

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

  function renderScoreGauge(container, score) {
    const w = 220, h = 130;
    const cx = w / 2, cy = h - 10;
    const r = 90;
    // Semi-circle arc: from left (180°) to right (0°), top half
    const startX = cx - r, startY = cy;
    const endX   = cx + r, endY   = cy;
    const color  = getScoreColor(score);

    // Arc length for the semi-circle
    const arcLen = Math.PI * r;
    // Offset = portion to leave un-filled (from the end)
    const targetOffset = arcLen * (1 - score / 100);

    const svg = `
      <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" class="score-gauge" style="overflow:visible">
        <defs>
          <filter id="gauge-shadow">
            <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.15"/>
          </filter>
        </defs>
        <!-- Track arc -->
        <path d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${endY}"
              fill="none" stroke="#dde8f0" stroke-width="12" stroke-linecap="round"/>
        <!-- Score arc — animated via JS -->
        <path id="gauge-arc" d="M ${startX} ${cy} A ${r} ${r} 0 0 1 ${endX} ${endY}"
              fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
              stroke-dasharray="${arcLen}" stroke-dashoffset="${arcLen}"
              filter="url(#gauge-shadow)"/>
        <!-- Score number -->
        <text x="${cx}" y="${cy - 20}" text-anchor="middle"
              font-size="42" font-weight="700" fill="${color}" font-family="Manrope,sans-serif">
          ${Math.round(score)}
        </text>
        <!-- Rating label -->
        <text x="${cx}" y="${cy - 2}" text-anchor="middle"
              font-size="12" font-weight="600" fill="#7a9bb0" font-family="Manrope,sans-serif"
              text-transform="uppercase" letter-spacing="1">
          ${getScoreRating(score)}
        </text>
      </svg>
    `;

    container.innerHTML = svg;

    // Animate arc filling in
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

  function renderTrendChart(container, history) {
    if (!history || history.length === 0) {
      container.innerHTML = '<p>Insufficient data for trend chart.</p>';
      return;
    }

    // Simple ASCII-style chart (can be enhanced with Chart.js or D3)
    const maxScore = 100;
    const chartHeight = 150;
    const chartWidth = 300;
    const barWidth = chartWidth / history.length;

    const svg = `
      <svg width="${chartWidth + 50}" height="${chartHeight + 40}" class="trend-chart">
        <text x="10" y="15" font-size="12" font-weight="bold">Score Trend (Last 6 Months)</text>
        
        <!-- Y-axis labels -->
        <text x="25" y="35" font-size="10" text-anchor="end">100</text>
        <text x="25" y="105" font-size="10" text-anchor="end">50</text>
        <text x="25" y="175" font-size="10" text-anchor="end">0</text>
        
        <!-- Grid lines -->
        <line x1="30" y1="30" x2="${chartWidth + 30}" y2="30" stroke="#ecf0f1" stroke-width="1"/>
        <line x1="30" y1="100" x2="${chartWidth + 30}" y2="100" stroke="#ecf0f1" stroke-width="1"/>
        <line x1="30" y1="170" x2="${chartWidth + 30}" y2="170" stroke="#ecf0f1" stroke-width="1"/>
        
        <!-- Bars -->
        ${history
          .map((item, idx) => {
            const barHeight = (item.score / maxScore) * chartHeight;
            const x = 30 + idx * barWidth + barWidth * 0.1;
            const y = 170 - barHeight;
            return `
              <rect x="${x}" y="${y}" width="${barWidth * 0.8}" height="${barHeight}"
                    fill="${getScoreColor(item.score)}" opacity="0.8">
                <title>${item.monthKey}: ${item.score}</title>
              </rect>
              <text x="${x + barWidth * 0.4}" y="185" font-size="9" text-anchor="middle">${item.monthKey.slice(-2)}</text>
            `;
          })
          .join('')}
      </svg>
    `;

    container.innerHTML = svg;
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

    // Restore the original inner structure (wipe spinner)
    if (container) {
      container.innerHTML = `
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
    }

    currentScore = scoreData;

    // Render main gauge
    const gaugeContainer = document.getElementById('secure-score-gauge');
    renderScoreGauge(gaugeContainer, scoreData.score);

    // Render component scores
    const componentContainer = document.getElementById('secure-score-components');
    renderComponentScores(componentContainer, scoreData.components);

    // Render trend chart
    const trendContainer = document.getElementById('secure-score-trend');
    renderTrendChart(trendContainer, historyData ? historyData.history : []);

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
