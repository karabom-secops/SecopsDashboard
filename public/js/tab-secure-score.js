// tab-secure-score.js — Secure Score tab implementation

const SecureScoreTab = (() => {
  let currentScore = null;

  async function fetchSecureScore() {
    try {
      const res = await fetch('/api/secure-score');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[SecureScore] fetch error:', err.message);
      return null;
    }
  }

  async function fetchScoreHistory() {
    try {
      const res = await fetch('/api/secure-score/history');
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
    const gaugeSize = 200;
    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference * (1 - score / 100);

    const svg = `
      <svg width="${gaugeSize}" height="${gaugeSize}" viewBox="0 0 ${gaugeSize} ${gaugeSize}" class="score-gauge">
        <!-- Background circle -->
        <circle cx="${gaugeSize / 2}" cy="${gaugeSize / 2}" r="${radius}" 
                fill="none" stroke="#ecf0f1" stroke-width="8"/>
        
        <!-- Score circle -->
        <circle cx="${gaugeSize / 2}" cy="${gaugeSize / 2}" r="${radius}" 
                fill="none" stroke="${getScoreColor(score)}" stroke-width="8"
                stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
                stroke-linecap="round" style="transform: rotate(-90deg); transform-origin: center; transition: stroke-dashoffset 0.5s ease;"/>
        
        <!-- Score text -->
        <text x="50%" y="45%" text-anchor="middle" font-size="48" font-weight="bold" fill="${getScoreColor(score)}">
          ${Math.round(score)}
        </text>
        <text x="50%" y="60%" text-anchor="middle" font-size="14" fill="#7f8c8d">
          ${getScoreRating(score)}
        </text>
      </svg>
    `;

    container.innerHTML = svg;
  }

  function renderComponentScores(container, components) {
    const html = `
      <div class="component-scores">
        <div class="component-card">
          <div class="component-header">
            <h4>Vulnerabilities</h4>
            <span class="component-weight">(40%)</span>
          </div>
          <div class="component-score-bar">
            <div class="score-bar-fill" style="width: ${components.vulnerabilities.score}%; background-color: ${getScoreColor(components.vulnerabilities.score)};"></div>
          </div>
          <div class="component-score-text">${components.vulnerabilities.score}/100</div>
          <small>Based on critical, high, medium, and low findings</small>
        </div>

        <div class="component-card">
          <div class="component-header">
            <h4>Security Awareness</h4>
            <span class="component-weight">(35%)</span>
          </div>
          <div class="component-score-bar">
            <div class="score-bar-fill" style="width: ${components.awareness.score}%; background-color: ${getScoreColor(components.awareness.score)};"></div>
          </div>
          <div class="component-score-text">${components.awareness.score}/100</div>
          <small>Training completion rate</small>
        </div>

        <div class="component-card">
          <div class="component-header">
            <h4>Incident Response</h4>
            <span class="component-weight">(25%)</span>
          </div>
          <div class="component-score-bar">
            <div class="score-bar-fill" style="width: ${components.incidentResponse.score}%; background-color: ${getScoreColor(components.incidentResponse.score)};"></div>
          </div>
          <div class="component-score-text">${components.incidentResponse.score}/100</div>
          <small>Ticket resolution & speed</small>
        </div>
      </div>
    `;
    container.innerHTML = html;
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
    const scoreData = await fetchSecureScore();
    const historyData = await fetchScoreHistory();

    if (!scoreData) {
      document.getElementById('secure-score-container').innerHTML =
        '<div class="error-message">Failed to load Secure Score data.</div>';
      return;
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
