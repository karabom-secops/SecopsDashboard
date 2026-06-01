/* tab-incidents.js — Incident ticket dashboard for Arctic Wolf MDR uploads */

(function () {
  'use strict';

  let _currentMdrData = null;
  let _currentTrends  = null;

  function escHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return escHtml(dateStr);
    return d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
  }

  function statCard(label, value, accent) {
    return `
      <div class="stat-card ${escHtml(accent)}">
        <div class="stat-label">${escHtml(label)}</div>
        <div class="stat-value">${escHtml(value)}</div>
      </div>`;
  }

  function renderUploadInfo(upload, section = '') {
    const prefix = section ? `${section}-` : '';
    const el = document.getElementById(`${prefix}incidents-upload-info`);
    if (!el) return;
    if (!upload) {
      el.textContent = '';
      return;
    }
    el.innerHTML = `
      <div class="info-row-item">
        <strong>Uploaded:</strong> ${formatDate(upload.uploaded_at)}
      </div>
      <div class="info-row-item">
        <strong>Tickets:</strong> ${escHtml(String(upload.total_tickets || 0))}
      </div>
      <div class="info-row-item">
        <strong>Resolved:</strong> ${escHtml(String(upload.resolved_count || 0))}
      </div>
      <div class="info-row-item">
        <strong>Pending:</strong> ${escHtml(String(upload.pending_count || 0))}
      </div>
      <div class="info-row-item">
        <strong>Avg resolution hrs:</strong> ${upload.avg_resolution_hours !== null ? escHtml(String(upload.avg_resolution_hours)) : '—'}
      </div>`;
  }

  function renderStatCards(section = '') {
    const prefix = section ? `${section}-` : '';
    const container = document.getElementById(`${prefix}incidents-stat-cards`);
    if (!container) return;

    const upload = _currentMdrData && _currentMdrData.upload ? _currentMdrData.upload : null;
    const trends = _currentTrends || {};
    const resolved = (trends.solved || 0) + (trends.closed || 0);

    const cards = [
      { label: 'Total Tickets', value: upload ? upload.total_tickets : '—', accent: 'accent-blue' },
      { label: 'Resolved', value: upload ? upload.resolved_count : '—', accent: 'accent-green' },
      { label: 'Pending', value: upload ? upload.pending_count : '—', accent: 'accent-amber' },
      { label: 'High Severity', value: trends.high_severity || 0, accent: 'accent-red' },
      { label: 'Medium Severity', value: trends.medium_severity || 0, accent: 'accent-blue' },
      { label: 'Low Severity', value: trends.low_severity || 0, accent: 'accent-green' },
    ];

    container.innerHTML = cards.map(card => statCard(card.label, card.value, card.accent)).join('');
  }

  function renderTicketCarousel(section = '') {
    const prefix = section ? `${section}-` : '';
    const slidesContainer = document.getElementById(`${prefix}incidents-carousel-slides`);
    const controlsContainer = document.getElementById(`${prefix}incidents-carousel-controls`);
    
    if (!slidesContainer || !controlsContainer) return;

    const tickets = _currentMdrData && Array.isArray(_currentMdrData.tickets) ? _currentMdrData.tickets : [];
    slidesContainer.innerHTML = '';

    if (tickets.length === 0) {
      const slide = document.createElement('div');
      slide.className = 'carousel-slide';
      slide.innerHTML = '<p style="color:var(--muted);font-size:.87rem;padding:1rem">No tickets available.</p>';
      slidesContainer.appendChild(slide);
    } else {
      tickets.forEach(ticket => {
        const slide = document.createElement('div');
        slide.className = 'carousel-slide';
        slide.innerHTML = `
          <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:1rem;font-size:0.9rem">
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Ticket #</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${escHtml(ticket.ticketNumber)}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Status</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${escHtml(ticket.status)}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Severity</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${escHtml(ticket.severity || '—')}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Type</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${escHtml(ticket.ticketType || '—')}</div>
            </div>
            <div style="grid-column:1/-1">
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Subject</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${escHtml(ticket.subject)}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Created</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${formatDate(ticket.createdAt)}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Updated</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${formatDate(ticket.updatedAt)}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Assigned To</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${escHtml(ticket.assignedTo || '—')}</div>
            </div>
          </div>
        `;
        slidesContainer.appendChild(slide);
      });
    }

    // Initialize or reinitialize carousel
    if (window._incidentsCarousel) {
      window._incidentsCarousel.destroy();
    }
    window._incidentsCarousel = window.initCarousel(`#${prefix}incidents-carousel`);
  }

  function renderEmptyState(hasUpload, section = '') {
    const prefix = section ? `${section}-` : '';
    const emptyEl = document.getElementById(`${prefix}incidents-empty-state`);
    const contentEl = document.getElementById(`${prefix}incidents-content`);
    if (!emptyEl || !contentEl) return;
    if (!hasUpload) {
      emptyEl.hidden = false;
      contentEl.hidden = true;
      return;
    }
    emptyEl.hidden = true;
    contentEl.hidden = false;
  }

  async function loadIncidents() {
    const [mdrRes, trendsRes] = await Promise.all([
      fetch('api/mdr'),
      fetch('api/mdr/trends'),
    ]);

    if (!mdrRes.ok) {
      throw new Error('Failed to load incident overview.');
    }

    _currentMdrData = await mdrRes.json();
    _currentTrends  = trendsRes.ok ? await trendsRes.json() : {};
  }

  function renderAll(section = '') {
    const prefix = section ? `${section}-` : '';
    const hasUpload = _currentMdrData && _currentMdrData.upload;
    renderStatCards(section);
    renderUploadInfo(_currentMdrData && _currentMdrData.upload ? _currentMdrData.upload : null, section);
    renderEmptyState(hasUpload, section);
    if (hasUpload) {
      renderTicketCarousel(section);
    }
    if (!section) {
      document.title = hasUpload ? 'SecOps — Incidents' : 'SecOps Dashboard';
    }
  }

  window.renderIncidents = async function renderIncidents(section = '') {
    try {
      await loadIncidents();
    } catch (err) {
      console.error(err);
      _currentMdrData = null;
      _currentTrends  = {};
    }
    renderAll(section);
  };
})();
