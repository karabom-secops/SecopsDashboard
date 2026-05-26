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

  function tenantParam(sep) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
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

  function renderUploadInfo(upload) {
    const el = document.getElementById('incidents-upload-info');
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

  function renderStatCards() {
    const container = document.getElementById('incidents-stat-cards');
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

  function renderTicketTable() {
    const tbody = document.getElementById('incidents-tbody');
    if (!tbody) return;
    const tickets = _currentMdrData && Array.isArray(_currentMdrData.tickets) ? _currentMdrData.tickets : [];

    if (tickets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8">No tickets available.</td></tr>';
      return;
    }

    tbody.innerHTML = tickets.map(ticket => `
      <tr>
        <td>${escHtml(ticket.ticketNumber)}</td>
        <td>${escHtml(ticket.subject)}</td>
        <td>${escHtml(ticket.status)}</td>
        <td>${escHtml(ticket.ticketType || '—')}</td>
        <td>${escHtml(ticket.severity || '—')}</td>
        <td>${formatDate(ticket.createdAt)}</td>
        <td>${formatDate(ticket.updatedAt)}</td>
        <td>${escHtml(ticket.assignedTo || '—')}</td>
      </tr>
    `).join('');
  }

  function renderEmptyState(hasUpload) {
    const emptyEl = document.getElementById('incidents-empty-state');
    const contentEl = document.getElementById('incidents-content');
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
    const tenantQuery = tenantParam('?');
    const [mdrRes, trendsRes] = await Promise.all([
      fetch('api/mdr' + tenantQuery),
      fetch('api/mdr/trends' + tenantQuery),
    ]);

    if (!mdrRes.ok) {
      throw new Error('Failed to load incident overview.');
    }

    _currentMdrData = await mdrRes.json();
    _currentTrends  = trendsRes.ok ? await trendsRes.json() : {};
  }

  function showUploadError(msg) {
    const errorDiv = document.getElementById('incidentsUploadError');
    if (!errorDiv) return;
    errorDiv.textContent = msg;
    errorDiv.hidden = false;
  }

  function clearUploadError() {
    const errorDiv = document.getElementById('incidentsUploadError');
    if (!errorDiv) return;
    errorDiv.hidden = true;
    errorDiv.textContent = '';
  }

  function setUploadLoading(loading) {
    const btn = document.getElementById('btnIncidentsUpload');
    const spinner = document.getElementById('incidentsUploadSpinner');
    if (btn) btn.disabled = loading;
    if (spinner) spinner.hidden = !loading;
  }

  async function initIncidentsUpload() {
    const form = document.getElementById('incidentsUploadForm');
    if (!form) return;

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      clearUploadError();

      const fileInput = document.getElementById('incidentsFile');
      const file = fileInput && fileInput.files.length > 0 ? fileInput.files[0] : null;
      if (!file) {
        showUploadError('Please select a CSV file to upload.');
        return;
      }

      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      if (isSA && !window.globalTenantId) {
        showUploadError('Please select a tenant in the header before uploading.');
        return;
      }

      const fd = new FormData();
      fd.append('mdrFile', file);
      if (isSA && window.globalTenantId) {
        fd.append('tenantId', window.globalTenantId);
      }

      setUploadLoading(true);
      try {
        const res = await fetch('api/mdr/upload', { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok || data.error) {
          showUploadError(data.error || `Server error (${res.status})`);
          return;
        }

        await window.renderIncidents();
      } catch (err) {
        showUploadError('Network error: ' + err.message);
      } finally {
        setUploadLoading(false);
      }
    });
  }

  function renderAll() {
    const hasUpload = _currentMdrData && _currentMdrData.upload;
    renderStatCards();
    renderUploadInfo(_currentMdrData && _currentMdrData.upload ? _currentMdrData.upload : null);
    renderEmptyState(hasUpload);
    if (hasUpload) {
      renderTicketTable();
    }
    document.title = hasUpload ? 'SecOps — Incidents' : 'SecOps Dashboard';
  }

  window.renderIncidents = async function renderIncidents() {
    try {
      await loadIncidents();
    } catch (err) {
      console.error(err);
      _currentMdrData = null;
      _currentTrends  = {};
    }
    renderAll();
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initIncidentsUpload);
  } else {
    initIncidentsUpload();
  }
})();
