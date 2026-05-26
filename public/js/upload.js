/* upload.js — handles the upload form submission */

(function () {
  'use strict';

  const form          = document.getElementById('uploadForm');
  const reportTextarea = document.getElementById('reportTextarea');
  const reportFile    = document.getElementById('reportFile');
  const csvFile       = document.getElementById('csvFile');
  const errorDiv      = document.getElementById('uploadError');
  const btnUpload     = document.getElementById('btnUpload');
  const btnLabel      = document.getElementById('uploadBtnLabel');
  const spinner       = document.getElementById('uploadSpinner');

  function showError(msg) {
    errorDiv.textContent = msg;
    errorDiv.hidden = false;
  }

  function clearError() {
    errorDiv.hidden = true;
    errorDiv.textContent = '';
  }

  function setLoading(loading) {
    btnUpload.disabled = loading;
    btnLabel.textContent = loading ? 'Parsing…' : 'Parse & Load Dashboard';
    spinner.hidden = !loading;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();

    const fd = new FormData();

    // Validate date picker
    const weekDateInput = document.getElementById('weekDate');
    const weekDateVal = weekDateInput ? weekDateInput.value.trim() : '';
    if (!weekDateVal) {
      showError('Please select the Week Commencing date.');
      return;
    }
    const weekPrefix = `Week Commencing: ${weekDateVal}`;

    // Prefer textarea text; fall back to file
    const pastedText = reportTextarea.value.trim();
    const fileInput  = reportFile.files[0];

    if (pastedText) {
      fd.append('report', weekPrefix + '\n\n' + pastedText);
    } else if (fileInput) {
      // Read file as text and send as field (server reads req.body.report first)
      try {
        const text = await readFileAsText(fileInput);
        fd.append('report', weekPrefix + '\n\n' + text);
      } catch {
        showError('Could not read the uploaded file.');
        return;
      }
    } else {
      showError('Please paste a report or upload a .txt file.');
      return;
    }

    // Optional CSV
    const csvInput = csvFile.files[0];
    if (csvInput) {
      fd.append('csv', csvInput);
    }

    setLoading(true);
    try {
      const res = await fetch('api/upload', { method: 'POST', body: fd });
      const data = await res.json();

      if (!res.ok || data.error) {
        showError(data.error || `Server error (${res.status})`);
        return;
      }

      // Redirect to dashboard, highlighting the newly uploaded week
      window.location.href = '/secops/?week=' + encodeURIComponent(data.weekKey);

    } catch (err) {
      showError('Network error: ' + err.message);
    } finally {
      setLoading(false);
    }
  });

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = (e) => resolve(e.target.result);
      reader.onerror = () => reject(new Error('FileReader error'));
      reader.readAsText(file);
    });
  }

  // ── Nessus Scan Upload ──────────────────────────────────────────────────────

  async function initVulnUpload() {
    const vulnForm      = document.getElementById('vulnUploadForm');
    const vulnMonthInput = document.getElementById('vulnMonthKey');
    const vulnFileInput = document.getElementById('vulnFile');
    const vulnErrorDiv  = document.getElementById('vulnUploadError');
    const btnVuln       = document.getElementById('btnVulnUpload');
    const vulnBtnLabel  = document.getElementById('vulnBtnLabel');
    const vulnSpinner   = document.getElementById('vulnSpinner');
    const tenantWrap    = document.getElementById('vulnTenantSelectWrap');
    const tenantSel     = document.getElementById('vulnTenantId');

    if (!vulnForm) return;

    // Default to current month
    const now = new Date();
    vulnMonthInput.value = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0');

    // Superadmin: load tenant list and show the tenant picker
    if (window.currentUser && window.currentUser.role === 'superadmin') {
      try {
        const res = await fetch('api/tenants');
        const tenants = res.ok ? await res.json() : [];
        tenants.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t.id;
          opt.textContent = t.name;
          tenantSel.appendChild(opt);
        });
        if (tenantWrap) tenantWrap.hidden = false;
      } catch (_) {
        // Non-fatal: tenant selector stays hidden, upload may fail server-side
      }
    }

    function showVulnError(msg) {
      vulnErrorDiv.textContent = msg;
      vulnErrorDiv.hidden = false;
    }

    function clearVulnError() {
      vulnErrorDiv.hidden = true;
      vulnErrorDiv.textContent = '';
    }

    function setVulnLoading(loading) {
      btnVuln.disabled = loading;
      vulnBtnLabel.textContent = loading ? 'Uploading…' : 'Upload Nessus Scan';
      vulnSpinner.hidden = !loading;
    }

    vulnForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearVulnError();

      const monthKey = (vulnMonthInput.value || '').trim();
      if (!monthKey) {
        showVulnError('Please select a month.');
        return;
      }

      const file = vulnFileInput.files[0];
      if (!file) {
        showVulnError('Please select a Nessus CSV or .nessus file.');
        return;
      }

      // For superadmin, tenantId is required
      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      if (isSA) {
        const tenantId = tenantSel ? (tenantSel.value || '').trim() : '';
        if (!tenantId) {
          showVulnError('Please select a tenant / organisation.');
          return;
        }
      }

      const fd = new FormData();
      fd.append('monthKey', monthKey);
      fd.append('vulnFile', file);
      if (isSA && tenantSel && tenantSel.value) {
        fd.append('tenantId', tenantSel.value);
      }

      setVulnLoading(true);
      try {
        const res  = await fetch('api/vulns/upload', { method: 'POST', body: fd });
        const data = await res.json();

        if (!res.ok || data.error) {
          showVulnError(data.error || `Server error (${res.status})`);
          return;
        }

        // Show carry-over summary then redirect
        const c = data.carriedCounts || {};
        const total = (c.fixed || 0) + (c.accepted || 0) + (c['in-progress'] || 0);
        if (total > 0) {
          const parts = [];
          if (c.fixed)            parts.push(`${c.fixed} fixed`);
          if (c.accepted)         parts.push(`${c.accepted} accepted risk`);
          if (c['in-progress'])   parts.push(`${c['in-progress']} in progress`);
          alert(`Upload successful!\n\n${total} finding${total !== 1 ? 's' : ''} automatically carried over from the previous scan:\n  • ${parts.join('\n  • ')}`);
        }

        window.location.href = '/secops/?tab=vulns&month=' + encodeURIComponent(data.monthKey);
      } catch (err) {
        showVulnError('Network error: ' + err.message);
      } finally {
        setVulnLoading(false);
      }
    });
  }

  // ── Security Awareness Upload ─────────────────────────────────────────────

  async function initAwarenessUpload() {
    var awarenessForm  = document.getElementById('awarenessUploadForm');
    var awarenessFile  = document.getElementById('awarenessFile');
    var awarenessErr   = document.getElementById('awarenessUploadError');
    var btnAwareness   = document.getElementById('btnAwarenessUpload');
    var awarenessLabel = document.getElementById('awarenessBtnLabel');
    var awarenessSpinner = document.getElementById('awarenessSpinner');
    var tenantWrap     = document.getElementById('awarenessTenantSelectWrap');
    var tenantSel      = document.getElementById('awarenessTenantId');

    if (!awarenessForm) return;

    if (window.currentUser && window.currentUser.role === 'superadmin') {
      try {
        const res = await fetch('api/tenants');
        const tenants = res.ok ? await res.json() : [];
        tenants.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t.id;
          opt.textContent = t.name;
          tenantSel.appendChild(opt);
        });
        if (tenantWrap) tenantWrap.hidden = false;
      } catch (_) {}
    }

    function showAwarenessError(msg) { awarenessErr.textContent = msg; awarenessErr.hidden = false; }
    function clearAwarenessError() { awarenessErr.hidden = true; awarenessErr.textContent = ''; }
    function setAwarenessLoading(loading) {
      btnAwareness.disabled = loading;
      awarenessLabel.textContent = loading ? 'Uploading…' : 'Upload CSV';
      awarenessSpinner.hidden = !loading;
    }

    awarenessForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearAwarenessError();

      const file = awarenessFile.files[0];
      if (!file) { showAwarenessError('Please select a CSV file.'); return; }

      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      if (isSA && tenantSel && !tenantSel.value) {
        showAwarenessError('Please select a tenant / organisation.'); return;
      }

      const fd = new FormData();
      fd.append('awarenessFile', file);
      if (isSA && tenantSel && tenantSel.value) fd.append('tenantId', tenantSel.value);

      setAwarenessLoading(true);
      try {
        const res  = await fetch('api/awareness/upload', { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok || data.error) { showAwarenessError(data.error || `Server error (${res.status})`); return; }
        window.location.href = '/secops/?tab=awareness';
      } catch (err) {
        showAwarenessError('Network error: ' + err.message);
      } finally {
        setAwarenessLoading(false);
      }
    });
  }

  // ── MDR Incidents Upload ────────────────────────────────────────────────

  async function initIncidentsUpload() {
    var incidentsForm  = document.getElementById('incidentsUploadForm');
    var incidentsFile  = document.getElementById('incidentsFile');
    var incidentsErr   = document.getElementById('incidentsUploadError');
    var btnIncidents   = document.getElementById('btnIncidentsUpload');
    var incidentsLabel = document.getElementById('incidentsBtnLabel');
    var incidentsSpinner = document.getElementById('incidentsSpinner');
    var tenantWrap     = document.getElementById('incidentsTenantSelectWrap');
    var tenantSel      = document.getElementById('incidentsTenantId');

    if (!incidentsForm) return;

    if (window.currentUser && window.currentUser.role === 'superadmin') {
      try {
        const res = await fetch('api/tenants');
        const tenants = res.ok ? await res.json() : [];
        tenants.forEach(t => {
          const opt = document.createElement('option');
          opt.value = t.id;
          opt.textContent = t.name;
          tenantSel.appendChild(opt);
        });
        if (tenantWrap) tenantWrap.hidden = false;
      } catch (_) {}
    }

    function showIncidentsError(msg) { incidentsErr.textContent = msg; incidentsErr.hidden = false; }
    function clearIncidentsError() { incidentsErr.hidden = true; incidentsErr.textContent = ''; }
    function setIncidentsLoading(loading) {
      btnIncidents.disabled = loading;
      incidentsLabel.textContent = loading ? 'Uploading…' : 'Upload CSV';
      incidentsSpinner.hidden = !loading;
    }

    incidentsForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearIncidentsError();

      const file = incidentsFile.files[0];
      if (!file) { showIncidentsError('Please select a CSV file.'); return; }

      const isSA = window.currentUser && window.currentUser.role === 'superadmin';
      if (isSA && tenantSel && !tenantSel.value) {
        showIncidentsError('Please select a tenant / organisation.');
        return;
      }

      const fd = new FormData();
      fd.append('mdrFile', file);
      if (isSA && tenantSel && tenantSel.value) {
        fd.append('tenantId', tenantSel.value);
      }

      setIncidentsLoading(true);
      try {
        const res  = await fetch('api/mdr/upload', { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok || data.error) { showIncidentsError(data.error || `Server error (${res.status})`); return; }
        window.location.href = '/secops/?tab=incidents';
      } catch (err) {
        showIncidentsError('Network error: ' + err.message);
      } finally {
        setIncidentsLoading(false);
      }
    });
  }

  // Wait for auth.js to resolve window.currentUser before initialising
  if (window.currentUser) {
    initVulnUpload();
    initAwarenessUpload();
    initIncidentsUpload();
  } else {
    document.addEventListener('authReady', () => {
      initVulnUpload();
      initAwarenessUpload();
      initIncidentsUpload();
    }, { once: true });
  }

})();
