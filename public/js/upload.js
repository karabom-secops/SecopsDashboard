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

})();
