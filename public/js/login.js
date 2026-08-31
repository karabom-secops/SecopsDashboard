(function () {
  'use strict';

  // Portal clients land somewhere different from staff. Kept in one place so
  // the three redirect sites below cannot drift apart.
  var CLIENT_HOME = 'portal.html';

  // If already authenticated, go straight to wherever this user belongs.
  // A client sent to the dashboard would see "you do not have access to any
  // pages" — their access map is empty by design — rather than their portal.
  fetch('api/auth/me', { credentials: 'same-origin' })
    .then(function (r) {
      if (!r.ok) return null;
      return r.json().catch(function () { return null; });
    })
    .then(function (me) {
      if (!me) return;
      location.replace(me.role === 'client' ? CLIENT_HOME : '');
    })
    .catch(function () {});

  var form    = document.getElementById('login-form');
  var errEl   = document.getElementById('login-error');
  var btn     = document.getElementById('login-btn');

  // ── SSO button ────────────────────────────────────────────────────────
  var ssoSection = document.getElementById('sso-section');
  var ssoBtn     = document.getElementById('sso-btn');

  fetch('api/auth/saml/enabled', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.enabled && ssoSection) ssoSection.hidden = false;
    })
    .catch(function () {});

  if (ssoBtn) {
    ssoBtn.addEventListener('click', function () {
      window.location.href = 'api/auth/saml/login';
    });
  }

  // ── Step 2a: TOTP verify ───────────────────────────────────────────────
  var mfaStep    = document.getElementById('mfa-step');
  var mfaCode    = document.getElementById('mfa-code');
  var mfaBtn     = document.getElementById('mfa-btn');
  var mfaBack    = document.getElementById('mfa-back');
  var mfaErr     = document.getElementById('mfa-error');

  // ── Step 2b: Forced enrollment ────────────────────────────────────────
  var enrollStep = document.getElementById('enroll-step');
  var enrollQr   = document.getElementById('enroll-qr-img');
  var enrollSecret = document.getElementById('enroll-secret-text');
  var enrollCode = document.getElementById('enroll-code');
  var enrollBtn  = document.getElementById('enroll-btn');
  var enrollBack = document.getElementById('enroll-back');
  var enrollErr  = document.getElementById('enroll-error');

  function showForm() {
    form.hidden        = false;
    if (mfaStep)    mfaStep.hidden    = true;
    if (enrollStep) enrollStep.hidden = true;
    errEl.hidden = true;
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }

  function showMfaStep() {
    form.hidden        = true;
    if (mfaStep)    mfaStep.hidden    = false;
    if (enrollStep) enrollStep.hidden = true;
    if (mfaCode)    mfaCode.value = '';
    if (mfaErr)     mfaErr.hidden = true;
    if (mfaCode)    setTimeout(function () { mfaCode.focus(); }, 50);
  }

  function showEnrollStep() {
    form.hidden        = true;
    if (mfaStep)    mfaStep.hidden    = true;
    if (enrollStep) enrollStep.hidden = false;
    // Fetch QR code from server
    fetch('api/auth/enroll-totp/setup', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (enrollQr)     enrollQr.src          = data.qrCodeUrl;
        if (enrollSecret) enrollSecret.textContent = data.secret;
      })
      .catch(function () {
        if (enrollErr) { enrollErr.textContent = 'Failed to load QR code.'; enrollErr.hidden = false; }
      });
  }

  // ── Password step ─────────────────────────────────────────────────────
  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errEl.hidden = true;
    btn.disabled = true;
    btn.textContent = 'Signing in\u2026';

    var username = document.getElementById('login-username').value.trim();
    var password = document.getElementById('login-password').value;

    try {
      var res = await fetch('api/auth/login', {
        method:      'POST',
        credentials: 'same-origin',
        headers:     { 'Content-Type': 'application/json' },
        body:        JSON.stringify({ username: username, password: password }),
      });

      var data = await res.json().catch(function () { return {}; });

      if (!res.ok) {
        errEl.textContent = data.error || 'Login failed. Please try again.';
        errEl.hidden = false;
        btn.disabled = false;
        btn.textContent = 'Sign In';
        return;
      }

      if (data.mfaRequired) {
        showMfaStep();
        return;
      }

      if (data.enrollRequired) {
        showEnrollStep();
        return;
      }

      // Normal login (non-SA or grace-period SA) — managers get their own page
      location.replace(data.redirect || '');
    } catch (_) {
      errEl.textContent = 'Network error. Please check your connection.';
      errEl.hidden = false;
      btn.disabled = false;
      btn.textContent = 'Sign In';
    }
  });

  // ── MFA verify step ───────────────────────────────────────────────────
  if (mfaBtn) {
    mfaBtn.addEventListener('click', async function () {
      if (mfaErr) mfaErr.hidden = true;
      mfaBtn.disabled = true;
      mfaBtn.textContent = 'Verifying\u2026';

      try {
        var res = await fetch('api/auth/mfa-verify', {
          method:      'POST',
          credentials: 'same-origin',
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ token: mfaCode ? mfaCode.value.trim() : '' }),
        });
        var data = await res.json().catch(function () { return {}; });

        if (res.ok) {
          location.replace(data.redirect || '');
        } else {
          if (mfaErr) { mfaErr.textContent = data.error || 'Verification failed.'; mfaErr.hidden = false; }
          mfaBtn.disabled = false;
          mfaBtn.textContent = 'Verify';
          if (mfaCode) { mfaCode.value = ''; mfaCode.focus(); }
        }
      } catch (_) {
        if (mfaErr) { mfaErr.textContent = 'Network error.'; mfaErr.hidden = false; }
        mfaBtn.disabled = false;
        mfaBtn.textContent = 'Verify';
      }
    });
  }

  // Allow Enter key in MFA input
  if (mfaCode) {
    mfaCode.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && mfaBtn) mfaBtn.click();
    });
  }

  if (mfaBack) {
    mfaBack.addEventListener('click', function () {
      // Clear the pending session then show login form
      fetch('api/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(function () {});
      showForm();
    });
  }

  // ── Enrollment confirm step ───────────────────────────────────────────
  if (enrollBtn) {
    enrollBtn.addEventListener('click', async function () {
      if (enrollErr) enrollErr.hidden = true;
      enrollBtn.disabled = true;
      enrollBtn.textContent = 'Confirming\u2026';

      try {
        var res = await fetch('api/auth/enroll-totp/confirm', {
          method:      'POST',
          credentials: 'same-origin',
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ token: enrollCode ? enrollCode.value.trim() : '' }),
        });
        var data = await res.json().catch(function () { return {}; });

        if (res.ok) {
          location.replace(data.redirect || '');
        } else {
          if (enrollErr) { enrollErr.textContent = data.error || 'Confirmation failed.'; enrollErr.hidden = false; }
          enrollBtn.disabled = false;
          enrollBtn.textContent = 'Confirm & Enable';
          if (enrollCode) { enrollCode.value = ''; enrollCode.focus(); }
        }
      } catch (_) {
        if (enrollErr) { enrollErr.textContent = 'Network error.'; enrollErr.hidden = false; }
        enrollBtn.disabled = false;
        enrollBtn.textContent = 'Confirm & Enable';
      }
    });
  }

  if (enrollCode) {
    enrollCode.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && enrollBtn) enrollBtn.click();
    });
  }

  if (enrollBack) {
    enrollBack.addEventListener('click', function () {
      fetch('api/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(function () {});
      showForm();
    });
  }

})();
