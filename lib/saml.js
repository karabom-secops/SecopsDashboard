'use strict';

const fs     = require('fs');
const { SAML } = require('@node-saml/node-saml');

let _saml = null;

/**
 * Loads the IdP certificate from SAML_CERT_FILE (path) or SAML_CERT (inline).
 * SAML_CERT_FILE takes precedence.
 */
function loadCert() {
  if (process.env.SAML_CERT_FILE) {
    return fs.readFileSync(process.env.SAML_CERT_FILE, 'utf8').trim();
  }
  return (process.env.SAML_CERT || '').replace(/\\n/g, '\n').trim();
}

function buildSaml() {
  const cert = loadCert();
  if (!cert) {
    throw new Error(
      'SAML idpCert is empty. Set SAML_CERT (inline PEM with \\n escapes) or SAML_CERT_FILE (path to PEM file).'
    );
  }
  return new SAML({
    idpCert: cert,
    entryPoint:           process.env.SAML_ENTRY_POINT,
    issuer:               process.env.SAML_ISSUER || 'secops-dashboard',
    callbackUrl:          process.env.SAML_CALLBACK_URL,
    validateInResponseTo: 'never',
    wantAssertionsSigned: true,
  });
}

function getSaml() {
  if (!_saml) _saml = buildSaml();
  return _saml;
}

/**
 * Returns true if SAML SSO is fully configured and enabled.
 */
function isSamlEnabled() {
  const hasCert = !!(process.env.SAML_CERT_FILE || process.env.SAML_CERT);
  return process.env.SAML_ENABLED === 'true' &&
         !!process.env.SAML_ENTRY_POINT &&
         hasCert &&
         !!process.env.SAML_CALLBACK_URL;
}

/**
 * Returns the IdP redirect URL for initiating an SSO login.
 * @returns {Promise<string>}
 */
async function getSamlLoginUrl() {
  return getSaml().getAuthorizeUrlAsync('', '', {});
}

/**
 * Validates a SAML POST response body and returns the user profile.
 * @param {Record<string,string>} body - Parsed POST body containing SAMLResponse
 * @returns {Promise<{profile: object, loggedOut: boolean}>}
 */
async function validateSamlResponse(body) {
  return getSaml().validatePostResponseAsync(body);
}

/**
 * Returns the SP metadata XML for Azure AD registration.
 * @returns {string}
 */
function getSamlMetadata() {
  return getSaml().generateServiceProviderMetadata(null, null);
}

module.exports = { isSamlEnabled, getSamlLoginUrl, validateSamlResponse, getSamlMetadata };
