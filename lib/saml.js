'use strict';

const { SAML } = require('@node-saml/node-saml');

let _saml = null;

function buildSaml() {
  // Support both literal newlines and escaped \n in the env var
  const rawCert = (process.env.SAML_CERT || '').replace(/\\n/g, '\n').trim();
  return new SAML({
    entryPoint:           process.env.SAML_ENTRY_POINT,
    issuer:               process.env.SAML_ISSUER || 'secops-dashboard',
    callbackUrl:          process.env.SAML_CALLBACK_URL,
    cert:                 rawCert,
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
  return process.env.SAML_ENABLED === 'true' &&
         !!process.env.SAML_ENTRY_POINT &&
         !!process.env.SAML_CERT &&
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
