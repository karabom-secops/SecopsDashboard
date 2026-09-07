'use strict';

/**
 * lib/fortigate-metadata.js — read the header comments before YAML sees them.
 *
 * ══ WHY THIS EXISTS ══
 *
 * A FortiGate export carries its identity in leading comment lines:
 *
 *   #config-version=FG10E1-7.4.11-FW-build2878-260126:opmode=0:vdom=1:user=ENTERPRISE-ENGINEERS
 *   #conf_file_ver=1234567890
 *   #buildno=2878
 *   #global_vdom=0:vd_name=RFX-OFFICE/RFX-OFFICE
 *
 * Every YAML parser discards comments — that is what a comment is. The audit
 * therefore looked for a `config-version` KEY in the parsed tree, never found
 * one, and reported "The firmware version could not be read from this config"
 * on a file that states its firmware on line one.
 *
 * That is the worst kind of finding: it names a real control (FortiOS version
 * currency is the highest-value check on a Fortinet device), reports it as
 * unknown, and the information was in the file all along.
 *
 * So the raw text is inspected BEFORE deserialisation. This module does that
 * and nothing else.
 *
 * ══ NOTHING IS INFERRED ══
 *
 * Every field is null unless the file said it. A version we could not parse is
 * reported as a parse WARNING carrying the raw line, never as "firmware is
 * absent" — the two send an analyst to entirely different places, and only one
 * of them is true.
 */

/** Only the leading comment block is metadata. Scan a bounded prefix. */
const MAX_HEADER_LINES = 60;

/**
 * Split `k=v:k=v:k=v` as FortiOS writes it in the config-version line.
 *
 * The FIRST segment has no `=` — it is the version token itself — so it is
 * returned separately rather than being dropped or mistaken for a key.
 */
function splitTagged(value) {
  const parts = String(value == null ? '' : value).split(':');
  const head = parts.shift();
  const tags = {};
  parts.forEach((p) => {
    const eq = p.indexOf('=');
    if (eq < 0) return;
    const k = p.slice(0, eq).trim().toLowerCase();
    const v = p.slice(eq + 1).trim();
    if (k) tags[k] = v;
  });
  return { head: (head || '').trim(), tags };
}

/**
 * Pull model, version and build out of a token like
 * `FG10E1-7.4.11-FW-build2878-260126`.
 *
 * Deliberately pattern-matched rather than split on '-' by position: the model
 * token contains no dashes on some platforms and several on others
 * (`FGT_VM64_KVM`), so counting fields from the left is how a version becomes
 * a model on the one device nobody tested against.
 *
 * The FULL token is always preserved. These are conveniences beside it, never
 * a replacement for it.
 */
function parseVersionToken(token) {
  const t = String(token == null ? '' : token).trim();
  const out = { raw: t || null, model: null, version: null, build: null };
  if (!t) return out;

  // Version: the first dotted numeric triple/pair in the token.
  const ver = t.match(/(\d+\.\d+(?:\.\d+)?)/);
  if (ver) out.version = ver[1];

  // Build: `build2878`, case-insensitive.
  const build = t.match(/build0*(\d+)/i);
  if (build) out.build = build[1];

  /*
   * Model: everything before the version. Where there is no recognisable
   * version the whole token is NOT assumed to be a model — an unparsed token
   * is left null and the caller warns, rather than putting a firmware string
   * in a field labelled "model".
   */
  if (ver && ver.index > 0) {
    const head = t.slice(0, ver.index).replace(/[-_\s]+$/, '');
    out.model = head || null;
  }

  return out;
}

/**
 * @returns {{
 *   raw: string[],            the header comment lines, verbatim
 *   configVersion: string|null,
 *   model: string|null,
 *   version: string|null,     FortiOS version, e.g. '7.4.11'
 *   build: string|null,
 *   confFileVer: string|null,
 *   opMode: string|null,
 *   vdomEnabled: boolean|null,
 *   currentVdom: string|null,
 *   globalVdom: string|null,
 *   exportUser: string|null,
 *   warnings: string[]
 * }}
 *
 * `vdomEnabled` is TRI-STATE. null means the header did not say — which is not
 * the same as "no VDOMs", and the layout detector must not treat it as such.
 */
function parseMetadata(text) {
  const out = {
    raw: [],
    configVersion: null,
    model: null,
    version: null,
    build: null,
    confFileVer: null,
    opMode: null,
    vdomEnabled: null,
    currentVdom: null,
    globalVdom: null,
    exportUser: null,
    warnings: [],
  };

  const lines = String(text == null ? '' : text).split(/\r?\n/);

  for (let i = 0; i < lines.length && i < MAX_HEADER_LINES; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '') continue;
    // The header block ends at the first line that is not a comment.
    if (trimmed[0] !== '#') break;

    out.raw.push(trimmed);

    const body = trimmed.replace(/^#+\s*/, '');
    const eq = body.indexOf('=');
    if (eq < 0) continue;

    const key = body.slice(0, eq).trim().toLowerCase();
    const value = body.slice(eq + 1).trim();

    if (key === 'config-version' || key === 'config_version') {
      const { head, tags } = splitTagged(value);
      out.configVersion = value || null;

      const v = parseVersionToken(head);
      out.model   = v.model;
      out.version = v.version;
      out.build   = v.build;

      if (!v.version) {
        // The raw line travels with the warning — that is the point. "Could not
        // parse" with nothing to look at is not actionable.
        out.warnings.push('The config-version header was present but no FortiOS ' +
          'version could be read from it: ' + trimmed);
      }

      if (tags.opmode !== undefined) out.opMode = tags.opmode;
      if (tags.vdom !== undefined) {
        // '1' means VDOMs are enabled. Anything unexpected stays null rather
        // than defaulting to "off", which would silently pick a layout.
        out.vdomEnabled = tags.vdom === '1' ? true : tags.vdom === '0' ? false : null;
        if (out.vdomEnabled === null) {
          out.warnings.push('The config-version header carried an unrecognised ' +
            'vdom flag (' + tags.vdom + '), so VDOM mode could not be determined: ' + trimmed);
        }
      }
      if (tags.user !== undefined) out.exportUser = tags.user || null;
      continue;
    }

    if (key === 'buildno' || key === 'build') {
      // Only fills a gap; the config-version token is the better source.
      if (!out.build) out.build = value.replace(/^0+/, '') || value || null;
      continue;
    }

    if (key === 'conf_file_ver' || key === 'conf-file-ver') {
      out.confFileVer = value || null;
      continue;
    }

    if (key === 'global_vdom' || key === 'global-vdom') {
      /*
       * `#global_vdom=0:vd_name=RFX-OFFICE/RFX-OFFICE`
       *
       * The leading digit is the global-VDOM indicator; vd_name carries the
       * VDOM this export belongs to, sometimes as `name/name`. Only the first
       * segment is taken, and the raw value is kept in `raw` regardless.
       */
      const { head, tags } = splitTagged(value);
      out.globalVdom = head || null;
      if (tags.vd_name) out.currentVdom = String(tags.vd_name).split('/')[0].trim() || null;
      continue;
    }
  }

  if (!out.raw.length) {
    out.warnings.push('No leading comment header was found, so firmware and VDOM ' +
      'details could not be read. This export may have been edited, or produced ' +
      'by a tool that strips comments.');
  } else if (!out.configVersion) {
    out.warnings.push('A comment header was present but carried no config-version ' +
      'line, so the firmware version is unknown.');
  }

  return out;
}

module.exports = {
  parseMetadata,
  parseVersionToken,
  splitTagged,
  MAX_HEADER_LINES,
};
