'use strict';

/**
 * Client logos, and the browser-tab icon.
 *
 * A logo is the first thing in this product that takes a FILE from an operator
 * and serves it back to a browser, in the client's own portal. That makes the
 * upload allowlist and the serve headers security properties, not cosmetics.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   no scripts in an image      SVG is refused at the route, at the multer
 *                               filter and by a CHECK constraint; the stored
 *                               mime is echoed back with nosniff, never guessed
 *   one client, one logo        upload, read and delete all resolve the tenant
 *                               from the session (or a superadmin's explicit
 *                               tenantId) — never from the form or the path
 *   the portal cannot write     a client may read their own logo and nothing
 *                               else; logos are not in CLIENT_PORTAL_WRITES
 *   not migrated is not broken  every read is behind a degrade-open probe
 *   the list stays a list       /api/tenants carries a flag, not bytes
 *   every page has an icon      one file, linked from all five entry points
 *
 *   node tests/client-logo.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('client-logo');

function codeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
}
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

const srv       = read('server.js');
const srvCode   = codeOnly(srv);
const portalSrc = codeOnly(read('lib', 'portal-routes.js'));
const gateSrc   = codeOnly(read('lib', 'portal-gate.js'));
const sql       = read('db', 'migrate-tenant-logo.sql');
const profileJs = codeOnly(read('public', 'js', 'tab-client-profile.js'));
const bootJs    = codeOnly(read('public', 'portal', 'js', 'portal-boot.js'));
const authJs    = codeOnly(read('public', 'js', 'auth.js'));

/** One route handler's source, from its app.VERB line to the next one. */
function route(src, verb, routePath) {
  const start = src.indexOf(`app.${verb}('${routePath}'`);
  if (start < 0) return '';
  const next = src.indexOf('\napp.', start + 1);
  return src.slice(start, next < 0 ? src.length : next);
}

// ── An image is not a document ──────────────────────────────────────────────

section('an uploaded logo cannot carry a script');

const filter = srvCode.slice(srvCode.indexOf('const logoUpload = multer('),
  srvCode.indexOf('const rateLimit'));
check('the upload filter allows raster types only',
  /image\\\/\(png\|jpeg\|webp\)/.test(filter) || /\/\^image\\\/\(png\|jpeg\|webp\)\$\//.test(filter) ||
  /png\|jpeg\|webp/.test(filter));
check('and says nothing about SVG, which is the point',
  !/svg/i.test(filter), 'no svg in the filter');
/*
 * The VALUE, not the text. The first version matched the literal
 * `fileSize: 512 * 1024`, which is still a substring of `512 * 1024 * 100` —
 * so a hundredfold raise in the limit passed the test. A logo rides in a row
 * the portal reads on every page load; the cap is the point.
 */
const capExpr = (filter.match(/fileSize:\s*([0-9*\s]+?)\s*\}/) || [])[1];
const capBytes = capExpr && /^[0-9*\s]+$/.test(capExpr)
  ? capExpr.split('*').reduce((n, part) => n * Number(part.trim()), 1)
  : null;
check('the size is capped so a logo cannot be a payload',
  capBytes === 512 * 1024, capBytes === null ? 'no cap found' : Math.round(capBytes / 1024) + ' KB');

const post = route(srvCode, 'post', '/api/client-profile/logo');
check('the route checks the type again, not trusting the filter alone',
  /image\/\(png\|jpeg\|webp\)/.test(post) || /png\|jpeg\|webp/.test(post));
check('the database refuses anything else as well',
  /logo_mime IN \('image\/png', 'image\/jpeg', 'image\/webp'\)/.test(sql));
check('and refuses a half-stored logo',
  /tenants_logo_complete/.test(sql) &&
  /logo_mime IS NULL AND logo_data IS NULL/.test(sql));

check('the bytes are served as the STORED type, never a sniffed one',
  /res\.set\('Content-Type', row\.logo_mime\)/.test(srvCode) &&
  /X-Content-Type-Options', 'nosniff'/.test(srvCode));
check('and privately, because the image belongs to one client',
  /Cache-Control', 'private/.test(srvCode));
check('the migration explains why SVG is refused', /script-bearing/.test(sql));

// ── One client, one logo ────────────────────────────────────────────────────

section('a logo belongs to exactly one client');

['post', 'delete'].forEach((verb) => {
  const r = route(srvCode, verb, '/api/client-profile/logo');
  check(`the ${verb.toUpperCase()} resolves the tenant server-side`,
    /resolveProfileTenant\(req\)/.test(r) && /No tenant context/.test(r), verb);
  check(`and the ${verb.toUpperCase()} scopes its write by that tenant`,
    /WHERE id = \$\d/.test(r), verb);
});
const get = route(srvCode, 'get', '/api/client-profile/logo');
check('the staff read is scoped the same way',
  /resolveProfileTenant\(req\)/.test(get) && /loadTenantLogo\(tenantId\)/.test(get));
check('no logo route takes an id from the path or the body',
  !/params\.(tenantId|id)/.test(post + get + route(srvCode, 'delete', '/api/client-profile/logo')));

section('the portal shows the client their own logo and nothing else');

/*
 * Bounded by the NEXT route, not by a comment banner: portalSrc has had its
 * comments stripped, so slicing to '// ── Incidents' ran to the end of the file
 * and swept in every later route's legitimate use of req.query.
 */
const portalLogoStart = portalSrc.indexOf("app.get('/api/portal/logo'");
const portalLogo = portalSrc.slice(portalLogoStart,
  portalSrc.indexOf('app.get(', portalLogoStart + 10));
check('the portal route exists and is gated like every other portal route',
  /app\.get\('\/api\/portal\/logo', gate, portal\(/.test(portalSrc));
check('it reads the tenant the wrapper resolved, not a parameter',
  /WHERE id = \$1', \[tenantId\]/.test(portalLogo) && !/req\.query/.test(portalLogo));
check('it serves the stored type with nosniff, as the staff route does',
  /Content-Type', row\.logo_mime/.test(portalLogo) && /nosniff/.test(portalLogo));
check('a client with no logo gets a 404, not someone else\'s',
  /No logo set/.test(portalLogo) && /status\(404\)/.test(portalLogo));

check('uploading is NOT something the portal can do',
  !/logo/i.test(gateSrc.slice(gateSrc.indexOf('CLIENT_PORTAL_WRITES'),
    gateSrc.indexOf('CLIENT_PORTAL_WRITES') + 400)),
  'not in the portal write allowlist');
check('/me reports a flag, never a URL the caller could choose',
  /hasLogo,/.test(portalSrc) && !/logoUrl/.test(portalSrc));

// ── Not migrated is not broken ──────────────────────────────────────────────

section('a deployment without the migration shows no logo, not an error');

check('the columns are added if absent, so the migration re-runs safely',
  (sql.match(/ADD COLUMN IF NOT EXISTS/g) || []).length >= 5);
check('reads go through a degrade-open probe',
  /async function hasTenantLogoColumns\(\)/.test(srvCode) &&
  /catch \(_\) \{\s*return false;/.test(srvCode.slice(srvCode.indexOf('hasTenantLogoColumns'))));
check('the probe caches only a positive answer, so running the migration needs no restart',
  /_hasTenantLogo = true;/.test(srvCode) && !/_hasTenantLogo = false;\s*return false/.test(srvCode));
check('uploading before the migration says which migration to run',
  /Run db\/migrate-tenant-logo\.sql/.test(post));
check('deleting before the migration is a no-op, not a 500',
  /if \(!await hasTenantLogoColumns\(\)\) return res\.json\(\{ ok: true \}\)/.test(srvCode));
check('the portal /me survives a missing column',
  /catch \(_\) \{ hasLogo = false; \}/.test(portalSrc));

// ── The list stays a list ───────────────────────────────────────────────────

section('the tenant list carries a flag, not images');

const tenants = route(srvCode, 'get', '/api/tenants');
check('/api/tenants reports has_logo',
  /logo_mime IS NOT NULL\) AS has_logo/.test(tenants));
check('and never selects the bytes',
  !/logo_data/.test(tenants), 'no logo_data in the dropdown query');
check('it falls back to FALSE when the column is absent',
  /'FALSE AS has_logo'/.test(tenants));
check('the profile payload carries a flag too, not base64',
  /hasLogo,/.test(srvCode) && !/toString\('base64'\)/.test(
    srvCode.slice(srvCode.indexOf('async function buildClientProfile'),
      srvCode.indexOf('async function buildClientProfile') + 3000)));

// ── The screens ─────────────────────────────────────────────────────────────

section('the operator can see what they uploaded');

check('the Client Profile tab has an upload control',
  /cp-logo-file/.test(profileJs) && /accept="image\/png,image\/jpeg,image\/webp"/.test(profileJs));
check('it posts multipart to the logo route',
  /new FormData\(\)/.test(profileJs) && /client-profile\/logo/.test(profileJs));
check('it checks type and size before sending, so the common mistakes are named',
  /512 \* 1024/.test(profileJs) && /not a PNG, JPEG or WebP/.test(profileJs));
check('a read-only user cannot upload or remove',
  /canWriteProfile\(\)/.test(profileJs.slice(profileJs.indexOf('function logoBlock'))));
check('the preview is cache-busted, so a replacement is visibly a replacement',
  /v=' \+ Date\.now\(\)/.test(profileJs));

check('the portal header shows the client logo when there is one',
  /portalClientLogo/.test(bootJs) && /api\/portal\/logo/.test(bootJs));
check('and keeps ours beside it',
  /header-logo-svg" src="img\/reflex-logo\.png"/.test(read('public', 'portal.html')));
check('the staff switcher shows the selected client\'s logo',
  /globalTenantLogo/.test(authJs) && /client-profile\/logo/.test(authJs));
check('the switcher asks for one image, not one per client in the list',
  /hasLogo\[t\.id\] = !!t\.has_logo/.test(authJs));
check('and hides it if the image fails to load',
  /addEventListener\('error'/.test(authJs));

// ── The browser tab ─────────────────────────────────────────────────────────

section('every page has a browser-tab icon');

const PAGES = ['index.html', 'login.html', 'manager.html', 'portal.html', 'upload.html'];
const icons = PAGES.map(p => ({ p, src: read('public', p) }));
check('all five entry points link the icon',
  icons.every(x => /<link rel="icon" href="img\/favicon\.png"/.test(x.src)),
  icons.filter(x => !/rel="icon"/.test(x.src)).map(x => x.p).join(', ') || 'all five');
check('each links it exactly once, so there is one source of truth',
  icons.every(x => (x.src.match(/rel="icon"/g) || []).length === 1),
  icons.map(x => x.p + '=' + (x.src.match(/rel="icon"/g) || []).length).join(' '));
check('and uses it for the phone home screen too',
  icons.every(x => /rel="apple-touch-icon" href="img\/favicon\.png"/.test(x.src)));

/*
 * The icon IS the Reflex mark, generated from the one logo asset — not a
 * lookalike drawn by hand. A square, reasonably sized PNG: the stacked lockup
 * itself would be illegible in a 16px tab, which is why the mark is cropped out
 * of it rather than linked directly.
 */
const ico = fs.readFileSync(path.join(ROOT, 'public', 'img', 'favicon.png'));
check('the icon file exists and is a real PNG', ico.slice(1, 4).toString('ascii') === 'PNG');
const icoW = ico.readUInt32BE(16), icoH = ico.readUInt32BE(20);
check('it is square and big enough for a retina tab and a home screen',
  icoW === icoH && icoW >= 128, icoW + 'x' + icoH);
check('and the source lockup is still the only brand asset it comes from',
  fs.existsSync(path.join(ROOT, 'public', 'img', 'reflex-logo.png')));
check('the hand-drawn placeholder icon is gone',
  !fs.existsSync(path.join(ROOT, 'public', 'img', 'favicon.svg')), 'favicon.svg removed');
check('no page still points at the logo file that never existed',
  !icons.some(x => /src="img\/logo\.png"/.test(x.src)), 'img/logo.png');

done();
