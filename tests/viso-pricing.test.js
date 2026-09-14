'use strict';

/**
 * vISO pricing — the second sub-tab of the Pricing page.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   the rate card adds up        each tier's advisory + platform is its list price
 *   the waiver counts honestly   3+ managed services, and MDR's included EDR,
 *                                NDR and Identity are not three extra services
 *   margin is derived            from the day cost and the platform cost on
 *                                screen, never quoted from a brochure
 *   the floor warns              and names the lever that caused it
 *   junk input cannot price      negatives, blanks and >100% discounts clamp
 *   the catalogue cannot drift   service keys and labels match lib/services.js
 *   grants survive the rename    the page key is still mdr-pricing
 *
 *   node tests/viso-pricing.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('viso-pricing');

const sandbox = { console };
sandbox.window = sandbox;
sandbox.document = { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [] };
vm.createContext(sandbox);
for (const f of ['tab-mdr-pricing.js', 'tab-viso-pricing.js', 'tab-pricing.js']) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'public', 'js', f), 'utf8'), sandbox, { filename: f });
}
const V = sandbox.VisoPricingTab;
const Shell = sandbox.PricingTab;

const servicesLib = require(path.join(ROOT, 'lib', 'services'));
const P = require(path.join(ROOT, 'lib', 'pages'));
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const appJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'app.js'), 'utf8');
const css = fs.readFileSync(path.join(ROOT, 'public', 'css', 'styles.css'), 'utf8');

const near = (a, b) => a !== null && Math.abs(a - b) < 0.01;
const card = V.DEFAULT_CARD;
const quote = (tierKey, over) => V.calculate(Object.assign({
  rate: card.rates[tierKey], services: [], discountPct: 0, termMonths: 12,
  dayCost: card.dayCost, platformCost: card.platformCost, gmFloorPct: card.gmFloor,
  fteAnnual: card.fteAnnual, waiverThreshold: card.waiverThreshold,
}, over || {}));

// ── The rate card ──────────────────────────────────────────────────────────

section('the rate card adds up to the proposed tiers');

check('the module loads', !!V && typeof V.calculate === 'function');
check('three tiers, in order', V.TIERS.map(t => t.key).join(',') === 'essential,standard,executive');

[['essential', 12500], ['standard', 28000], ['executive', 65000]].forEach(([k, list]) => {
  const r = quote(k);
  check(`${k} lists at R${list.toLocaleString('en-US')} a month`,
    r.listMonthly === list, r.advisoryMonthly + ' + ' + r.platformMonthly + ' = ' + r.listMonthly);
});

check('every tier says what it includes',
  V.TIERS.every(t => Array.isArray(t.includes) && t.includes.length >= 3));

/*
 * Platform running cost is NOT known, so it defaults to nothing rather than to
 * an invented figure — and the margin card has to say it is excluded.
 */
check('the platform running cost is left unset rather than invented',
  card.platformCost === 0);

// ── Pricing a quote ────────────────────────────────────────────────────────

section('a standard quote, no services attached');

const std = quote('standard');
check('the platform fee is charged', std.platformWaived === false && std.platformCharged === 6500);
check('final monthly is the list price', std.finalMonthly === 28000, std.finalMonthly);
check('annual value is twelve months', std.annualValue === 336000, std.annualValue);
check('delivery cost is days times day rate', std.labourMonthly === 9750, std.labourMonthly);
check('margin is derived from those inputs',
  near(std.grossMarginPct, (28000 - 9750) / 28000 * 100), std.grossMarginPct.toFixed(2) + '%');
check('and it clears the floor', std.belowFloor === false);
check('the in-house ISO comparison is computed',
  near(std.fteSharePct, 336000 / 1500000 * 100), std.fteSharePct.toFixed(1) + '%');

section('the platform waiver');

check('two services are not enough',
  quote('standard', { services: ['mdr', 'vuln'] }).platformWaived === false);

const waived = quote('standard', { services: ['mdr', 'vuln', 'awareness'] });
check('three are', waived.platformWaived === true && waived.finalMonthly === 21500, waived.finalMonthly);
check('the list price still shows what was given away', waived.listMonthly === 28000);

/*
 * MDR delivers EDR, NDR and Identity. A client on MDR is buying one service,
 * not four, and must not have the platform fee waived for it.
 */
const mdrBundle = quote('standard', { services: ['mdr', 'edr', 'ndr', 'identity'] });
check('MDR plus its included services counts once, not four times',
  mdrBundle.attachedCount === 1 && mdrBundle.platformWaived === false,
  mdrBundle.attached.join(','));
check('but EDR bought without MDR does count',
  quote('standard', { services: ['edr', 'vuln', 'email'] }).platformWaived === true);
check('unknown and repeated service keys are ignored',
  quote('standard', { services: ['mdr', 'mdr', 'viso', 'nonsense'] }).attachedCount === 1);
check('a blank waiver threshold does not waive the fee for everyone',
  quote('standard', { waiverThreshold: '', services: ['mdr'] }).platformWaived === false);

/*
 * THE TRADE-OFF THE FLOOR EXISTS FOR. The waiver removes revenue without
 * removing cost, so a waived fee plus a modest discount is exactly what takes
 * Standard under 50%.
 */
section('the margin floor');

check('waiving the fee alone keeps Standard above the floor',
  waived.belowFloor === false, waived.grossMarginPct.toFixed(1) + '%');
const squeezed = quote('standard', { services: ['mdr', 'vuln', 'awareness'], discountPct: 10 });
check('a 10% discount on top of the waiver breaches it',
  squeezed.belowFloor === true && near(squeezed.grossMarginPct, (19350 - 9750) / 19350 * 100),
  squeezed.grossMarginPct.toFixed(1) + '%');

const warnHtml = V.summaryHtml(squeezed, V.TIERS[1]);
check('the summary marks the margin card', /visop-warn/.test(warnHtml));
check('and names the levers actually available on this quote',
  /reduce the discount/i.test(warnHtml) && /charge the platform fee/i.test(warnHtml) &&
  /next tier up/i.test(warnHtml), (warnHtml.match(/visop-alert[^<]*/) || [''])[0]);
check('an executive quote is not told to go up a tier',
  !/next tier up/i.test(V.summaryHtml(
    quote('executive', { discountPct: 60 }), V.TIERS[2])));
check('a clean quote raises no alert', !/visop-alert/.test(V.summaryHtml(std, V.TIERS[1])));
check('the margin is flagged as excluding platform cost while that is unset',
  /excludes platform running cost/.test(V.summaryHtml(std, V.TIERS[1])));
check('and not once it is set',
  !/excludes platform running cost/.test(V.summaryHtml(quote('standard', { platformCost: 1500 }), V.TIERS[1])));

// ── Junk input ─────────────────────────────────────────────────────────────

section('junk input cannot produce a price');

const free = quote('standard', { discountPct: 250 });
check('a discount above 100% is clamped to 100', free.discountPct === 100 && free.finalMonthly === 0);
check('no revenue has no margin percentage', free.grossMarginPct === null);
check('but is still flagged, because delivery still costs money', free.belowFloor === true);
check('negative rates and costs clamp to zero',
  quote('standard', { rate: { advisory: -5000, platform: -1, days: -2 }, dayCost: -100 }).finalMonthly === 0);
check('string inputs from form fields are read as numbers',
  quote('standard', { discountPct: '10', termMonths: '24' }).contractValue === 28000 * 0.9 * 24);
check('a blank term is a twelve-month contract', quote('standard', { termMonths: '' }).termMonths === 12);
check('no in-house ISO cost means no comparison, not a division by zero',
  quote('standard', { fteAnnual: 0 }).fteSharePct === null);

section('a stored rate card loads safely');

const merged = V.mergeCard({ dayCost: 'abc', rates: { standard: { advisory: 30000, days: '' } } });
check('a malformed stored value falls back to the default', merged.dayCost === card.dayCost);
check('a valid stored rate is kept', merged.rates.standard.advisory === 30000);
check('a blank stored rate falls back rather than becoming zero',
  merged.rates.standard.days === card.rates.standard.days);
check('fields saved before they existed still get defaults',
  V.mergeCard({}).waiverThreshold === card.waiverThreshold);

// ── The catalogue ──────────────────────────────────────────────────────────

section('the service list matches lib/services.js');

/*
 * lib/services.js is server-side and cannot be loaded in the browser, so the
 * list is repeated here. This is what stops the two drifting apart: a service
 * renamed or added in the catalogue fails this check until the calculator
 * follows.
 */
const catalogue = servicesLib.SERVICES.filter(s => s.key !== 'viso');
check('the same services, in the same order',
  V.SERVICES.map(s => s.key).join(',') === catalogue.map(s => s.key).join(','),
  V.SERVICES.map(s => s.key).join(','));
check('with the same labels',
  V.SERVICES.every((s, i) => catalogue[i] && s.label === catalogue[i].label));
check('and the same MDR inclusions',
  V.SERVICES.filter(s => s.includedIn === 'mdr').map(s => s.key).sort().join(',') ===
  servicesLib.SERVICE_INCLUDES.mdr.slice().sort().join(','));

// ── The page ───────────────────────────────────────────────────────────────

section('the Pricing page has an MDR and a vISO sub-tab');

check('the shell defines both sub-tabs',
  !!Shell && Shell.SUBTABS.map(t => t.key).join(',') === 'mdr,viso');
check('the sub-tab bar is in the page', /id="pricingSubtabs"/.test(indexHtml));
check('the MDR calculator sits in its own pane', /id="pricingPane-mdr"/.test(indexHtml));
check('the vISO pane is in the page', /id="pricingPane-viso"/.test(indexHtml));
check('the MDR pane still holds the MDR form',
  indexHtml.indexOf('id="pricingPane-mdr"') < indexHtml.indexOf('id="mdrp-form"') &&
  indexHtml.indexOf('id="mdrp-form"') < indexHtml.indexOf('id="pricingPane-viso"'));
check('all three scripts are loaded',
  ['tab-mdr-pricing.js', 'tab-viso-pricing.js', 'tab-pricing.js']
    .every(f => indexHtml.indexOf(`<script src="js/${f}"></script>`) >= 0));
check('opening the page renders through the shell',
  /target === 'mdr-pricing'[\s\S]{0,120}PricingTab\.loadAndRender\(\)/.test(appJs));
check('the sub-tabs share the Admin sub-tab styling', /\.pricing-subtab\b/.test(css));

section('the rename does not revoke anyone\'s access');

/*
 * Per-user page grants are stored against the page KEY. Renaming the key to
 * "pricing" would have looked tidier and silently removed the page from every
 * user who had it. Only the label moved.
 */
const page = P.PAGES.find(p => p.key === 'mdr-pricing');
check('the page key is unchanged', !!page, page && page.key);
check('its label is now Pricing', page && page.label === 'Pricing', page && page.label);
check('the panel id is unchanged', /<section id="tab-mdr-pricing"/.test(indexHtml));
check('the nav reads Pricing', /data-tab="mdr-pricing"[\s\S]{0,400}side-nav-text">Pricing</.test(indexHtml));
check('a client role still cannot see pricing',
  ['read', 'write'].indexOf(P.ROLE_DEFAULTS.client['mdr-pricing']) < 0,
  P.ROLE_DEFAULTS.client['mdr-pricing']);

done();
