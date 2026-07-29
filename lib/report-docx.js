'use strict';

/**
 * Builds the Reflex penetration test report as a Word (.docx) document.
 *
 * Structure mirrors the house template (see "ReflexGO Web Application Penetration
 * Test Report"): cover, TOC, sections 1-9, then Appendix A (scope), Appendix B
 * (per-finding detail) and Appendix C (static CVSS classification criteria).
 *
 * Narrative prose comes from redteam_report_meta; the risk table, finding counts
 * and Appendix B come from pentest_findings + pentest_finding_evidence.
 */

const {
  AlignmentType, BorderStyle, Document, Footer, Header, HeadingLevel, ImageRun,
  PageBreak, PageNumber, Packer, Paragraph, ShadingType, Table, TableCell,
  TableOfContents, TableRow, TextRun, VerticalAlign, WidthType,
} = require('docx');

// ── Palette ───────────────────────────────────────────────────────────────────
// Matches PALETTE in public/js/report-shell.js so the Word report and the HTML
// print reports stay visually consistent.
const BLUE  = '1077C7';
const NAVY  = '12294A';
const INK   = '262626';
const MUTED = '595959';
const FOOT  = '7F7F7F';
const RULE  = 'D9D9D9';

const SEVERITY_FILL = {
  critical:      '7030A0',
  high:          'FF0000',
  medium:        'FFC000',
  low:           '00B0F0',
  informational: '92D050',
};
const SEVERITY_LABEL = {
  critical: 'Critical', high: 'High', medium: 'Medium',
  low: 'Low', informational: 'Informational',
};
// Descending, i.e. report order and the order counts are announced in.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

const CONTENT_WIDTH_PX = 600;   // ~6.25in of usable body width at 96dpi
const NO_BORDER = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };

// ── Small helpers ─────────────────────────────────────────────────────────────

const NUMBER_WORDS = [
  'zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine',
  'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen',
  'seventeen', 'eighteen', 'nineteen', 'twenty',
];

/** "three (3)" — falls back to the bare numeral past twenty. */
function spellCount(n) {
  const word = NUMBER_WORDS[n];
  return word ? `${word} (${n})` : `${n}`;
}

function capitalise(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}

function str(v) {
  return v == null ? '' : String(v);
}

/** Report reference code: 1 -> "001". */
function refCode(index) {
  return String(index + 1).padStart(3, '0');
}

function fmtDate(value) {
  if (!value) return '';
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return str(value);
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July',
    'August', 'September', 'October', 'November', 'December'];
  return `${String(d.getUTCDate()).padStart(2, '0')} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

/** CVSS scores print with one decimal ("8.6", "0.0"); blank when unscored. */
function fmtScore(v) {
  if (v === null || v === undefined || v === '') return '';
  const n = Number(v);
  return isNaN(n) ? '' : n.toFixed(1);
}

// ── Paragraph builders ────────────────────────────────────────────────────────

function body(text, opts = {}) {
  return new Paragraph({
    spacing: { after: opts.after == null ? 160 : opts.after, line: 276 },
    alignment: opts.alignment,
    children: [new TextRun({
      text: str(text),
      size: opts.size || 22,
      bold: opts.bold,
      italics: opts.italics,
      color: opts.color || INK,
    })],
  });
}

function bullet(text) {
  return new Paragraph({
    bullet: { level: 0 },
    spacing: { after: 80, line: 276 },
    children: [new TextRun({ text: str(text), size: 22, color: INK })],
  });
}

/** A blank spacer paragraph. */
function gap(after = 120) {
  return new Paragraph({ spacing: { after }, children: [] });
}

function sectionHeading(number, title) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 320, after: 180 },
    children: [new TextRun({
      text: number ? `${number}.\t${title.toUpperCase()}` : title.toUpperCase(),
      bold: true, size: 26, color: BLUE,
    })],
  });
}

function subHeading(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 140 },
    children: [new TextRun({ text: str(text), bold: true, size: 24, color: BLUE })],
  });
}

/** Bold inline label used for "Business Impact:", "Remediation steps to be taken:" etc. */
function label(text) {
  return new Paragraph({
    spacing: { before: 200, after: 100 },
    children: [new TextRun({ text: str(text), bold: true, size: 22, color: INK })],
  });
}

/**
 * Renders a plain-text field the way consultants actually type it:
 * blank lines separate paragraphs, and lines opening with -, * or a bullet glyph
 * become list items. Keeps the authoring UI as ordinary textareas.
 */
function prose(text) {
  const out = [];
  const lines = str(text).replace(/\r\n/g, '\n').split('\n');
  let buffer = [];

  const flush = () => {
    if (buffer.length) {
      out.push(body(buffer.join(' ').trim()));
      buffer = [];
    }
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) { flush(); continue; }
    if (/^[-*•·]\s+/.test(line)) {
      flush();
      out.push(bullet(line.replace(/^[-*•·]\s+/, '')));
    } else {
      buffer.push(line);
    }
  }
  flush();
  return out;
}

/** Same as prose(), but a field that is entirely non-bulleted still reads as bullets. */
function proseAsBullets(text) {
  const lines = str(text).replace(/\r\n/g, '\n').split('\n')
    .map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  const anyBulleted = lines.some((l) => /^[-*•·]\s+/.test(l));
  if (anyBulleted) return prose(text);
  return lines.map((l) => bullet(l));
}

// ── Table builders ────────────────────────────────────────────────────────────

function cellText(text, opts = {}) {
  return new Paragraph({
    alignment: opts.alignment || AlignmentType.LEFT,
    spacing: { before: 60, after: 60 },
    children: [new TextRun({
      text: str(text),
      bold: opts.bold,
      size: opts.size || 20,
      color: opts.color || INK,
    })],
  });
}

function cell(text, opts = {}) {
  return new TableCell({
    shading: opts.fill
      ? { type: ShadingType.CLEAR, color: 'auto', fill: opts.fill }
      : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 60, bottom: 60, left: 120, right: 120 },
    width: opts.width ? { size: opts.width, type: WidthType.PERCENTAGE } : undefined,
    children: [cellText(text, opts)],
  });
}

function headerRow(labels, widths) {
  return new TableRow({
    tableHeader: true,
    children: labels.map((l, i) => cell(l, {
      fill: BLUE, bold: true, color: 'FFFFFF',
      alignment: AlignmentType.CENTER,
      width: widths && widths[i],
    })),
  });
}

function table(rows) {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows,
  });
}

// ── Cover, header, footer ─────────────────────────────────────────────────────

function logoParagraph(logo, opts = {}) {
  if (!logo) return null;
  return new Paragraph({
    alignment: opts.alignment || AlignmentType.RIGHT,
    spacing: { after: opts.after == null ? 100 : opts.after },
    children: [new ImageRun({
      data: logo,
      type: 'png',
      transformation: { width: opts.width || 90, height: opts.height || 42 },
    })],
  });
}

function buildCover({ title, subtitle, dateText, logo }) {
  const kids = [];
  const logoPara = logoParagraph(logo, { alignment: AlignmentType.LEFT, width: 150, height: 70, after: 600 });
  if (logoPara) kids.push(logoPara);

  kids.push(gap(2400));
  kids.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 200 },
    children: [new TextRun({ text: str(title), bold: true, size: 56, color: BLUE })],
  }));
  kids.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 160 },
    children: [new TextRun({ text: str(subtitle), size: 32, color: NAVY })],
  }));
  kids.push(gap(2400));
  kids.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 60 },
    children: [new TextRun({ text: str(dateText), size: 22, color: MUTED })],
  }));
  kids.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: 'Prepared by Reflex', bold: true, size: 22, color: NAVY })],
  }));
  return kids;
}

function buildHeader({ title, subtitle, logo }) {
  const left = new TableCell({
    borders: { top: NO_BORDER, bottom: NO_BORDER, left: NO_BORDER, right: NO_BORDER },
    width: { size: 70, type: WidthType.PERCENTAGE },
    children: [new Paragraph({
      spacing: { after: 0 },
      children: [
        new TextRun({ text: str(title), bold: true, size: 20, color: BLUE }),
        new TextRun({ text: ` | ${str(subtitle)}`, size: 20, color: BLUE }),
      ],
    })],
  });
  const right = new TableCell({
    borders: { top: NO_BORDER, bottom: NO_BORDER, left: NO_BORDER, right: NO_BORDER },
    width: { size: 30, type: WidthType.PERCENTAGE },
    children: [logoParagraph(logo) || new Paragraph({ children: [] })],
  });

  return new Header({
    children: [
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        borders: {
          top: NO_BORDER, bottom: NO_BORDER, left: NO_BORDER, right: NO_BORDER,
          insideHorizontal: NO_BORDER, insideVertical: NO_BORDER,
        },
        rows: [new TableRow({ children: [left, right] })],
      }),
      gap(80),
    ],
  });
}

function buildFooter({ client }) {
  const confidential = `Reflex Solutions (Pty) Ltd © | ${client || 'Client'}: Confidential`;
  return new Footer({
    children: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 120, after: 40 },
        border: { top: { style: BorderStyle.SINGLE, size: 4, color: RULE, space: 6 } },
        children: [new TextRun({ text: confidential, size: 16, color: FOOT })],
      }),
      new Paragraph({
        alignment: AlignmentType.RIGHT,
        children: [
          new TextRun({ text: 'Pg ', size: 16, bold: true, color: BLUE }),
          new TextRun({ children: [PageNumber.CURRENT], size: 16, bold: true, color: BLUE }),
        ],
      }),
    ],
  });
}

// ── Section 4: business risk table ────────────────────────────────────────────

function severityCounts(findings) {
  const counts = {};
  for (const key of SEVERITY_ORDER) counts[key] = 0;
  for (const f of findings) {
    const key = SEVERITY_ORDER.includes(f.severity) ? f.severity : 'medium';
    counts[key] += 1;
  }
  return counts;
}

/** "Eight (8) security weaknesses were identified: two (2) rated high, ..." */
function riskLeadSentence(findings) {
  const total = findings.length;
  if (!total) return 'No security weaknesses were identified during the assessment.';

  const counts = severityCounts(findings);
  const parts = SEVERITY_ORDER
    .filter((k) => counts[k] > 0)
    .map((k) => `${spellCount(counts[k])} rated ${SEVERITY_LABEL[k].toLowerCase()}`);

  const noun = total === 1 ? 'security weakness was' : 'security weaknesses were';
  return `${capitalise(spellCount(total))} ${noun} identified: ${parts.join(', ')}.`;
}

function buildRiskTable(findings) {
  const rows = [headerRow(['Reference', 'Description', 'CVSS', 'Vulnerability Rating'], [14, 54, 12, 20])];

  findings.forEach((f, i) => {
    const sev = SEVERITY_ORDER.includes(f.severity) ? f.severity : 'medium';
    rows.push(new TableRow({
      children: [
        cell(refCode(i), { bold: true, alignment: AlignmentType.CENTER }),
        cell(f.title, { alignment: AlignmentType.CENTER }),
        cell(fmtScore(f.cvss_score) || '—', { alignment: AlignmentType.CENTER }),
        cell(SEVERITY_LABEL[sev], {
          fill: SEVERITY_FILL[sev], bold: true,
          // Only the dark fills (purple/red) take white text; the rest stay dark.
          color: sev === 'critical' || sev === 'high' ? 'FFFFFF' : INK,
          alignment: AlignmentType.CENTER,
        }),
      ],
    }));
  });

  return table(rows);
}

// ── Section 6: OWASP results table ────────────────────────────────────────────

const DEFAULT_OWASP = [
  { id: 'A01:2021', title: 'Broken Access Control', result: 'Pass' },
  { id: 'A02:2021', title: 'Cryptographic Failures', result: 'Pass' },
  { id: 'A03:2021', title: 'Injection', result: 'Pass' },
  { id: 'A04:2021', title: 'Insecure Design', result: 'Pass' },
  { id: 'A05:2021', title: 'Security Misconfiguration', result: 'Pass' },
  { id: 'A06:2021', title: 'Vulnerable and Outdated Components', result: 'Pass' },
  { id: 'A07:2021', title: 'Identification and Authentication Failures', result: 'Pass' },
  { id: 'A08:2021', title: 'Software and Data Integrity Failures', result: 'Pass' },
  { id: 'A09:2021', title: 'Security Logging and Monitoring Failures', result: 'Pass' },
  { id: 'A10:2021', title: 'Server-Side Request Forgery (SSRF)', result: 'Pass' },
];

function buildOwaspTable(results) {
  const list = Array.isArray(results) && results.length ? results : DEFAULT_OWASP;
  const rows = [headerRow(['OWASP Top 10 Web Application Security Risks', 'Result'], [78, 22])];

  for (const r of list) {
    const pass = String(r.result || 'Pass').toLowerCase() === 'pass';
    rows.push(new TableRow({
      children: [
        cell(`${str(r.id)} – ${str(r.title)}`.replace(/^ – /, '')),
        cell(pass ? 'Pass' : 'Issues Identified', {
          bold: true,
          color: pass ? '2E9E5B' : 'C00000',
          alignment: AlignmentType.CENTER,
        }),
      ],
    }));
  }
  return table(rows);
}

// ── Appendix B: findings ──────────────────────────────────────────────────────

/** Centred metadata block that sits under each finding heading. */
function findingMeta(finding) {
  const out = [];
  const endpoints = str(finding.affected_endpoints).split('\n')
    .map((s) => s.trim()).filter(Boolean);

  if (endpoints.length) {
    out.push(body('Affected Endpoints:', { bold: true, alignment: AlignmentType.CENTER, after: 40 }));
    for (const e of endpoints) {
      out.push(body(e, { alignment: AlignmentType.CENTER, after: 40, color: BLUE }));
    }
  }

  if (finding.cvss_vector) {
    out.push(body(finding.cvss_vector, { bold: true, alignment: AlignmentType.CENTER, after: 40 }));
  }

  const score = fmtScore(finding.cvss_score);
  if (score) {
    out.push(new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 40 },
      children: [
        new TextRun({ text: 'Score: ', bold: true, size: 22, color: INK }),
        new TextRun({ text: score, size: 22, color: INK }),
      ],
    }));
  }

  const sev = SEVERITY_ORDER.includes(finding.severity) ? finding.severity : 'medium';
  const classification = finding.classification || SEVERITY_LABEL[sev];
  out.push(new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 200 },
    children: [
      new TextRun({ text: 'Classification: ', bold: true, size: 22, color: INK }),
      new TextRun({ text: str(classification), size: 22, color: INK }),
    ],
  }));

  return out;
}

/**
 * Reads intrinsic pixel dimensions straight from a PNG or JPEG header, so
 * evidence keeps its aspect ratio in the document. Returns nulls if the header
 * cannot be read — evidenceImage() then falls back to a default box.
 */
function imageDimensions(buf, mime) {
  try {
    if (/png/i.test(mime)) {
      return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
    }
    // JPEG: walk the marker segments to the first Start-Of-Frame.
    let i = 2;
    while (i < buf.length - 9) {
      if (buf[i] !== 0xFF) { i += 1; continue; }
      const marker = buf[i + 1];
      // Standalone markers carry no length payload.
      if (marker === 0xD8 || marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { i += 2; continue; }
      const len = buf.readUInt16BE(i + 2);
      // SOF0-SOF15, excluding DHT (C4), JPG (C8) and DAC (CC), which are not frames.
      if (marker >= 0xC0 && marker <= 0xCF && marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC) {
        return { height: buf.readUInt16BE(i + 5), width: buf.readUInt16BE(i + 7) };
      }
      if (len < 2) break;
      i += 2 + len;
    }
  } catch (_) { /* fall through */ }
  return { width: null, height: null };
}

/** Scales an evidence image to the content width, preserving aspect ratio. */
function evidenceImage(ev) {
  const w = Number(ev.width_px) || CONTENT_WIDTH_PX;
  const h = Number(ev.height_px) || Math.round(CONTENT_WIDTH_PX * 0.5);
  const scale = w > CONTENT_WIDTH_PX ? CONTENT_WIDTH_PX / w : 1;

  const out = [new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 60 },
    children: [new ImageRun({
      data: ev.data,
      type: /jpe?g/i.test(ev.mime) ? 'jpg' : 'png',
      transformation: { width: Math.round(w * scale), height: Math.round(h * scale) },
    })],
  })];

  if (ev.caption) {
    out.push(body(ev.caption, {
      alignment: AlignmentType.CENTER, italics: true, size: 18, color: MUTED, after: 160,
    }));
  }
  return out;
}

function buildFinding(finding, index, evidence) {
  const kids = [];

  kids.push(new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 180 },
    children: [new TextRun({
      text: `${refCode(index)} - ${str(finding.title)}`,
      bold: true, size: 24, color: BLUE, underline: {},
    })],
  }));

  kids.push(...findingMeta(finding));
  kids.push(...prose(finding.description));

  if (str(finding.business_impact).trim()) {
    kids.push(label('Business Impact:'));
    kids.push(...proseAsBullets(finding.business_impact));
  }

  kids.push(label('Screenshot/Evidence:'));
  if (evidence && evidence.length) {
    for (const ev of evidence) kids.push(...evidenceImage(ev));
  } else {
    kids.push(body('No evidence captured for this finding.', { italics: true, color: MUTED }));
  }

  if (str(finding.recommendation).trim()) {
    kids.push(label('Remediation steps to be taken:'));
    kids.push(...proseAsBullets(finding.recommendation));
  }

  return kids;
}

// ── Appendix C: static classification criteria ────────────────────────────────

function twoColTable(headers, rows, widths) {
  const trs = [headerRow(headers, widths)];
  for (const r of rows) {
    trs.push(new TableRow({
      children: r.map((c, i) => cell(c, { bold: i === 0, width: widths && widths[i] })),
    }));
  }
  return table(trs);
}

function buildAppendixC() {
  const kids = [];

  kids.push(sectionHeading(null, 'Appendix C: Findings Classification Criteria'));
  kids.push(body(
    'Reflex has aligned its risk ratings with the Common Vulnerability Scoring System (CVSS). '
    + 'CVSS is an open framework for communicating the characteristics and severity of software '
    + 'vulnerabilities. CVSS consists of three metric groups: Base, Temporal, and Environmental. '
    + 'The Base metrics produce a score ranging from 0 to 10, which can then be refined by scoring '
    + 'the Temporal and Environmental metrics to more accurately reflect the relative severity posed '
    + 'by a vulnerability to the environment at the time of the assessment. For the purposes of the '
    + 'risk ratings in this report, the Temporal score is used.'
  ));
  kids.push(body(
    'CVSS is well suited as a standard measurement system for organisations that need accurate and '
    + 'consistent vulnerability severity scores. Two common uses of CVSS are calculating the severity '
    + 'of vulnerabilities discovered on systems and as a factor in prioritisation of vulnerability '
    + 'remediation activities.'
  ));

  kids.push(subHeading('Base Metrics'));

  kids.push(body('Attack Vector', { bold: true, after: 100 }));
  kids.push(body(
    'This metric reflects the context by which vulnerability exploitation was possible. The Base Score '
    + 'is larger the more remote an attacker can be to exploit the vulnerable component.'
  ));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Network', 'The target can be accessed from any network.'],
    ['Adjacent', 'The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology.'],
    ['Local', "The vulnerable component is not bound to the network stack, and the attacker's path is via read/write/execute capabilities."],
    ['Physical', 'Full compromise of a single system/application/component allowing full read/write access.'],
  ], [22, 78]));
  kids.push(gap(200));

  kids.push(body('Attack Complexity', { bold: true, after: 100 }));
  kids.push(body(
    "This metric describes the conditions beyond the attacker's control that must exist to exploit the "
    + 'vulnerability. The Base Score is greatest for the least complex attacks.'
  ));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Low', 'Specialised access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success when attacking the vulnerable component.'],
    ['High', "A successful attack depends on conditions beyond the attacker's control, requiring measurable effort in preparation or execution before success can be expected."],
  ], [22, 78]));
  kids.push(gap(200));

  kids.push(body('User Interaction', { bold: true, after: 100 }));
  kids.push(body(
    'This metric captures the requirement for a human user, other than the attacker, to participate in '
    + 'the successful compromise of the vulnerable component. The Base Score is greatest when no user '
    + 'interaction is required.'
  ));
  kids.push(twoColTable(['Option', 'Description'], [
    ['None', 'The vulnerable system can be exploited without interaction from any user.'],
    ['Required', 'Successful exploitation requires a user to take some action before the vulnerability can be exploited.'],
  ], [22, 78]));
  kids.push(gap(200));

  kids.push(body('Scope', { bold: true, after: 100 }));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Unchanged', 'An exploited vulnerability can only affect resources managed by the same security authority.'],
    ['Changed', 'An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component.'],
  ], [22, 78]));
  kids.push(gap(200));

  kids.push(body('Impact', { bold: true, after: 100 }));
  kids.push(body(
    'The impact of a vulnerability considers the potential effect on the business, should a vulnerability '
    + 'be exploited. Each impacted data set is compared against the CIA triad to view what kind of impact '
    + 'an exploit would have (high, low, or none).'
  ));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Confidentiality', 'Only those who are authorised have access to specific data sets, and those who are unauthorised are actively prevented from obtaining access.'],
    ['Integrity', 'Ensuring that data has not been tampered with and can be deemed trustworthy.'],
    ['Availability', 'Networks, systems, and applications are up and running, ensuring users have reliable access to resources when they are needed.'],
  ], [22, 78]));

  kids.push(subHeading('Temporal Metrics'));

  kids.push(body('Exploit Code Maturity', { bold: true, after: 100 }));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Not Defined', 'There is insufficient information available to choose an appropriate option.'],
    ['High', 'Reliable, widely available, and easy-to-use automated tools are available to exploit the vulnerability.'],
    ['Functional', 'Functional exploit code is available. The code works in most situations where the vulnerability exists.'],
    ['Proof-of-Concept', 'The code or technique is not functional in all situations and may require substantial modification by a skilled attacker.'],
    ['Unproven', 'No exploit code is available, or an exploit is theoretical.'],
  ], [22, 78]));
  kids.push(gap(200));

  kids.push(body('Remediation Level', { bold: true, after: 100 }));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Not Defined', 'There is insufficient information available to choose an appropriate option.'],
    ['Unavailable', 'There is either no solution available, or it is impossible to apply.'],
    ['Workaround', 'There is an unofficial, non-vendor solution available.'],
    ['Temporary Fix', 'There is an official but temporary fix available, such as a vendor hotfix or tool.'],
    ['Official Fix', 'A complete vendor solution is available. Either the vendor has issued an official patch, or an upgrade is available.'],
  ], [22, 78]));
  kids.push(gap(200));

  kids.push(body('Report Confidence', { bold: true, after: 100 }));
  kids.push(twoColTable(['Option', 'Description'], [
    ['Not Defined', 'There is insufficient information available to choose an appropriate option.'],
    ['Confirmed', 'Detailed reports exist, or functional reproduction is possible.'],
    ['Reasonable', 'Significant details are published, but researchers do not have full confidence in the root cause, or lack source code access to fully confirm all interactions.'],
    ['Unknown', 'A vulnerability is present, but the exact nature of the vulnerability is unknown.'],
  ], [22, 78]));

  kids.push(subHeading('Qualitative Severity Rating Scale'));
  kids.push(body('The Base and Temporal scores can be mapped to qualitative ratings as defined below.'));

  const scale = [
    ['9.0 - 10.0', 'Critical', SEVERITY_FILL.critical, 'FFFFFF'],
    ['7.0 – 8.9', 'High', SEVERITY_FILL.high, 'FFFFFF'],
    ['4.0 – 6.9', 'Medium', SEVERITY_FILL.medium, INK],
    ['0.1 - 3.9', 'Low', SEVERITY_FILL.low, INK],
    ['0.0', 'None / Informational', SEVERITY_FILL.informational, INK],
  ];
  const scaleRows = [headerRow(['Range Rating', 'Risk Rating'], [40, 60])];
  for (const [range, rating, fill, color] of scale) {
    scaleRows.push(new TableRow({
      children: [
        cell(range, { fill, color, bold: true, alignment: AlignmentType.CENTER }),
        cell(rating, { bold: true, alignment: AlignmentType.CENTER }),
      ],
    }));
  }
  kids.push(table(scaleRows));

  return kids;
}

// ── Document assembly ─────────────────────────────────────────────────────────

/**
 * @param {object}  opts
 * @param {object}  opts.project    redteam_projects row
 * @param {object}  opts.meta       redteam_report_meta row (or defaults)
 * @param {Array}   opts.findings   pentest_findings rows, already in report order
 * @param {object}  opts.evidenceByFinding  { [findingId]: evidenceRow[] }
 * @param {Buffer=} opts.logoBuffer public/img/reflex-logo.png
 * @returns {Promise<Buffer>}
 */
async function buildPentestReport({ project, meta, findings, evidenceByFinding, logoBuffer }) {
  const m = meta || {};
  const list = findings || [];
  const evidence = evidenceByFinding || {};

  const title = m.report_title || project.title || 'Penetration Test';
  const subtitle = m.report_subtitle || 'Web Application Penetration Test Report';
  const dateText = fmtDate(m.report_date) || fmtDate(new Date());

  const content = [];

  // 1-3
  content.push(sectionHeading(1, 'Executive Summary'));
  content.push(...prose(m.exec_summary));
  if (str(m.key_risk_themes).trim()) {
    content.push(body('Based on the findings identified during testing, the key risk themes were:'));
    content.push(...proseAsBullets(m.key_risk_themes));
  }

  content.push(sectionHeading(2, 'Approach'));
  content.push(...prose(m.approach));

  content.push(sectionHeading(3, 'Summary of Scope and Objectives'));
  content.push(...prose(m.scope_objectives));

  // 4
  content.push(sectionHeading(4, 'Summary of Business Risks'));
  content.push(body(riskLeadSentence(list)));
  if (list.length) content.push(buildRiskTable(list));

  // 5
  content.push(sectionHeading(5, 'Summary of Findings'));
  content.push(...prose(m.findings_summary));

  // 6
  content.push(sectionHeading(6, 'OWASP Top 10 Web Security Risks Summary'));
  content.push(body(
    'The Open Web Application Security Project (OWASP) Top 10 Web Application Security Risks is a '
    + 'widely recognised framework that highlights common, high-impact threats to web applications. '
    + 'Against this framework, the assessed application showed strengths in several areas; however, '
    + 'issues were identified as summarised below.'
  ));
  content.push(buildOwaspTable(m.owasp_results));

  // 7
  content.push(sectionHeading(7, 'Mitigating Factors'));
  content.push(body(
    'Mitigating factors are controls implemented to reduce the likelihood and impact of cyber-attacks '
    + 'by introducing additional layers of protection (for example, encryption, authentication, access '
    + 'controls, and monitoring).'
  ));
  content.push(...prose(m.mitigating_factors));

  // 8
  content.push(sectionHeading(8, 'Attack Paths'));
  content.push(body(
    'Attack path mapping provides business context by illustrating how an attacker could reach critical '
    + 'assets through a sequence of weaknesses. It supports prioritisation of remediation and improves '
    + 'incident response readiness.'
  ));
  content.push(...prose(m.attack_paths_intro));
  content.push(...prose(m.attack_paths_narrative));

  // 9
  content.push(sectionHeading(9, 'Recommended Next Steps'));
  content.push(...prose(m.next_steps));

  // Appendix A
  content.push(new Paragraph({ children: [new PageBreak()] }));
  content.push(sectionHeading(null, 'Appendix A: Overview and Scope'));
  content.push(body(
    'The assessment scope included a penetration test of the target application to identify weaknesses '
    + 'an external adversary could uncover and exploit. The objective was to identify exploitable '
    + 'vulnerabilities and misconfigurations that could lead to unauthorised access, sensitive data '
    + 'exposure, or disruption of application functionality.'
  ));

  content.push(subHeading('Scope'));
  const endpoints = str(m.scope_endpoints || project.scope).split('\n')
    .map((s) => s.trim()).filter(Boolean);
  if (endpoints.length) {
    content.push(body('Testing focused on the following endpoints:'));
    for (const e of endpoints) content.push(bullet(e));
  } else {
    content.push(body('No scope endpoints were recorded for this engagement.', { italics: true, color: MUTED }));
  }

  content.push(subHeading('Methodology'));
  content.push(...prose(m.methodology || 'The assessment was conducted using a black-box methodology.'));

  content.push(subHeading('Delivery Team'));
  const team = Array.isArray(m.delivery_team) ? m.delivery_team.filter((t) => t && (t.name || t.role)) : [];
  if (team.length) {
    const rows = [headerRow(['Name', 'Role'], [45, 55])];
    for (const t of team) {
      rows.push(new TableRow({ children: [cell(t.name), cell(t.role)] }));
    }
    content.push(table(rows));
  } else {
    content.push(body('No delivery team members were recorded.', { italics: true, color: MUTED }));
  }

  content.push(subHeading('Timeline'));
  const timeline = m.timeline_note
    || [fmtDate(project.start_date), fmtDate(project.end_date)].filter(Boolean).join(' to ')
    || 'Not recorded.';
  content.push(body(timeline));

  // Appendix B
  content.push(new Paragraph({ children: [new PageBreak()] }));
  content.push(sectionHeading(null, 'Appendix B: Identified Vulnerabilities'));
  if (list.length) {
    list.forEach((f, i) => {
      if (i > 0) content.push(new Paragraph({ children: [new PageBreak()] }));
      content.push(...buildFinding(f, i, evidence[f.id]));
    });
  } else {
    content.push(body('No vulnerabilities were identified during this assessment.', { italics: true, color: MUTED }));
  }

  // Appendix C
  content.push(new Paragraph({ children: [new PageBreak()] }));
  content.push(...buildAppendixC());

  const doc = new Document({
    creator: 'Reflex Solutions (Pty) Ltd',
    title: `${title} — ${subtitle}`,
    description: 'Penetration test report generated by the Reflex SecOps Dashboard.',
    // Prompts Word to resolve the table of contents field on open.
    features: { updateFields: true },
    styles: {
      default: {
        document: { run: { font: 'Calibri', size: 22, color: INK } },
      },
    },
    sections: [
      {
        // Cover — no header/footer, no page number.
        properties: { titlePage: false },
        children: buildCover({ title, subtitle, dateText, logo: logoBuffer }),
      },
      {
        properties: {},
        headers: { default: buildHeader({ title, subtitle, logo: logoBuffer }) },
        footers: { default: buildFooter({ client: project.client }) },
        children: [
          // Deliberately not a Heading style — it must not list itself.
          new Paragraph({
            spacing: { after: 220 },
            children: [new TextRun({ text: 'TABLE OF CONTENTS', bold: true, size: 26, color: BLUE })],
          }),
          new TableOfContents('Table of Contents', {
            hyperlink: true,
            headingStyleRange: '1-2',
          }),
          new Paragraph({ children: [new PageBreak()] }),
          ...content,
        ],
      },
    ],
  });

  return Packer.toBuffer(doc);
}

module.exports = {
  buildPentestReport,
  imageDimensions,
  DEFAULT_OWASP,
  SEVERITY_ORDER,
  SEVERITY_LABEL,
};
