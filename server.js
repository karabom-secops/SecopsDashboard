'use strict';

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');

const { parseReport } = require('./lib/parser');
const { computeAllMetrics, getSummary, getOrgHistory } = require('./lib/metrics');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const WEEKS_FILE = path.join(DATA_DIR, 'weeks.json');
const METRICS_FILE = path.join(DATA_DIR, 'metrics.json');

// ── Data helpers ──────────────────────────────────────────────────────────────

function readData(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return {};
  }
}

function writeData(filePath, obj) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
}

function recomputeMetrics() {
  const weeks = readData(WEEKS_FILE);
  const metrics = computeAllMetrics(weeks);
  writeData(METRICS_FILE, metrics);
  return metrics;
}

// ── Basic Auth ────────────────────────────────────────────────────────────────

const AUTH_USER = process.env.AUTH_USER || 'admin';
const AUTH_PASS = process.env.AUTH_PASS || 'secops';

function basicAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const b64 = authHeader.startsWith('Basic ') ? authHeader.slice(6) : '';
  const [user, pass] = Buffer.from(b64, 'base64').toString().split(':');

  if (user === AUTH_USER && pass === AUTH_PASS) {
    return next();
  }

  res.set('WWW-Authenticate', 'Basic realm="SecOps Dashboard"');
  return res.status(401).json({ statusCode: 401, error: 'Unauthorized', message: 'Authentication required' });
}

// ── Middleware ────────────────────────────────────────────────────────────────

app.use(basicAuth);
app.use(express.json());
// Serve static assets both at root AND under /secops/ so that
// <base href="/secops/"> resolves asset paths correctly.
const PUBLIC = path.join(__dirname, 'public');
app.use('/secops', express.static(PUBLIC));
app.use(express.static(PUBLIC));

const upload = multer({ storage: multer.memoryStorage() });

// ── Routes ────────────────────────────────────────────────────────────────────

/**
 * POST /api/upload
 * Fields:
 *   report  – plain text (text field OR .txt file upload)
 *   csv     – optional CSV file upload
 */
app.post(
  '/api/upload',
  upload.fields([{ name: 'report', maxCount: 1 }, { name: 'csv', maxCount: 1 }]),
  (req, res) => {
    try {
      // Support both textarea text field and file upload for report
      let reportText = req.body.report || '';
      if (!reportText && req.files && req.files.report) {
        reportText = req.files.report[0].buffer.toString('utf8');
      }
      if (!reportText) {
        return res.status(400).json({ error: 'No report provided.' });
      }

      let csvText = '';
      if (req.files && req.files.csv) {
        csvText = req.files.csv[0].buffer.toString('utf8');
      }

      const parsed = parseReport(reportText, csvText);
      if (parsed.error) {
        return res.status(400).json({ error: parsed.error });
      }

      const weeks = readData(WEEKS_FILE);
      weeks[parsed.weekKey] = parsed;
      writeData(WEEKS_FILE, weeks);

      recomputeMetrics();

      return res.json(parsed);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
);

/**
 * GET /api/weeks
 * Returns [{ key, weekCommencing }] sorted descending.
 */
app.get('/api/weeks', (req, res) => {
  try {
    const weeks = readData(WEEKS_FILE);
    const list = Object.keys(weeks)
      .sort((a, b) => b.localeCompare(a))
      .map(k => ({ key: k, weekCommencing: weeks[k].weekCommencing }));
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/week/:weekKey
 */
app.get('/api/week/:weekKey', (req, res) => {
  try {
    const weeks = readData(WEEKS_FILE);
    const week = weeks[req.params.weekKey];
    if (!week) return res.status(404).json({ error: 'Week not found.' });
    res.json(week);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * PATCH /api/week/:weekKey/priority/:index
 * Body: { status: 'open' | 'wip' | 'done' }
 */
app.patch('/api/week/:weekKey/priority/:index', (req, res) => {
  try {
    const { weekKey, index } = req.params;
    const { status } = req.body;

    if (!['open', 'wip', 'done'].includes(status)) {
      return res.status(400).json({ error: 'status must be open, wip, or done.' });
    }

    const weeks = readData(WEEKS_FILE);
    const week = weeks[weekKey];
    if (!week) return res.status(404).json({ error: 'Week not found.' });

    const idx = parseInt(index, 10);
    if (isNaN(idx) || idx < 0 || idx >= week.priorities.length) {
      return res.status(400).json({ error: 'Invalid priority index.' });
    }

    week.priorities[idx].status = status;
    writeData(WEEKS_FILE, weeks);
    recomputeMetrics();

    res.json(week);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/metrics/summary
 * Returns last 12 weeks of computed metrics.
 */
app.get('/api/metrics/summary', (req, res) => {
  try {
    const metrics = readData(METRICS_FILE);
    const summary = getSummary(metrics, 12);
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/metrics/orgs
 * Returns per-org alert history across all weeks.
 */
app.get('/api/metrics/orgs', (req, res) => {
  try {
    const weeks = readData(WEEKS_FILE);
    const history = getOrgHistory(weeks);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`SecOps Dashboard running on http://localhost:${PORT}`);
  console.log(`Access via base path:   http://localhost:${PORT}/secops/`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Stop the existing process or change PORT in .env`);
  } else {
    console.error('Server error:', err.message);
  }
  process.exit(1);
});
