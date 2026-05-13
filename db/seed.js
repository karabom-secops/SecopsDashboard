'use strict';

/**
 * db/seed.js
 * Creates the first admin user.
 *
 * Usage:
 *   node db/seed.js
 *
 * Reads credentials from environment variables (or .env):
 *   SEED_USERNAME  — defaults to "admin"
 *   SEED_PASSWORD  — REQUIRED (will exit if not set)
 *
 * Safe to re-run: skips creation if the username already exists.
 */

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.PG_HOST     || 'localhost',
  port:     parseInt(process.env.PG_PORT || '5432', 10),
  database: process.env.PG_DATABASE || 'secops_db',
  user:     process.env.PG_USER     || 'secops_user',
  password: process.env.PG_PASSWORD,
});

async function seed() {
  const username = (process.env.SEED_USERNAME || 'admin').trim();
  const password = (process.env.SEED_PASSWORD || '').trim();

  if (!password) {
    console.error('ERROR: SEED_PASSWORD environment variable is required.');
    console.error('  Set it in .env or prefix the command:');
    console.error('  SEED_PASSWORD=yourpassword node db/seed.js');
    process.exit(1);
  }

  if (username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_]+$/.test(username)) {
    console.error('ERROR: SEED_USERNAME must be 3-30 alphanumeric characters (underscores allowed).');
    process.exit(1);
  }

  const client = await pool.connect();
  try {
    const existing = await client.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      console.log(`User "${username}" already exists (id=${existing.rows[0].id}). Skipping.`);
      return;
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await client.query(
      `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin') RETURNING id`,
      [username, hash]
    );
    console.log(`Admin user "${username}" created successfully (id=${result.rows[0].id}).`);
  } finally {
    client.release();
    await pool.end();
  }
}

seed().catch(err => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});
