'use strict';

/**
 * lib/db.js
 * Single shared pg.Pool instance for the application.
 */

const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.PG_HOST     || 'localhost',
  port:     parseInt(process.env.PG_PORT || '5432', 10),
  database: process.env.PG_DATABASE || 'secops_db',
  user:     process.env.PG_USER     || 'secops_user',
  password: process.env.PG_PASSWORD,
  // Keep connections alive and limit pool size
  max:              10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err.message);
});

module.exports = pool;
