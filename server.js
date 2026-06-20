const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

// ── Block-explorer proxy config ──────────────────────────────────────────────
// The bridge reads window.usernode.transactionsBaseUrl ('/explorer-api') and
// fetches `${base}/transactions` from inside the iframe. That request lands
// here and must be forwarded to the public block explorer, which exposes the
// chain-scoped path POST /<chain_id>/transactions. The explorer base is the
// platform-managed NODE_RPC_URL (points at usernode-node in-network); CHAIN_ID
// selects the chain segment. EXPLORER_BASE_URL is an optional override for a
// standalone explorer host.
const EXPLORER_BASE = (
  process.env.EXPLORER_BASE_URL ||
  process.env.NODE_RPC_URL ||
  ''
).replace(/\/+$/, '');
const CHAIN_ID = (process.env.CHAIN_ID || process.env.USERNODE_CHAIN_ID || '').trim();

const PUBLIC_API_PATHS = new Set(['/health']);
const PUBLIC_PREFIXES = ['/explorer-api/'];

app.use(express.json());

app.use((req, res, next) => {
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_SECRET) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch {}
  }
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (PUBLIC_PREFIXES.some((p) => req.path.startsWith(p))) return next();
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── Explorer reverse proxy ───────────────────────────────────────────────────
// Mounted after the auth middleware (the /explorer-api/ prefix already bypasses
// the JWT gate) and before express.static / the catch-all. Forwards any method
// and sub-path: /explorer-api/<rest> → <EXPLORER_BASE>/<chain_id>/<rest>,
// preserving the method, content-type and JSON body, and streaming the upstream
// status + body back unchanged. On a config/network error it returns a non-2xx
// JSON error so the bridge's getTransactions().catch degrades to an empty list
// rather than throwing.
app.all('/explorer-api/*', async (req, res) => {
  if (!EXPLORER_BASE) {
    return res.status(502).json({ error: 'Block explorer upstream not configured (set NODE_RPC_URL / EXPLORER_BASE_URL)' });
  }

  // Everything after the '/explorer-api/' prefix, including the query string.
  const sub = req.originalUrl.replace(/^\/explorer-api\/?/, '');
  const target =
    EXPLORER_BASE +
    (CHAIN_ID ? '/' + encodeURIComponent(CHAIN_ID) : '') +
    '/' + sub;

  const headers = {};
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['accept']) headers['accept'] = req.headers['accept'];

  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    // express.json() already parsed the body; re-serialize it verbatim.
    init.body = JSON.stringify(req.body == null ? {} : req.body);
    if (!headers['content-type']) headers['content-type'] = 'application/json';
  }

  try {
    const upstream = await fetch(target, init);
    const body = await upstream.text();
    res.status(upstream.status);
    const ct = upstream.headers.get('content-type');
    if (ct) res.set('content-type', ct);
    return res.send(body);
  } catch (err) {
    return res.status(502).json({ error: 'Explorer proxy request failed: ' + err.message });
  }
});

app.get('/api/me', (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, usernode_pubkey: req.user.usernode_pubkey || null });
});

app.get('/api/proposals', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        p.id, p.title, p.description, p.created_at,
        COALESCE(SUM(CASE WHEN v.direction = 'for' THEN 1 ELSE 0 END), 0)::int AS for_count,
        COALESCE(SUM(CASE WHEN v.direction = 'against' THEN 1 ELSE 0 END), 0)::int AS against_count,
        MAX(CASE WHEN v.user_id = $1 THEN v.direction END) AS my_vote
      FROM governance_proposals p
      LEFT JOIN votes v ON v.proposal_id = p.id
      GROUP BY p.id
      ORDER BY p.id
    `, [req.user.id]);
    res.json({ proposals: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/votes', async (req, res) => {
  const { proposal_id, direction } = req.body;
  if (!proposal_id || !['for', 'against'].includes(direction)) {
    return res.status(400).json({ error: 'Invalid vote payload' });
  }
  try {
    await pool.query(`
      INSERT INTO votes (proposal_id, user_id, username, direction)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (proposal_id, user_id)
      DO UPDATE SET direction = EXCLUDED.direction, created_at = NOW()
    `, [proposal_id, req.user.id, req.user.username, direction]);
    res.json({ ok: true, direction });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Sales (source of truth in Postgres; the on-chain memo is a best-effort
//    receipt). The dashboard's sales / treasury / stats render from here. ──────
app.get('/api/sales', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, user_id, username, seller_addr, title, amount, fee, tx_hash, created_at
      FROM sales
      ORDER BY id DESC
    `);
    res.json({ sales: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sales', async (req, res) => {
  const { title, amount, fee, seller_addr } = req.body || {};
  const amt = Number(amount);
  if (!title || !String(title).trim() || isNaN(amt) || amt <= 0) {
    return res.status(400).json({ error: 'Invalid sale payload' });
  }
  try {
    const { rows } = await pool.query(`
      INSERT INTO sales (user_id, username, seller_addr, title, amount, fee)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, user_id, username, seller_addr, title, amount, fee, tx_hash, created_at
    `, [req.user.id, req.user.username, seller_addr || null, String(title).slice(0, 255), amt, Number(fee) || 0]);
    res.json({ sale: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/sales/:id/tx', async (req, res) => {
  const { tx_hash } = req.body || {};
  try {
    await pool.query(`UPDATE sales SET tx_hash = $1 WHERE id = $2`, [tx_hash || null, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Enrolments (artist ownership; public — shown to every member in-app). ─────
app.get('/api/enrolments', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, user_id, username, addr, tx_hash, created_at
      FROM enrolments
      ORDER BY id ASC
    `);
    res.json({ enrolments: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/enrolments', async (req, res) => {
  const { addr } = req.body || {};
  if (!addr || !String(addr).trim()) {
    return res.status(400).json({ error: 'Missing addr' });
  }
  try {
    // The addr UNIQUE constraint is the dedupe — no need to read the chain.
    const existing = await pool.query(`SELECT id, addr, tx_hash FROM enrolments WHERE addr = $1`, [addr]);
    if (existing.rows.length) {
      return res.json({ enrolment: existing.rows[0], enrolled: false });
    }
    const { rows } = await pool.query(`
      INSERT INTO enrolments (user_id, username, addr)
      VALUES ($1, $2, $3)
      ON CONFLICT (addr) DO NOTHING
      RETURNING id, addr, tx_hash
    `, [req.user.id, req.user.username, addr]);
    if (rows.length) {
      return res.json({ enrolment: rows[0], enrolled: true });
    }
    const again = await pool.query(`SELECT id, addr, tx_hash FROM enrolments WHERE addr = $1`, [addr]);
    res.json({ enrolment: again.rows[0], enrolled: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/enrolments/:id/tx', async (req, res) => {
  const { tx_hash } = req.body || {};
  try {
    await pool.query(`UPDATE enrolments SET tx_hash = $1 WHERE id = $2`, [tx_hash || null, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  if (!req.user) {
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Usernode</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Usernode</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="https://social-vibecoding.usernodelabs.org" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Go to Usernode</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

async function start() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS governance_proposals (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS votes (
      id SERIAL PRIMARY KEY,
      proposal_id INTEGER NOT NULL REFERENCES governance_proposals(id),
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      direction VARCHAR(10) NOT NULL CHECK (direction IN ('for', 'against')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (proposal_id, user_id)
    )
  `);

  await pool.query(`COMMENT ON TABLE votes IS 'staging:private'`);

  // Sales: durable record of each recorded sale. The on-chain memo is a
  // best-effort receipt (tx_hash), not the source of truth — so a rejected
  // send no longer erases the sale. Marked private: amounts are financial data.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sales (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      seller_addr VARCHAR(255),
      title VARCHAR(255) NOT NULL,
      amount NUMERIC NOT NULL DEFAULT 0,
      fee NUMERIC NOT NULL DEFAULT 0,
      tx_hash VARCHAR(255),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`COMMENT ON TABLE sales IS 'staging:private'`);

  // Enrolments: artist ownership roster. Public — every member sees the
  // ownership split in-app. addr is unique (dedupes enrolment without a chain read).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS enrolments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      addr VARCHAR(255) NOT NULL UNIQUE,
      tx_hash VARCHAR(255),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Seed the initial proposal in all environments — it's a new table with no
  // prior production data, so it needs seeding on first deploy everywhere.
  await pool.query(`
    INSERT INTO governance_proposals (id, title, description)
    VALUES (1, 'Fee Split Adjustment',
      'Proposal to adjust gallery revenue distribution: raise Artist dividends from 50% to 55%, reducing Reserve from 15% to 10%. This change better rewards participating artists for their contributions.')
    ON CONFLICT (id) DO NOTHING
  `);

  if (IS_STAGING) {
    // Seed mock votes so the progress bar shows a realistic state in staging.
    // (votes is staging:private — no rows copy from prod)
    const mockVotes = [
      [1, 9001, 'staging-artist-1', 'for'],
      [1, 9002, 'staging-artist-2', 'for'],
      [1, 9003, 'staging-artist-3', 'for'],
      [1, 9004, 'staging-artist-4', 'for'],
      [1, 9005, 'staging-artist-5', 'against'],
    ];
    for (const [pid, uid, uname, dir] of mockVotes) {
      await pool.query(`
        INSERT INTO votes (proposal_id, user_id, username, direction)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (proposal_id, user_id) DO NOTHING
      `, [pid, uid, uname, dir]);
    }

    // Seed enrolments so Ownership shows an even 4-way split. enrolments is a
    // newly-created table (empty in staging); sales is staging:private (empty).
    // Addresses match the demo addresses used elsewhere in the UI.
    const mockEnrolments = [
      [900001, 9001, 'staging-artist-1', 'ut1stg1abc'],
      [900002, 9002, 'staging-artist-2', 'ut1stg2def'],
      [900003, 9003, 'staging-artist-3', 'ut1stg3ghi'],
      [900004, 9004, 'staging-artist-4', 'ut1stg4jkl'],
    ];
    for (const [id, uid, uname, addr] of mockEnrolments) {
      await pool.query(`
        INSERT INTO enrolments (id, user_id, username, addr)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO NOTHING
      `, [id, uid, uname, addr]);
    }

    // Seed a few sales so Treasury / Your sales / stats render populated.
    const mockSales = [
      [900001, 9001, 'staging-artist-1', 'ut1stg1abc', 'Staging demo — Autumn Light #1', 450, 45],
      [900002, 9001, 'staging-artist-1', 'ut1stg1abc', 'Staging demo — Blue Resonance #7', 280, 28],
      [900003, 9001, 'staging-artist-1', 'ut1stg1abc', 'Staging demo — Quiet Tide #3', 620, 62],
    ];
    for (const [id, uid, uname, addr, title, amount, fee] of mockSales) {
      await pool.query(`
        INSERT INTO sales (id, user_id, username, seller_addr, title, amount, fee)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO NOTHING
      `, [id, uid, uname, addr, title, amount, fee]);
    }
  }

  app.listen(port, () => console.log(`Listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
