const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;
const IS_STAGING = process.env.USERNODE_ENV === 'staging';

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
  }

  app.listen(port, () => console.log(`Listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
