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

// ── Desktop access code ───────────────────────────────────────────────────────
// Mints a short sign-in code for the gallery website (artists-collective.pages.dev)
// so an artist can manage their gallery from a computer. No on-chain transaction:
// this is a plain authenticated HTTPS call made SERVER-SIDE so the bearer key
// (WEB_ACCESS_KEY) never reaches the browser. Auth is guaranteed by the
// deny-by-default middleware above (this path is NOT in PUBLIC_API_PATHS), so
// req.user is always present here. Identity (username, address) is taken from the
// verified JWT; the client-supplied address is only a demo-mode fallback.
const WEB_ACCESS_URL = 'https://artists-collective.pages.dev/api/web-access';
const WEB_ACCESS_LOGIN_URL = 'https://artists-collective.pages.dev/login';

app.post('/api/web-access-code', async (req, res) => {
  const username = req.user.username;
  // Trust the verified pubkey first; fall back to the client-sent address only
  // for demo sessions where the wallet isn't linked (usernode_pubkey is null).
  const address = req.user.usernode_pubkey || (req.body && req.body.address) || '';
  if (!address) {
    return res.status(400).json({ error: 'No artist address available' });
  }

  // Staging: the prod WEB_ACCESS_KEY is private (excluded from staging), so skip
  // the external call entirely and return an obviously-fake code so the flow is
  // testable end-to-end. Strict no-op in production.
  if (IS_STAGING) {
    console.log('[web-access-code] staging stub for', username);
    return res.json({ ok: true, code: '024680', username, login_url: WEB_ACCESS_LOGIN_URL });
  }

  const key = process.env.WEB_ACCESS_KEY;
  if (!key) {
    console.warn('[web-access-code] WEB_ACCESS_KEY is not set — cannot mint a code');
    return res.status(502).json({ error: 'Desktop access is not configured yet' });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const upstream = await fetch(WEB_ACCESS_URL, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + key,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ address, username }),
      signal: controller.signal,
    });
    if (!upstream.ok) {
      console.warn('[web-access-code] upstream responded', upstream.status);
      return res.status(502).json({ error: "Couldn't get a code right now, try again" });
    }
    const data = await upstream.json();
    if (!data || !data.code) {
      console.warn('[web-access-code] upstream response missing code');
      return res.status(502).json({ error: "Couldn't get a code right now, try again" });
    }
    // Pass the upstream JSON through. The code is one-time-display — never stored.
    return res.json({
      ok: true,
      code: data.code,
      username: data.username || username,
      login_url: data.login_url || WEB_ACCESS_LOGIN_URL,
    });
  } catch (err) {
    console.warn('[web-access-code] request failed:', err.message);
    return res.status(502).json({ error: "Couldn't get a code right now, try again" });
  } finally {
    clearTimeout(timeout);
  }
});

// ── Profile picture (avatar) ────────────────────────────────────────────────
// Forwards an artist's new portrait to the gallery website server-side, so the
// bearer key (WEB_ACCESS_KEY — the same private platform secret used by the
// desktop-access route) never reaches the browser. No on-chain transaction:
// this is a plain authenticated HTTPS call. Auth is guaranteed by the
// deny-by-default middleware above (this path is NOT in PUBLIC_API_PATHS), so
// req.user is always present. The address is taken from the verified pubkey
// first, with the client-supplied address as a demo-mode fallback (mirrors the
// web-access-code handler).
const AVATAR_URL = 'https://artists-collective.pages.dev/api/avatar';
const ALLOWED_AVATAR_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
// Backstop cap on the base64 payload (~7MB of base64 ≈ ~5MB binary). The client
// guards before upload; this protects the route from oversized bodies.
const MAX_AVATAR_BASE64_LEN = 7 * 1024 * 1024;

app.post('/api/avatar', async (req, res) => {
  const body = req.body || {};
  const content_type = String(body.content_type || '');
  const image_base64 = typeof body.image_base64 === 'string' ? body.image_base64 : '';
  // Trust the verified pubkey first; fall back to the client-sent address only
  // for demo sessions where the wallet isn't linked (usernode_pubkey is null).
  const address = req.user.usernode_pubkey || body.address || '';

  if (!address) {
    return res.status(400).json({ error: 'No artist address available' });
  }
  if (!ALLOWED_AVATAR_TYPES.has(content_type)) {
    return res.status(400).json({ error: 'Unsupported image type' });
  }
  if (!image_base64) {
    return res.status(400).json({ error: 'No image data provided' });
  }
  if (image_base64.length > MAX_AVATAR_BASE64_LEN) {
    return res.status(400).json({ error: 'Image is too large' });
  }

  // Staging: the prod WEB_ACCESS_KEY is private (excluded from staging), so skip
  // the external call entirely and echo the uploaded image back as a data: URL
  // so the upload flow is testable end-to-end. Strict no-op in production.
  if (IS_STAGING) {
    console.log('[avatar] staging stub for', req.user.username);
    const dataUrl = 'data:' + content_type + ';base64,' + image_base64;
    return res.json({ ok: true, portrait: '', portrait_url: dataUrl });
  }

  const key = process.env.WEB_ACCESS_KEY;
  if (!key) {
    console.warn('[avatar] WEB_ACCESS_KEY is not set — cannot update portrait');
    return res.status(502).json({ error: "Couldn't update your picture, try again" });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const upstream = await fetch(AVATAR_URL, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + key,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ address, content_type, image_base64 }),
      signal: controller.signal,
    });
    if (!upstream.ok) {
      console.warn('[avatar] upstream responded', upstream.status);
      return res.status(502).json({ error: "Couldn't update your picture, try again" });
    }
    const data = await upstream.json();
    if (!data || !data.portrait_url) {
      console.warn('[avatar] upstream response missing portrait_url');
      return res.status(502).json({ error: "Couldn't update your picture, try again" });
    }
    return res.json({ ok: true, portrait: data.portrait || '', portrait_url: data.portrait_url });
  } catch (err) {
    console.warn('[avatar] request failed:', err.message);
    return res.status(502).json({ error: "Couldn't update your picture, try again" });
  } finally {
    clearTimeout(timeout);
  }
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

// ── Forum (public discussion board; pure DB-backed, no on-chain component). ───
app.get('/api/threads', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        t.id, t.user_id, t.username, t.title, t.body, t.created_at,
        COUNT(r.id)::int AS reply_count,
        GREATEST(t.created_at, COALESCE(MAX(r.created_at), t.created_at)) AS last_activity
      FROM forum_threads t
      LEFT JOIN forum_replies r ON r.thread_id = t.id
      GROUP BY t.id
      ORDER BY last_activity DESC, t.id DESC
    `);
    res.json({ threads: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/threads/:id', async (req, res) => {
  try {
    const threadRes = await pool.query(`
      SELECT id, user_id, username, title, body, created_at
      FROM forum_threads WHERE id = $1
    `, [req.params.id]);
    if (!threadRes.rows.length) return res.status(404).json({ error: 'Thread not found' });
    const repliesRes = await pool.query(`
      SELECT id, thread_id, user_id, username, body, created_at
      FROM forum_replies WHERE thread_id = $1
      ORDER BY created_at ASC, id ASC
    `, [req.params.id]);
    res.json({ thread: threadRes.rows[0], replies: repliesRes.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/threads', async (req, res) => {
  const title = String((req.body && req.body.title) || '').trim();
  const body = String((req.body && req.body.body) || '').trim();
  if (!title || !body) return res.status(400).json({ error: 'Title and message are required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO forum_threads (user_id, username, title, body)
      VALUES ($1, $2, $3, $4)
      RETURNING id, user_id, username, title, body, created_at
    `, [req.user.id, req.user.username, title.slice(0, 255), body.slice(0, 5000)]);
    res.json({ thread: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/threads/:id/replies', async (req, res) => {
  const body = String((req.body && req.body.body) || '').trim();
  if (!body) return res.status(400).json({ error: 'Reply cannot be empty' });
  try {
    const exists = await pool.query(`SELECT id FROM forum_threads WHERE id = $1`, [req.params.id]);
    if (!exists.rows.length) return res.status(404).json({ error: 'Thread not found' });
    const { rows } = await pool.query(`
      INSERT INTO forum_replies (thread_id, user_id, username, body)
      VALUES ($1, $2, $3, $4)
      RETURNING id, thread_id, user_id, username, body, created_at
    `, [req.params.id, req.user.id, req.user.username, body.slice(0, 5000)]);
    res.json({ reply: rows[0] });
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

  // Forum: discussion board for the collective. Public — every member reads
  // the board in-app (no auth/financial/personal data), so NO 'staging:private'
  // comment: these tables replicate to staging normally. forum_replies →
  // forum_threads is a public→public FK (satisfies the linter rule).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS forum_threads (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      title VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS forum_replies (
      id SERIAL PRIMARY KEY,
      thread_id INTEGER NOT NULL REFERENCES forum_threads(id),
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // ── Governance proposals seed ───────────────────────────────────────────────
  // Replace the single legacy proposal with six Yes/No proposals. Internally
  // votes still use direction 'for'/'against' (Yes=for, No=against) — only the
  // labels change in the UI — so the existing vote endpoint and on-chain memo
  // are reused unchanged.
  //
  // Re-run-safe migration (runs in all environments — these are product content
  // with no prior prod data, like the original seed):
  //   1. Retire the legacy proposal keyed on its TITLE (never the bare id=1, or
  //      a redeploy would wipe real votes on the new proposal #1). After the
  //      first boot the title is gone, so subsequent boots delete nothing.
  //   2. Insert the six proposals at fixed ids with ON CONFLICT DO NOTHING, so
  //      later boots are no-ops and accumulated votes are preserved.
  //   3. Bump the serial sequence past the explicit ids (belt-and-suspenders;
  //      nothing inserts proposals via the API today).
  await pool.query(`DELETE FROM votes WHERE proposal_id IN (SELECT id FROM governance_proposals WHERE title = 'Fee Split Adjustment')`);
  await pool.query(`DELETE FROM governance_proposals WHERE title = 'Fee Split Adjustment'`);

  const seededProposals = [
    [1, 'Set the platform fee to 20%', "Lower the gallery's cut on every sale to a flat 20%."],
    [2, 'Set the platform fee to 30%', "Raise the gallery's cut on every sale to a flat 30% to fund more programs."],
    [3, 'Allocate 40% of the treasury to marketing & reach', 'Commit 40% of the collective treasury to advertising, partnerships and audience growth.'],
    [4, 'Introduce a 2% artist dividend from each sale', 'Pay every enrolled artist a 2% dividend funded from each sale across the collective.'],
    [5, 'Feature one rising artist on the homepage each week', 'Spotlight a different emerging member on the public homepage every week.'],
    [6, 'Open the collective to outside collectors as non-voting members', 'Let outside collectors join as non-voting members with purchase access but no governance vote.'],
  ];
  for (const [id, title, description] of seededProposals) {
    await pool.query(`
      INSERT INTO governance_proposals (id, title, description)
      VALUES ($1, $2, $3)
      ON CONFLICT (id) DO NOTHING
    `, [id, title, description]);
  }
  await pool.query(`SELECT setval(pg_get_serial_sequence('governance_proposals', 'id'), GREATEST((SELECT MAX(id) FROM governance_proposals), 1))`);

  // ── Forum starter threads seed ──────────────────────────────────────────────
  // Seeded in all environments (product content; forum tables are public so a
  // fresh staging container starts empty until this runs). Idempotent via fixed
  // ids + ON CONFLICT DO NOTHING; authored by a neutral house account so no real
  // member is impersonated. Sequences bumped past the explicit ids afterwards.
  const HOUSE_ID = 9000;
  const HOUSE_NAME = 'collective';
  const seededThreads = [
    [1, 'What should our platform fee be?',
      'There are two fee proposals up for a vote right now — 20% and 30%. What feels fair to you as a working artist? Lower keeps more in our pockets per sale; higher funds shared marketing and reach. Curious where people land.'],
    [2, "Ideas for next month's featured wall",
      'We rotate a featured wall each month. Drop your themes or specific pieces you think should be up next — landscapes, abstracts, a newcomer showcase? All ideas welcome.'],
    [3, 'How do we attract more collectors?',
      "Sales have been steady but we could grow the collector base. What has worked for you elsewhere — social, open studios, collaborations, referral perks? Let's pool tactics."],
  ];
  for (const [id, title, body] of seededThreads) {
    await pool.query(`
      INSERT INTO forum_threads (id, user_id, username, title, body)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (id) DO NOTHING
    `, [id, HOUSE_ID, HOUSE_NAME, title, body]);
  }
  const seededReplies = [
    [1, 1, 9001, 'mara-vance', 'I lean 20%. We already cover our own materials; keeping more per sale matters most for the smaller artists.'],
    [2, 1, 9002, 'jonah-reed', 'Counterpoint: 30% only works if the extra actually goes to reach. If marketing is funded and transparent I could be convinced.'],
    [3, 2, 9003, 'lina-okafor', 'A "newcomers" wall — spotlight artists who joined in the last two months. Great way to welcome people.'],
    [4, 2, 9001, 'mara-vance', "Love that. I'd also vote for a colour-themed month — everything in blues and greens would look striking together."],
    [5, 3, 9004, 'theo-blanc', 'Open studio nights did wonders for a collective I was in before. Pair it with a small online preview the week prior.'],
    [6, 3, 9002, 'jonah-reed', 'Referral perks for existing collectors too — a small discount when they bring someone who buys.'],
  ];
  for (const [id, threadId, uid, uname, body] of seededReplies) {
    await pool.query(`
      INSERT INTO forum_replies (id, thread_id, user_id, username, body)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (id) DO NOTHING
    `, [id, threadId, uid, uname, body]);
  }
  await pool.query(`SELECT setval(pg_get_serial_sequence('forum_threads', 'id'), GREATEST((SELECT MAX(id) FROM forum_threads), 1))`);
  await pool.query(`SELECT setval(pg_get_serial_sequence('forum_replies', 'id'), GREATEST((SELECT MAX(id) FROM forum_replies), 1))`);

  if (IS_STAGING) {
    // Seed mock votes so each proposal shows a distinct live Yes/No tally in
    // staging. (votes is staging:private — no rows copy from prod.) direction
    // stays 'for'/'against' internally; the UI renders these as Yes/No.
    const mockVotes = [
      // Proposal 1 — Set fee to 20%: leans Yes
      [1, 9001, 'staging-artist-1', 'for'],
      [1, 9002, 'staging-artist-2', 'for'],
      [1, 9003, 'staging-artist-3', 'for'],
      [1, 9004, 'staging-artist-4', 'against'],
      // Proposal 2 — Set fee to 30%: leans No
      [2, 9001, 'staging-artist-1', 'against'],
      [2, 9002, 'staging-artist-2', 'against'],
      [2, 9003, 'staging-artist-3', 'for'],
      // Proposal 3 — 40% to marketing: split
      [3, 9001, 'staging-artist-1', 'for'],
      [3, 9002, 'staging-artist-2', 'against'],
      [3, 9004, 'staging-artist-4', 'for'],
      // Proposal 4 — 2% artist dividend: strong Yes
      [4, 9001, 'staging-artist-1', 'for'],
      [4, 9002, 'staging-artist-2', 'for'],
      [4, 9003, 'staging-artist-3', 'for'],
      [4, 9005, 'staging-artist-5', 'for'],
      // Proposal 5 — weekly featured artist: leans Yes
      [5, 9002, 'staging-artist-2', 'for'],
      [5, 9003, 'staging-artist-3', 'for'],
      [5, 9005, 'staging-artist-5', 'against'],
      // Proposal 6 — open to outside collectors: leans No
      [6, 9001, 'staging-artist-1', 'against'],
      [6, 9003, 'staging-artist-3', 'against'],
      [6, 9004, 'staging-artist-4', 'for'],
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
