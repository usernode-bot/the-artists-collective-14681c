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
    return res.json({ ok: true, code: '024680', username, login_url: WEB_ACCESS_LOGIN_URL, magic_url: WEB_ACCESS_LOGIN_URL + '?magic=staging-demo-token' });
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
      magic_url: data.magic_url || null,
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

// ── Platform fee governance ──────────────────────────────────────────────────
// The displayed/applied platform fee is governed by a single Fee Split proposal.
// platform_settings (id=1) holds the current fee, the value the proposal would
// set, which proposal governs it, and a sticky outcome status. No blockchain:
// the outcome is decided from the DB vote tally and persisted, so it survives
// reloads and redeploys.
const FEE_QUORUM = 4; // minimum total votes before the outcome is decided

// Recompute the fee outcome from the live vote tally. Only acts while status is
// still 'open'; once 'passed'/'failed' it early-returns, making the result
// persistent. On a pass, the proposed fee becomes the current fee.
async function evaluateFeeOutcome() {
  const settingsRes = await pool.query(
    `SELECT fee_proposal_id, proposed_fee, status FROM platform_settings WHERE id = 1`
  );
  if (!settingsRes.rows.length) return;
  const s = settingsRes.rows[0];
  if (s.status !== 'open' || !s.fee_proposal_id) return;

  const tallyRes = await pool.query(
    `SELECT
       COALESCE(SUM(CASE WHEN direction = 'for' THEN 1 ELSE 0 END), 0)::int AS for_count,
       COALESCE(SUM(CASE WHEN direction = 'against' THEN 1 ELSE 0 END), 0)::int AS against_count
     FROM votes WHERE proposal_id = $1`,
    [s.fee_proposal_id]
  );
  const forCount = tallyRes.rows[0].for_count;
  const againstCount = tallyRes.rows[0].against_count;
  const total = forCount + againstCount;
  if (total < FEE_QUORUM) return; // not enough participation yet — stays open

  if (forCount > againstCount) {
    await pool.query(
      `UPDATE platform_settings SET status = 'passed', fee_percent = proposed_fee WHERE id = 1`
    );
  } else {
    await pool.query(`UPDATE platform_settings SET status = 'failed' WHERE id = 1`);
  }
}

app.get('/api/platform', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT fee_percent, proposed_fee, fee_proposal_id, status FROM platform_settings WHERE id = 1`
    );
    const s = rows[0] || { fee_percent: 20, proposed_fee: 15, fee_proposal_id: null, status: 'open' };
    res.json({
      feePercent: s.fee_percent,
      proposedFee: s.proposed_fee,
      feeProposalId: s.fee_proposal_id,
      status: s.status,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    // If this was a vote on the Fee Split proposal, re-evaluate whether the
    // governed fee should now flip (sticky once decided).
    const feeRes = await pool.query(`SELECT fee_proposal_id FROM platform_settings WHERE id = 1`);
    if (feeRes.rows.length && feeRes.rows[0].fee_proposal_id === Number(proposal_id)) {
      await evaluateFeeOutcome();
    }
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

app.get('/api/enrolments/me', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, addr, tx_hash, has_seen_welcome FROM enrolments WHERE user_id = $1',
      [req.user.id]
    );
    if (rows.length) return res.json({ enrolled: true, enrolment: rows[0] });
    res.json({ enrolled: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/enrolments/me/welcome-seen', async (req, res) => {
  try {
    await pool.query(
      'UPDATE enrolments SET has_seen_welcome = TRUE WHERE user_id = $1',
      [req.user.id]
    );
    res.json({ ok: true });
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
    const existing = await pool.query(`SELECT id, addr, tx_hash, has_seen_welcome FROM enrolments WHERE addr = $1`, [addr]);
    if (existing.rows.length) {
      return res.json({ enrolment: existing.rows[0], enrolled: false });
    }
    const { rows } = await pool.query(`
      INSERT INTO enrolments (user_id, username, addr)
      VALUES ($1, $2, $3)
      ON CONFLICT (addr) DO NOTHING
      RETURNING id, addr, tx_hash, has_seen_welcome
    `, [req.user.id, req.user.username, addr]);
    if (rows.length) {
      return res.json({ enrolment: rows[0], enrolled: true });
    }
    const again = await pool.query(`SELECT id, addr, tx_hash, has_seen_welcome FROM enrolments WHERE addr = $1`, [addr]);
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

// ── Artist profiles ──────────────────────────────────────────────────────────
// A profile is keyed by user_id. Identity + bio come from the enrolments roster;
// the works gallery is derived from the artist's sales rows (each sale's title is
// a work — amounts are intentionally omitted so the page reads as a showcase, not
// a finance view). Non-enrolled authors (e.g. the forum house account) still
// resolve to a name-only profile rather than 404/500.
app.get('/api/artists/:id', async (req, res) => {
  const uid = parseInt(req.params.id, 10);
  if (!uid) return res.status(400).json({ error: 'Invalid artist id' });
  try {
    const enrolRes = await pool.query(
      `SELECT username, addr, bio FROM enrolments WHERE user_id = $1 LIMIT 1`,
      [uid]
    );

    let username;
    let addr = null;
    let bio = null;
    let enrolled = false;

    if (enrolRes.rows.length) {
      const e = enrolRes.rows[0];
      username = e.username;
      addr = e.addr;
      bio = e.bio;
      enrolled = true;
    } else {
      // Fall back to the most recent name this user appears under in-app, then
      // to a client-passed hint, then to a neutral placeholder.
      const nameRes = await pool.query(
        `SELECT username FROM (
           SELECT username, created_at FROM sales WHERE user_id = $1
           UNION ALL
           SELECT username, created_at FROM forum_threads WHERE user_id = $1
           UNION ALL
           SELECT username, created_at FROM forum_replies WHERE user_id = $1
         ) t ORDER BY created_at DESC LIMIT 1`,
        [uid]
      );
      username = (nameRes.rows[0] && nameRes.rows[0].username)
        || (req.query.username && String(req.query.username).slice(0, 255))
        || 'Unknown artist';
    }

    const worksRes = await pool.query(
      `SELECT id, title, created_at FROM sales WHERE user_id = $1 ORDER BY created_at DESC, id DESC`,
      [uid]
    );

    // Follow stats: counts on both sides plus whether the viewer follows this
    // artist. follows is public; this is a query-time read, not an FK.
    const followRes = await pool.query(
      `SELECT
         (SELECT COUNT(*)::int FROM follows WHERE followee_id = $1) AS follower_count,
         (SELECT COUNT(*)::int FROM follows WHERE follower_id = $1) AS following_count,
         EXISTS (SELECT 1 FROM follows WHERE follower_id = $2 AND followee_id = $1) AS is_following`,
      [uid, req.user.id]
    );
    const f = followRes.rows[0] || { follower_count: 0, following_count: 0, is_following: false };

    res.json({
      artist: {
        user_id: uid, username, addr, bio, enrolled,
        follower_count: f.follower_count,
        following_count: f.following_count,
        is_following: f.is_following,
      },
      works: worksRes.rows,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Followers / following lists for an artist's profile. Public social graph;
//    each row is { user_id, username } drawn from the relevant side of follows. ─
app.get('/api/artists/:id/followers', async (req, res) => {
  const uid = parseInt(req.params.id, 10);
  if (!uid) return res.status(400).json({ error: 'Invalid artist id' });
  try {
    const { rows } = await pool.query(
      `SELECT follower_id AS user_id, follower_username AS username
       FROM follows WHERE followee_id = $1 ORDER BY created_at DESC, id DESC`,
      [uid]
    );
    res.json({ followers: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/artists/:id/following', async (req, res) => {
  const uid = parseInt(req.params.id, 10);
  if (!uid) return res.status(400).json({ error: 'Invalid artist id' });
  try {
    const { rows } = await pool.query(
      `SELECT followee_id AS user_id, followee_username AS username
       FROM follows WHERE follower_id = $1 ORDER BY created_at DESC, id DESC`,
      [uid]
    );
    res.json({ following: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Follow / unfollow ─────────────────────────────────────────────────────────
// follows is a public social graph (who-follows-whom is in-app-visible content,
// like the ownership roster and forum). usernames are denormalized, mirroring
// the rest of the app; there is no FK to a private table.
app.post('/api/follows', async (req, res) => {
  const followeeId = parseInt((req.body && req.body.followee_id) || 0, 10);
  const followeeUsername = String((req.body && req.body.followee_username) || '').trim();
  if (!followeeId || followeeId === req.user.id) {
    return res.status(400).json({ error: 'Invalid follow target' });
  }
  if (!followeeUsername) {
    return res.status(400).json({ error: 'Missing followee_username' });
  }
  try {
    await pool.query(
      `INSERT INTO follows (follower_id, follower_username, followee_id, followee_username)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (follower_id, followee_id) DO NOTHING`,
      [req.user.id, req.user.username, followeeId, followeeUsername.slice(0, 255)]
    );
    res.json({ ok: true, following: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/follows/:followeeId', async (req, res) => {
  const followeeId = parseInt(req.params.followeeId, 10);
  if (!followeeId) return res.status(400).json({ error: 'Invalid follow target' });
  try {
    await pool.query(
      `DELETE FROM follows WHERE follower_id = $1 AND followee_id = $2`,
      [req.user.id, followeeId]
    );
    res.json({ ok: true, following: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Personalized feed ─────────────────────────────────────────────────────────
// Latest works from the artists the viewer follows. Works are sales rows; only
// title/date/author are selected — amounts/fees are deliberately omitted so no
// financial data leaves the server (matching the profile works showcase).
app.get('/api/feed', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT s.user_id, s.username, s.title, s.created_at
       FROM follows f
       JOIN sales s ON s.user_id = f.followee_id
       WHERE f.follower_id = $1
       ORDER BY s.created_at DESC, s.id DESC
       LIMIT 50`,
      [req.user.id]
    );
    res.json({ items: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/artists/me/bio', async (req, res) => {
  const bio = String((req.body && req.body.bio) || '').trim().slice(0, 1000);
  try {
    const { rows } = await pool.query(
      `UPDATE enrolments SET bio = $1 WHERE user_id = $2 RETURNING id`,
      [bio, req.user.id]
    );
    if (!rows.length) {
      return res.status(400).json({ error: 'Enrol before editing your profile' });
    }
    res.json({ ok: true, bio });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/artists/:id/collections', async (req, res) => {
  const uid = parseInt(req.params.id, 10);
  if (!uid) return res.status(400).json({ error: 'Invalid artist id' });
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.title, c.created_at, COUNT(ci.id)::int AS item_count
      FROM collections c
      LEFT JOIN collection_items ci ON ci.collection_id = c.id
      WHERE c.user_id = $1
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `, [uid]);
    res.json({ collections: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Artwork reactions & comments ─────────────────────────────────────────────
const ALLOWED_EMOJIS = ['❤️', '🔥', '👏', '✨', '🎨'];

app.get('/api/artworks/:saleId/reactions', async (req, res) => {
  const saleId = parseInt(req.params.saleId, 10);
  if (!saleId) return res.status(400).json({ error: 'Invalid saleId' });
  try {
    const countsRes = await pool.query(
      `SELECT emoji, COUNT(*)::int AS cnt FROM artwork_reactions WHERE sale_id = $1 GROUP BY emoji`,
      [saleId]
    );
    const counts = {};
    for (const e of ALLOWED_EMOJIS) counts[e] = 0;
    for (const row of countsRes.rows) if (counts[row.emoji] !== undefined) counts[row.emoji] = row.cnt;

    let myEmoji = null;
    if (req.user) {
      const myRes = await pool.query(
        `SELECT emoji FROM artwork_reactions WHERE sale_id = $1 AND user_id = $2`,
        [saleId, req.user.id]
      );
      myEmoji = myRes.rows[0] ? myRes.rows[0].emoji : null;
    }
    res.json({ counts, myEmoji });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/artworks/:saleId/reactions', async (req, res) => {
  const saleId = parseInt(req.params.saleId, 10);
  if (!saleId) return res.status(400).json({ error: 'Invalid saleId' });
  const emoji = (req.body && req.body.emoji) || '';
  if (!ALLOWED_EMOJIS.includes(emoji)) return res.status(400).json({ error: 'Invalid emoji' });
  try {
    const saleCheck = await pool.query(`SELECT id FROM sales WHERE id = $1`, [saleId]);
    if (!saleCheck.rows.length) return res.status(404).json({ error: 'Artwork not found' });

    const existing = await pool.query(
      `SELECT emoji FROM artwork_reactions WHERE sale_id = $1 AND user_id = $2`,
      [saleId, req.user.id]
    );
    if (existing.rows.length && existing.rows[0].emoji === emoji) {
      await pool.query(
        `DELETE FROM artwork_reactions WHERE sale_id = $1 AND user_id = $2`,
        [saleId, req.user.id]
      );
    } else {
      await pool.query(
        `INSERT INTO artwork_reactions (sale_id, user_id, username, emoji)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (sale_id, user_id) DO UPDATE SET emoji = EXCLUDED.emoji, created_at = NOW()`,
        [saleId, req.user.id, req.user.username, emoji]
      );
    }

    const countsRes = await pool.query(
      `SELECT emoji, COUNT(*)::int AS cnt FROM artwork_reactions WHERE sale_id = $1 GROUP BY emoji`,
      [saleId]
    );
    const counts = {};
    for (const e of ALLOWED_EMOJIS) counts[e] = 0;
    for (const row of countsRes.rows) if (counts[row.emoji] !== undefined) counts[row.emoji] = row.cnt;
    const myRes = await pool.query(
      `SELECT emoji FROM artwork_reactions WHERE sale_id = $1 AND user_id = $2`,
      [saleId, req.user.id]
    );
    const myEmoji = myRes.rows[0] ? myRes.rows[0].emoji : null;
    res.json({ counts, myEmoji });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/artworks/:saleId/comments', async (req, res) => {
  const saleId = parseInt(req.params.saleId, 10);
  if (!saleId) return res.status(400).json({ error: 'Invalid saleId' });
  try {
    const { rows } = await pool.query(
      `SELECT id, user_id, username, body, created_at FROM artwork_comments WHERE sale_id = $1 ORDER BY created_at ASC`,
      [saleId]
    );
    res.json({ comments: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/artworks/:saleId/comments', async (req, res) => {
  const saleId = parseInt(req.params.saleId, 10);
  if (!saleId) return res.status(400).json({ error: 'Invalid saleId' });
  const body = String((req.body && req.body.body) || '').trim();
  if (!body) return res.status(400).json({ error: 'Comment body required' });
  if (body.length > 500) return res.status(400).json({ error: 'Comment too long (max 500 chars)' });
  try {
    const saleCheck = await pool.query(`SELECT id FROM sales WHERE id = $1`, [saleId]);
    if (!saleCheck.rows.length) return res.status(404).json({ error: 'Artwork not found' });

    const { rows } = await pool.query(
      `INSERT INTO artwork_comments (sale_id, user_id, username, body)
       VALUES ($1, $2, $3, $4)
       RETURNING id, user_id, username, body, created_at`,
      [saleId, req.user.id, req.user.username, body]
    );
    res.json({ comment: rows[0] });
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

// ── Direct Messages ───────────────────────────────────────────────────────────
// Both dm_conversations and direct_messages are staging:private — they contain
// one-to-one chat content. Canonical pair ordering: user_a_id = LEAST(a,b),
// user_b_id = GREATEST(a,b) so the UNIQUE(user_a_id, user_b_id) constraint
// deduplicates without needing both orderings.

app.get('/api/dm/conversations', async (req, res) => {
  try {
    const uid = req.user.id;
    const { rows } = await pool.query(`
      SELECT
        c.id,
        CASE WHEN c.user_a_id = $1 THEN c.user_b_id ELSE c.user_a_id END AS other_id,
        CASE WHEN c.user_a_id = $1 THEN c.user_b_username ELSE c.user_a_username END AS other_username,
        c.last_message_at,
        (
          SELECT LEFT(m.body, 100)
          FROM direct_messages m
          WHERE m.conversation_id = c.id
          ORDER BY m.created_at DESC, m.id DESC
          LIMIT 1
        ) AS last_message_body,
        (
          SELECT COUNT(*)::int
          FROM direct_messages m
          WHERE m.conversation_id = c.id AND m.sender_id != $1 AND m.read_at IS NULL
        ) AS unread_count
      FROM dm_conversations c
      WHERE c.user_a_id = $1 OR c.user_b_id = $1
      ORDER BY c.last_message_at DESC
    `, [uid]);
    res.json({ conversations: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/dm/conversations', async (req, res) => {
  const uid = req.user.id;
  const recipId = parseInt((req.body && req.body.recipient_id) || 0, 10);
  const recipUsername = String((req.body && req.body.recipient_username) || '').trim();
  if (!recipId || recipId === uid) {
    return res.status(400).json({ error: 'Invalid recipient' });
  }
  if (!recipUsername) {
    return res.status(400).json({ error: 'Missing recipient_username' });
  }
  try {
    const a_id = Math.min(uid, recipId);
    const b_id = Math.max(uid, recipId);
    const a_username = a_id === uid ? req.user.username : recipUsername;
    const b_username = b_id === uid ? req.user.username : recipUsername;

    await pool.query(`
      INSERT INTO dm_conversations (user_a_id, user_a_username, user_b_id, user_b_username)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (user_a_id, user_b_id) DO NOTHING
    `, [a_id, a_username, b_id, b_username]);

    const { rows } = await pool.query(
      `SELECT id, user_a_id, user_a_username, user_b_id, user_b_username, last_message_at, created_at
       FROM dm_conversations WHERE user_a_id = $1 AND user_b_id = $2`,
      [a_id, b_id]
    );
    res.json({ conversation: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dm/conversations/:id/messages', async (req, res) => {
  try {
    const uid = req.user.id;
    const convId = parseInt(req.params.id, 10);
    const conv = await pool.query(
      `SELECT id FROM dm_conversations WHERE id = $1 AND (user_a_id = $2 OR user_b_id = $2)`,
      [convId, uid]
    );
    if (!conv.rows.length) return res.status(403).json({ error: 'Forbidden' });

    await pool.query(
      `UPDATE direct_messages SET read_at = NOW()
       WHERE conversation_id = $1 AND sender_id != $2 AND read_at IS NULL`,
      [convId, uid]
    );

    const { rows } = await pool.query(
      `SELECT id, conversation_id, sender_id, sender_username, body, read_at, created_at
       FROM direct_messages WHERE conversation_id = $1 ORDER BY created_at ASC, id ASC`,
      [convId]
    );
    res.json({ messages: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/dm/conversations/:id/messages', async (req, res) => {
  const uid = req.user.id;
  const convId = parseInt(req.params.id, 10);
  const body = String((req.body && req.body.body) || '').trim();
  if (!body) return res.status(400).json({ error: 'Message cannot be empty' });
  try {
    const conv = await pool.query(
      `SELECT id FROM dm_conversations WHERE id = $1 AND (user_a_id = $2 OR user_b_id = $2)`,
      [convId, uid]
    );
    if (!conv.rows.length) return res.status(403).json({ error: 'Forbidden' });

    const { rows } = await pool.query(`
      INSERT INTO direct_messages (conversation_id, sender_id, sender_username, body)
      VALUES ($1, $2, $3, $4)
      RETURNING id, conversation_id, sender_id, sender_username, body, read_at, created_at
    `, [convId, uid, req.user.username, body.slice(0, 5000)]);

    await pool.query(
      `UPDATE dm_conversations SET last_message_at = NOW() WHERE id = $1`,
      [convId]
    );
    res.json({ message: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dm/unread-count', async (req, res) => {
  try {
    const uid = req.user.id;
    const { rows } = await pool.query(`
      SELECT COUNT(*)::int AS count
      FROM direct_messages dm
      JOIN dm_conversations c ON c.id = dm.conversation_id
      WHERE (c.user_a_id = $1 OR c.user_b_id = $1)
        AND dm.sender_id != $1
        AND dm.read_at IS NULL
    `, [uid]);
    res.json({ count: rows[0].count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Collections ──────────────────────────────────────────────────────────────
app.get('/api/collections', async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        c.id, c.user_id, c.username, c.title, c.description, c.created_at,
        COUNT(ci.id)::int AS item_count
      FROM collections c
      LEFT JOIN collection_items ci ON ci.collection_id = c.id
      GROUP BY c.id
      ORDER BY c.created_at DESC
    `);
    res.json({ collections: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/collections', async (req, res) => {
  const title = String((req.body && req.body.title) || '').trim();
  const description = String((req.body && req.body.description) || '').trim();
  if (!title) return res.status(400).json({ error: 'Title is required' });
  try {
    const { rows } = await pool.query(`
      INSERT INTO collections (user_id, username, title, description)
      VALUES ($1, $2, $3, $4)
      RETURNING id, user_id, username, title, description, created_at
    `, [req.user.id, req.user.username, title.slice(0, 255), description.slice(0, 2000) || null]);
    res.json({ collection: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/collections/:id', async (req, res) => {
  try {
    const collRes = await pool.query(
      `SELECT id, user_id, username, title, description, created_at FROM collections WHERE id = $1`,
      [req.params.id]
    );
    if (!collRes.rows.length) return res.status(404).json({ error: 'Collection not found' });
    const itemRes = await pool.query(
      `SELECT id, sale_id, work_title, artist_username, position, added_at
       FROM collection_items WHERE collection_id = $1 ORDER BY position ASC, id ASC`,
      [req.params.id]
    );
    res.json({ collection: collRes.rows[0], items: itemRes.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/collections/:id/items', async (req, res) => {
  const saleId = parseInt((req.body && req.body.sale_id) || 0, 10);
  if (!saleId) return res.status(400).json({ error: 'sale_id is required' });
  try {
    const collRes = await pool.query(
      `SELECT id, user_id FROM collections WHERE id = $1`, [req.params.id]
    );
    if (!collRes.rows.length) return res.status(404).json({ error: 'Collection not found' });
    if (collRes.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });

    const countRes = await pool.query(
      `SELECT COUNT(*)::int AS n FROM collection_items WHERE collection_id = $1`, [req.params.id]
    );
    if (countRes.rows[0].n >= 20) return res.status(400).json({ error: 'Collections are limited to 20 works' });

    const saleRes = await pool.query(
      `SELECT id, title, username FROM sales WHERE id = $1`, [saleId]
    );
    if (!saleRes.rows.length) return res.status(404).json({ error: 'Work not found' });

    const posRes = await pool.query(
      `SELECT COALESCE(MAX(position), 0) + 1 AS next_pos FROM collection_items WHERE collection_id = $1`, [req.params.id]
    );
    const nextPos = posRes.rows[0].next_pos;

    const { rows } = await pool.query(`
      INSERT INTO collection_items (collection_id, sale_id, work_title, artist_username, position)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (collection_id, sale_id) DO NOTHING
      RETURNING id, sale_id, work_title, artist_username, position, added_at
    `, [req.params.id, saleId, saleRes.rows[0].title.slice(0, 255), saleRes.rows[0].username, nextPos]);

    if (!rows.length) return res.status(409).json({ error: 'This work is already in the collection' });
    res.json({ item: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/collections/:id/items/:itemId', async (req, res) => {
  try {
    const collRes = await pool.query(
      `SELECT user_id FROM collections WHERE id = $1`, [req.params.id]
    );
    if (!collRes.rows.length) return res.status(404).json({ error: 'Collection not found' });
    if (collRes.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    await pool.query(
      `DELETE FROM collection_items WHERE id = $1 AND collection_id = $2`,
      [req.params.itemId, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/collections/:id', async (req, res) => {
  try {
    const collRes = await pool.query(
      `SELECT user_id FROM collections WHERE id = $1`, [req.params.id]
    );
    if (!collRes.rows.length) return res.status(404).json({ error: 'Collection not found' });
    if (collRes.rows[0].user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    await pool.query(`DELETE FROM collection_items WHERE collection_id = $1`, [req.params.id]);
    await pool.query(`DELETE FROM collections WHERE id = $1`, [req.params.id]);
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
  // has_seen_welcome: tracks whether the artist has seen the one-time welcome
  // panel shown after their first enrolment. Backfill TRUE for all existing
  // rows so pre-deploy members are not shown a retroactive welcome panel.
  await pool.query(`ALTER TABLE enrolments ADD COLUMN IF NOT EXISTS has_seen_welcome BOOLEAN NOT NULL DEFAULT FALSE`);
  await pool.query(`UPDATE enrolments SET has_seen_welcome = TRUE WHERE has_seen_welcome = FALSE`);
  // bio: free-text artist introduction shown on the public profile page. Public
  // profile content (enrolments stays public — no staging:private comment), so
  // no public→private FK is introduced.
  await pool.query(`ALTER TABLE enrolments ADD COLUMN IF NOT EXISTS bio TEXT`);

  // Follows: social graph (who-follows-whom). Public — this is in-app-visible
  // content like the ownership roster and forum, not sensitive, so NO
  // 'staging:private' comment. usernames are denormalized (mirroring votes /
  // forum / dm tables); there is no FK to a private table, so the public→private
  // FK linter rule is satisfied (the feed reads sales via a query-time JOIN).
  // UNIQUE(follower_id, followee_id) makes a follow idempotent; the CHECK blocks
  // self-follows.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS follows (
      id SERIAL PRIMARY KEY,
      follower_id INTEGER NOT NULL,
      follower_username VARCHAR(255) NOT NULL,
      followee_id INTEGER NOT NULL,
      followee_username VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (follower_id, followee_id),
      CHECK (follower_id <> followee_id)
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS follows_follower_idx ON follows (follower_id)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS follows_followee_idx ON follows (followee_id)`);

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

  // Direct messages: private (1:1 chats between members). Both tables marked
  // staging:private so row content never leaks into PR staging containers.
  // direct_messages → dm_conversations is a private→private FK, which is
  // permitted (the linter only blocks public→private FKs).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dm_conversations (
      id SERIAL PRIMARY KEY,
      user_a_id INTEGER NOT NULL,
      user_a_username VARCHAR(255) NOT NULL,
      user_b_id INTEGER NOT NULL,
      user_b_username VARCHAR(255) NOT NULL,
      last_message_at TIMESTAMPTZ DEFAULT NOW(),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_a_id, user_b_id)
    )
  `);
  await pool.query(`COMMENT ON TABLE dm_conversations IS 'staging:private'`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS direct_messages (
      id SERIAL PRIMARY KEY,
      conversation_id INTEGER NOT NULL REFERENCES dm_conversations(id),
      sender_id INTEGER NOT NULL,
      sender_username VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      read_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`COMMENT ON TABLE direct_messages IS 'staging:private'`);

  // Artwork reactions: emoji reactions on individual artworks (sales rows).
  // Public — community-facing engagement data, no sensitive content.
  // No FK to sales because sales is staging:private (public→private FK is not allowed).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS artwork_reactions (
      id SERIAL PRIMARY KEY,
      sale_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      emoji VARCHAR(10) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (sale_id, user_id)
    )
  `);

  // Artwork comments: text comments on individual artworks (sales rows).
  // Public — community discussion, no sensitive content.
  // No FK to sales for the same reason as artwork_reactions.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS artwork_comments (
      id SERIAL PRIMARY KEY,
      sale_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Platform settings: single-row table (id always 1) governing the displayed /
  // applied platform fee via the Fee Split proposal. Public — product config, no
  // per-user/financial/personal data, no FK to a private table. fee_percent is
  // the current fee, proposed_fee is what a passing Fee Split vote sets it to,
  // fee_proposal_id points at the governing proposal, and status is a sticky
  // outcome ('open' | 'passed' | 'failed'). No blockchain involved.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS platform_settings (
      id INTEGER PRIMARY KEY,
      fee_percent INTEGER NOT NULL DEFAULT 20,
      proposed_fee INTEGER NOT NULL DEFAULT 15,
      fee_proposal_id INTEGER,
      status TEXT NOT NULL DEFAULT 'open'
    )
  `);

  // Collections: public showcase content — no financial data, no private FKs.
  // collection_items stores sale_id as a plain integer (no FK constraint) to
  // avoid a public→private FK to the staging:private sales table.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS collections (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS collection_items (
      id SERIAL PRIMARY KEY,
      collection_id INTEGER NOT NULL REFERENCES collections(id),
      sale_id INTEGER NOT NULL,
      work_title VARCHAR(255) NOT NULL,
      artist_username VARCHAR(255) NOT NULL,
      position INTEGER NOT NULL DEFAULT 0,
      added_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (collection_id, sale_id)
    )
  `);

  // ── Governance proposals seed ───────────────────────────────────────────────
  // Internally votes use direction 'for'/'against' (Yes=for, No=against) — only
  // the labels change in the UI — so the existing vote endpoint and on-chain
  // memo are reused unchanged.
  //
  // The two old fee proposals ('Set the platform fee to 20%/30%') are replaced
  // by a single consolidated Fee Split proposal (id 1) that actually governs the
  // displayed fee via platform_settings + evaluateFeeOutcome().
  //
  // Re-run-safe migration (runs in all environments — these are product content
  // with no prior prod data, like the original seed):
  //   1. Retire by TITLE the legacy proposal and the two old fee proposals,
  //      deleting their votes first. Keyed on title (never a bare id) so once
  //      the new proposal #1 exists with its own title, later boots delete
  //      nothing and accumulated votes on it are preserved.
  //   2. Insert the proposals at fixed ids with ON CONFLICT DO NOTHING, so
  //      later boots are no-ops and accumulated votes are preserved.
  //   3. Bump the serial sequence past the explicit ids (belt-and-suspenders;
  //      nothing inserts proposals via the API today).
  const FEE_PROPOSAL_ID = 1;
  const RETIRED_TITLES = [
    'Fee Split Adjustment',
    'Set the platform fee to 20%',
    'Set the platform fee to 30%',
  ];
  await pool.query(
    `DELETE FROM votes WHERE proposal_id IN (SELECT id FROM governance_proposals WHERE title = ANY($1))`,
    [RETIRED_TITLES]
  );
  await pool.query(`DELETE FROM governance_proposals WHERE title = ANY($1)`, [RETIRED_TITLES]);

  const seededProposals = [
    [FEE_PROPOSAL_ID, 'Fee Split — lower the platform fee from 20% to 15%',
      "Cut the gallery's cut on every sale from 20% to 15%, so artists keep more of each sale. If this passes, the platform fee updates to 15% for all new sales."],
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

  // Seed the single platform_settings row (all environments). Current fee 20%,
  // a passing Fee Split vote sets it to 15%. ON CONFLICT DO NOTHING preserves a
  // decided outcome across redeploys. fee_proposal_id ties it to the Fee Split
  // proposal so the vote endpoint knows when to re-evaluate.
  await pool.query(`
    INSERT INTO platform_settings (id, fee_percent, proposed_fee, fee_proposal_id, status)
    VALUES (1, 20, 15, $1, 'open')
    ON CONFLICT (id) DO NOTHING
  `, [FEE_PROPOSAL_ID]);

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
      // Proposal 1 — Fee Split (20% → 15%): 4 Yes / 1 No → meets quorum (4) with
      // a Yes majority, so evaluateFeeOutcome() flips it to passed and the
      // displayed fee updates to 15% in the demo.
      [1, 9001, 'staging-artist-1', 'for'],
      [1, 9002, 'staging-artist-2', 'for'],
      [1, 9003, 'staging-artist-3', 'for'],
      [1, 9005, 'staging-artist-5', 'for'],
      [1, 9004, 'staging-artist-4', 'against'],
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

    // Seed bios on the demo artists so their profile pages render populated.
    const mockBios = [
      [9001, 'Staging demo — Painter of coastal light and slow tides. Mostly oils.'],
      [9002, 'Staging demo — Abstract colourist exploring blues and greens.'],
      [9003, 'Staging demo — Printmaker and illustrator; loves a newcomers wall.'],
      [9004, 'Staging demo — Sculptor working in reclaimed materials.'],
    ];
    for (const [uid, bio] of mockBios) {
      await pool.query(`UPDATE enrolments SET bio = $1 WHERE user_id = $2`, [bio, uid]);
    }

    // Seed a few sales so Treasury / Your sales / stats render populated.
    // staging-artist-1 (9001) gets three; artists 2 and 3 get works too so more
    // than one profile gallery renders populated in staging.
    const mockSales = [
      [900001, 9001, 'staging-artist-1', 'ut1stg1abc', 'Staging demo — Autumn Light #1', 450, 45],
      [900002, 9001, 'staging-artist-1', 'ut1stg1abc', 'Staging demo — Blue Resonance #7', 280, 28],
      [900003, 9001, 'staging-artist-1', 'ut1stg1abc', 'Staging demo — Quiet Tide #3', 620, 62],
      [900004, 9002, 'staging-artist-2', 'ut1stg2def', 'Staging demo — Green Field Study', 320, 32],
      [900005, 9002, 'staging-artist-2', 'ut1stg2def', 'Staging demo — Cerulean Drift', 540, 54],
      [900006, 9003, 'staging-artist-3', 'ut1stg3ghi', 'Staging demo — Newcomers Print I', 200, 20],
    ];
    for (const [id, uid, uname, addr, title, amount, fee] of mockSales) {
      await pool.query(`
        INSERT INTO sales (id, user_id, username, seller_addr, title, amount, fee)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (id) DO NOTHING
      `, [id, uid, uname, addr, title, amount, fee]);
    }

    // Seed follow edges among the demo artists so follower/following counts and
    // lists render populated on their profiles. follows is a newly-created table
    // (empty in staging). Fixed ids + ON CONFLICT DO NOTHING keep it idempotent.
    // [id, follower_id, follower_username, followee_id, followee_username]
    const mockFollows = [
      [900001, 9001, 'staging-artist-1', 9002, 'staging-artist-2'],
      [900002, 9001, 'staging-artist-1', 9003, 'staging-artist-3'],
      [900003, 9002, 'staging-artist-2', 9001, 'staging-artist-1'],
      [900004, 9003, 'staging-artist-3', 9001, 'staging-artist-1'],
      [900005, 9003, 'staging-artist-3', 9004, 'staging-artist-4'],
      [900006, 9004, 'staging-artist-4', 9001, 'staging-artist-1'],
    ];
    for (const [id, fId, fName, tId, tName] of mockFollows) {
      await pool.query(`
        INSERT INTO follows (id, follower_id, follower_username, followee_id, followee_username)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (follower_id, followee_id) DO NOTHING
      `, [id, fId, fName, tId, tName]);
    }
    await pool.query(`SELECT setval(pg_get_serial_sequence('follows', 'id'), GREATEST((SELECT MAX(id) FROM follows), 1))`);

    // Seed DM conversations and messages (both tables are staging:private — empty in staging).
    // Two conversations for staging-artist-1 (uid 9001) so the Messages tab
    // renders populated. Message 900003 is intentionally unread to show the badge.
    const mockDmConvs = [
      [900001, 9001, 'staging-artist-1', 9002, 'staging-artist-2'],
      [900002, 9001, 'staging-artist-1', 9003, 'staging-artist-3'],
    ];
    for (const [id, a_id, a_uname, b_id, b_uname] of mockDmConvs) {
      await pool.query(`
        INSERT INTO dm_conversations (id, user_a_id, user_a_username, user_b_id, user_b_username)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (id) DO NOTHING
      `, [id, a_id, a_uname, b_id, b_uname]);
    }
    // [id, conv_id, sender_id, sender_username, body, isRead]
    const mockDmMsgs = [
      [900001, 900001, 9002, 'staging-artist-2', 'Staging demo — Love the colour palette in your recent piece', true],
      [900002, 900001, 9001, 'staging-artist-1', 'Staging demo — Thank you! Working on a new series', true],
      [900003, 900001, 9002, 'staging-artist-2', 'Staging demo — Would you be open to a collaboration?', false],
      [900004, 900002, 9001, 'staging-artist-1', 'Staging demo — Saw your proposal about the marketing budget', true],
      [900005, 900002, 9003, 'staging-artist-3', 'Staging demo — Yes, happy to discuss further', true],
    ];
    for (const [id, conv_id, sender_id, sender_username, body, isRead] of mockDmMsgs) {
      await pool.query(`
        INSERT INTO direct_messages (id, conversation_id, sender_id, sender_username, body, read_at)
        VALUES ($1, $2, $3, $4, $5, CASE WHEN $6 THEN NOW() ELSE NULL END)
        ON CONFLICT (id) DO NOTHING
      `, [id, conv_id, sender_id, sender_username, body, isRead]);
    }
    await pool.query(`SELECT setval(pg_get_serial_sequence('dm_conversations', 'id'), GREATEST((SELECT MAX(id) FROM dm_conversations), 1))`);
    await pool.query(`SELECT setval(pg_get_serial_sequence('direct_messages', 'id'), GREATEST((SELECT MAX(id) FROM direct_messages), 1))`);
    await pool.query(`SELECT setval(pg_get_serial_sequence('sales', 'id'), GREATEST((SELECT MAX(id) FROM sales), 1))`);

    // Seed artwork reactions across the demo sales so the reaction bar renders
    // with non-zero counts in staging (artwork_reactions is a new table, empty).
    const mockReactions = [
      [900001, 9001, 'staging-artist-1', '❤️'],
      [900001, 9002, 'staging-artist-2', '❤️'],
      [900001, 9003, 'staging-artist-3', '✨'],
      [900002, 9001, 'staging-artist-1', '🔥'],
      [900002, 9004, 'staging-artist-4', '🔥'],
      [900003, 9002, 'staging-artist-2', '👏'],
      [900003, 9003, 'staging-artist-3', '🎨'],
      [900003, 9004, 'staging-artist-4', '❤️'],
      [900004, 9001, 'staging-artist-1', '✨'],
      [900005, 9003, 'staging-artist-3', '🔥'],
    ];
    for (const [sale_id, uid, uname, emoji] of mockReactions) {
      await pool.query(`
        INSERT INTO artwork_reactions (sale_id, user_id, username, emoji)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (sale_id, user_id) DO NOTHING
      `, [sale_id, uid, uname, emoji]);
    }

    // Seed artwork comments on the demo sales (artwork_comments is a new table, empty).
    const mockComments = [
      [900001, 9001, 'staging-artist-1', 900002, 'Staging demo — Absolutely love the warm tones in this one.'],
      [900002, 9002, 'staging-artist-2', 900001, 'Staging demo — The composition here is stunning.'],
      [900003, 9003, 'staging-artist-3', 900001, 'Staging demo — Always admired your use of coastal light.'],
      [900004, 9004, 'staging-artist-4', 900003, 'Staging demo — This palette reminds me of early morning tide.'],
      [900005, 9001, 'staging-artist-1', 900004, 'Staging demo — Beautiful field study — so much energy in the greens.'],
    ];
    for (const [id, uid, uname, sale_id, body] of mockComments) {
      await pool.query(`
        INSERT INTO artwork_comments (id, sale_id, user_id, username, body)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (id) DO NOTHING
      `, [id, sale_id, uid, uname, body]);
    }
    await pool.query(`SELECT setval(pg_get_serial_sequence('artwork_comments', 'id'), GREATEST((SELECT MAX(id) FROM artwork_comments), 1))`);

    // Seed collections. Both tables are newly-created (empty in staging).
    // Titles and artist_usernames are copied directly — not read from the
    // staging:private sales table — so the seed is self-contained.
    const mockCollections = [
      [900001, 9001, 'staging-artist-1', 'Staging demo — Coastal Studies', 'A selection of works exploring light on water.'],
      [900002, 9002, 'staging-artist-2', 'Staging demo — Colour Field Picks', 'Blues, greens, and the space between.'],
    ];
    for (const [id, uid, uname, title, description] of mockCollections) {
      await pool.query(`
        INSERT INTO collections (id, user_id, username, title, description)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (id) DO NOTHING
      `, [id, uid, uname, title, description]);
    }
    const mockCollectionItems = [
      [900001, 900001, 900001, 'Staging demo — Autumn Light #1', 'staging-artist-1', 1],
      [900002, 900001, 900002, 'Staging demo — Blue Resonance #7', 'staging-artist-1', 2],
      [900003, 900001, 900006, 'Staging demo — Newcomers Print I', 'staging-artist-3', 3],
      [900004, 900002, 900004, 'Staging demo — Green Field Study', 'staging-artist-2', 1],
      [900005, 900002, 900005, 'Staging demo — Cerulean Drift', 'staging-artist-2', 2],
    ];
    for (const [id, collId, saleId, workTitle, artistUsername, position] of mockCollectionItems) {
      await pool.query(`
        INSERT INTO collection_items (id, collection_id, sale_id, work_title, artist_username, position)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT DO NOTHING
      `, [id, collId, saleId, workTitle, artistUsername, position]);
    }
    await pool.query(`SELECT setval(pg_get_serial_sequence('collections', 'id'), GREATEST((SELECT MAX(id) FROM collections), 1))`);
    await pool.query(`SELECT setval(pg_get_serial_sequence('collection_items', 'id'), GREATEST((SELECT MAX(id) FROM collection_items), 1))`);

    // Resolve the Fee Split outcome from the seeded votes so the demo (/?demo=1)
    // shows the passed state: fee updated to 15%, badge "Passed — fee updated to 15%".
    await evaluateFeeOutcome();
  }

  app.listen(port, () => console.log(`Listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
