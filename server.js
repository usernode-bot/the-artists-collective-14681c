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
const VOTE_QUORUM = 4; // minimum total votes before any proposal outcome is decided

// Tally a single proposal's votes. Returns { forCount, againstCount, total }.
async function tallyProposal(proposalId) {
  const tallyRes = await pool.query(
    `SELECT
       COALESCE(SUM(CASE WHEN direction = 'for' THEN 1 ELSE 0 END), 0)::int AS for_count,
       COALESCE(SUM(CASE WHEN direction = 'against' THEN 1 ELSE 0 END), 0)::int AS against_count
     FROM votes WHERE proposal_id = $1`,
    [proposalId]
  );
  const forCount = tallyRes.rows[0].for_count;
  const againstCount = tallyRes.rows[0].against_count;
  return { forCount, againstCount, total: forCount + againstCount };
}

// Recompute the fee outcome from the live vote tally. Only acts while status is
// still 'open'; once 'passed'/'failed' it early-returns, making the result
// persistent. On a pass, the proposed fee becomes the current fee. This handles
// only the Fee Split proposal's extra side-effect on platform_settings;
// per-proposal status lives on governance_proposals (see evaluateProposalOutcome).
async function evaluateFeeOutcome() {
  const settingsRes = await pool.query(
    `SELECT fee_proposal_id, proposed_fee, status FROM platform_settings WHERE id = 1`
  );
  if (!settingsRes.rows.length) return;
  const s = settingsRes.rows[0];
  if (s.status !== 'open' || !s.fee_proposal_id) return;

  const { forCount, againstCount, total } = await tallyProposal(s.fee_proposal_id);
  if (total < VOTE_QUORUM) return; // not enough participation yet — stays open

  if (forCount > againstCount) {
    await pool.query(
      `UPDATE platform_settings SET status = 'passed', fee_percent = proposed_fee WHERE id = 1`
    );
  } else {
    await pool.query(`UPDATE platform_settings SET status = 'failed' WHERE id = 1`);
  }
}

// Generic per-proposal outcome evaluator. Mirrors the Fee Split rule for ALL
// governance proposals: once a proposal reaches VOTE_QUORUM total votes it is
// decided — 'passed' when Yes (for) outnumber No (against), else 'failed' — and
// the result is sticky (early-returns once status is no longer 'open'). For the
// proposal that governs the platform fee, also runs evaluateFeeOutcome() so the
// fee→15% side-effect and the top fee badge keep working unchanged.
async function evaluateProposalOutcome(proposalId) {
  const propRes = await pool.query(
    `SELECT status FROM governance_proposals WHERE id = $1`,
    [proposalId]
  );
  if (!propRes.rows.length) return;
  if (propRes.rows[0].status !== 'open') return; // sticky once decided

  const { forCount, againstCount, total } = await tallyProposal(proposalId);
  if (total < VOTE_QUORUM) return; // not enough participation yet — stays open

  const outcome = forCount > againstCount ? 'passed' : 'failed';
  await pool.query(
    `UPDATE governance_proposals SET status = $1 WHERE id = $2`,
    [outcome, proposalId]
  );

  // Fee Split proposal carries the extra platform_settings side-effect.
  const feeRes = await pool.query(`SELECT fee_proposal_id FROM platform_settings WHERE id = 1`);
  if (feeRes.rows.length && feeRes.rows[0].fee_proposal_id === Number(proposalId)) {
    await evaluateFeeOutcome();
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
        p.id, p.title, p.description, p.status, p.created_at,
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
    // Re-evaluate this proposal's outcome (sticky once decided). For the Fee
    // Split proposal this also applies the fee→15% side-effect internally.
    await evaluateProposalOutcome(Number(proposal_id));
    res.json({ ok: true, direction });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Best-effort on-chain receipt for a vote (mirrors /api/sales/:id/tx). The vote
// itself is already recorded in the DB; this just records the confirmed tx hash
// of the governance-address send. Never surfaced in the Ledger.
app.post('/api/votes/:proposal_id/tx', async (req, res) => {
  const { tx_hash } = req.body || {};
  try {
    await pool.query(
      `UPDATE votes SET tx_hash = $1 WHERE proposal_id = $2 AND user_id = $3`,
      [tx_hash || null, req.params.proposal_id, req.user.id]
    );
    res.json({ ok: true });
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

// ── Weekly Art Challenge (public gallery; pure DB-backed, no on-chain
//    component — mirrors the Forum feature's shape). ──────────────────────────
// The active theme rotates automatically once a week, deterministically from
// the calendar date, so it behaves identically in staging and production (no
// admin role exists anywhere in this app yet — see challenge_prompts comment
// in start()).
function currentWeekInfo() {
  var now = new Date();
  var utcDate = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()));
  // ISO week number: shift to the Thursday of this week, then count weeks
  // from that ISO year's January 1st.
  var isoDate = new Date(utcDate);
  var isoDayNum = isoDate.getUTCDay() || 7; // Monday=1 .. Sunday=7
  isoDate.setUTCDate(isoDate.getUTCDate() + 4 - isoDayNum);
  var isoYear = isoDate.getUTCFullYear();
  var yearStart = new Date(Date.UTC(isoYear, 0, 1));
  var weekNo = Math.ceil((((isoDate - yearStart) / 86400000) + 1) / 7);
  var yearWeek = isoYear + '-W' + String(weekNo).padStart(2, '0');

  // Monday..Sunday of the calendar week containing `now` (for display only).
  var dayNum = utcDate.getUTCDay() || 7;
  var monday = new Date(utcDate);
  monday.setUTCDate(utcDate.getUTCDate() - dayNum + 1);
  var sunday = new Date(monday);
  sunday.setUTCDate(monday.getUTCDate() + 6);

  return {
    yearWeek: yearWeek,
    weekIndex: isoYear * 53 + weekNo, // monotonic-enough key for prompt rotation
    weekStart: monday.toISOString().slice(0, 10),
    weekEnd: sunday.toISOString().slice(0, 10),
  };
}

// Get-or-create this week's challenge row. Pure function of the current date
// plus the seeded prompt pool, so it's identical in staging and production.
async function getOrCreateCurrentChallenge() {
  const info = currentWeekInfo();
  const existing = await pool.query(
    `SELECT id, year_week, theme, week_start, week_end, created_at FROM weekly_challenges WHERE year_week = $1`,
    [info.yearWeek]
  );
  if (existing.rows.length) return existing.rows[0];

  const countRes = await pool.query(`SELECT COUNT(*)::int AS n FROM challenge_prompts`);
  const n = countRes.rows[0].n || 1;
  const promptIdx = ((info.weekIndex % n) + n) % n;
  const promptRes = await pool.query(
    `SELECT id, theme FROM challenge_prompts ORDER BY sort_order ASC LIMIT 1 OFFSET $1`,
    [promptIdx]
  );
  const prompt = promptRes.rows[0] || null;

  await pool.query(`
    INSERT INTO weekly_challenges (year_week, prompt_id, theme, week_start, week_end)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (year_week) DO NOTHING
  `, [info.yearWeek, prompt ? prompt.id : null, prompt ? prompt.theme : 'Open theme', info.weekStart, info.weekEnd]);

  const rows = await pool.query(
    `SELECT id, year_week, theme, week_start, week_end, created_at FROM weekly_challenges WHERE year_week = $1`,
    [info.yearWeek]
  );
  return rows.rows[0];
}

app.get('/api/challenges/current', async (req, res) => {
  try {
    const challenge = await getOrCreateCurrentChallenge();
    const subsRes = await pool.query(`
      SELECT
        s.id, s.challenge_id, s.user_id, s.username, s.image_url, s.caption, s.created_at,
        COUNT(l.id)::int AS like_count,
        BOOL_OR(l.user_id = $2) AS liked_by_me
      FROM challenge_submissions s
      LEFT JOIN challenge_likes l ON l.submission_id = s.id
      WHERE s.challenge_id = $1
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `, [challenge.id, req.user.id]);
    const mySubmission = subsRes.rows.find((r) => r.user_id === req.user.id) || null;
    res.json({ challenge, submissions: subsRes.rows, my_submission: mySubmission });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/challenges/current/submissions', async (req, res) => {
  const imageUrl = String((req.body && req.body.image_url) || '').trim();
  const caption = String((req.body && req.body.caption) || '').trim();
  if (!/^https?:\/\//i.test(imageUrl)) {
    return res.status(400).json({ error: 'Please provide an image URL starting with http:// or https://' });
  }
  try {
    const challenge = await getOrCreateCurrentChallenge();
    const { rows } = await pool.query(`
      INSERT INTO challenge_submissions (challenge_id, user_id, username, image_url, caption)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (challenge_id, user_id) DO NOTHING
      RETURNING id, challenge_id, user_id, username, image_url, caption, created_at
    `, [challenge.id, req.user.id, req.user.username, imageUrl.slice(0, 2048), caption.slice(0, 280) || null]);
    if (!rows.length) {
      return res.status(409).json({ error: "You've already submitted this week" });
    }
    res.json({ submission: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/submissions/:id/likes', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO challenge_likes (submission_id, user_id, username)
      VALUES ($1, $2, $3)
      ON CONFLICT (submission_id, user_id) DO NOTHING
    `, [req.params.id, req.user.id, req.user.username]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/submissions/:id/likes', async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM challenge_likes WHERE submission_id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );
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
  // Per-proposal sticky outcome: 'open' until VOTE_QUORUM votes decide it,
  // then 'passed' / 'failed'. Single source of truth for every proposal's
  // result (the Fee Split proposal additionally mirrors into platform_settings).
  await pool.query(`ALTER TABLE governance_proposals ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open'`);

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
  // Best-effort on-chain receipt of the governance-address vote send.
  await pool.query(`ALTER TABLE votes ADD COLUMN IF NOT EXISTS tx_hash VARCHAR(255)`);

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

  // Weekly Art Challenge: public tables (community content, like forum_threads/
  // forum_replies above) — no admin role exists anywhere in this app, so the
  // active theme rotates deterministically from the calendar date instead of
  // being created through a UI (see getOrCreateCurrentChallenge()).
  await pool.query(`
    CREATE TABLE IF NOT EXISTS challenge_prompts (
      id SERIAL PRIMARY KEY,
      theme VARCHAR(255) NOT NULL,
      sort_order INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS weekly_challenges (
      id SERIAL PRIMARY KEY,
      year_week VARCHAR(10) NOT NULL UNIQUE,
      prompt_id INTEGER REFERENCES challenge_prompts(id),
      theme VARCHAR(255) NOT NULL,
      week_start DATE,
      week_end DATE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS challenge_submissions (
      id SERIAL PRIMARY KEY,
      challenge_id INTEGER NOT NULL REFERENCES weekly_challenges(id),
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      image_url TEXT NOT NULL,
      caption VARCHAR(280),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (challenge_id, user_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS challenge_likes (
      id SERIAL PRIMARY KEY,
      submission_id INTEGER NOT NULL REFERENCES challenge_submissions(id),
      user_id INTEGER NOT NULL,
      username VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (submission_id, user_id)
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

  // ── Staging-only proposal presence guarantee ────────────────────────────────
  // The dashboard's Governance cards are DB-backed for their title/description
  // (counts + badges come from the live on-chain ledger-governance feed). The
  // product seed above already inserts proposals 1/3/4/5/6 in every environment,
  // so this block is normally a no-op (ON CONFLICT DO NOTHING). It exists so the
  // title display + "confirming…" flow stay exercisable in a freshly-emptied
  // staging DB even if the product seed is ever trimmed — using obviously-fake
  // "Staging demo …" titles that only surface when no real row claims the id.
  if (IS_STAGING) {
    const stagingDemoProposals = [
      [FEE_PROPOSAL_ID, 'Staging demo — Fee Split: lower the platform fee from 20% to 15%',
        'Staging demo proposal. Cut the gallery fee on every sale from 20% to 15%.'],
      [3, 'Staging demo — Allocate 40% of the treasury to marketing & reach',
        'Staging demo proposal. Commit 40% of the treasury to advertising and growth.'],
      [4, 'Staging demo — Introduce a 2% artist dividend from each sale',
        'Staging demo proposal. Pay every enrolled artist a 2% dividend from each sale.'],
      [5, 'Staging demo — Feature one rising artist on the homepage each week',
        'Staging demo proposal. Spotlight a different emerging member weekly.'],
      [6, 'Staging demo — Open the collective to outside collectors as non-voting members',
        'Staging demo proposal. Let outside collectors join without a governance vote.'],
    ];
    for (const [id, title, description] of stagingDemoProposals) {
      await pool.query(`
        INSERT INTO governance_proposals (id, title, description)
        VALUES ($1, $2, $3)
        ON CONFLICT (id) DO NOTHING
      `, [id, title, description]);
    }
  }

  // Boot-time back-fill (all environments): decide any proposal that already
  // sits at/above quorum so its badge renders without waiting for a new vote.
  // Sticky, so this is idempotent across reboots.
  {
    const { rows: allProps } = await pool.query(`SELECT id FROM governance_proposals`);
    for (const { id } of allProps) {
      await evaluateProposalOutcome(id);
    }
  }

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

  // ── Weekly Art Challenge prompt pool seed ───────────────────────────────────
  // Seeded in all environments (product content, like the forum seed above).
  // The active week's theme is picked from this pool by getOrCreateCurrentChallenge()
  // using a deterministic index derived from the ISO week number, so the
  // rotation needs no admin UI and behaves identically in staging/production.
  const seededPrompts = [
    [1, 'Autumn light', 1],
    [2, 'One color, many moods', 2],
    [3, 'A quiet corner', 3],
    [4, 'Movement and blur', 4],
    [5, 'Texture study', 5],
    [6, 'Night', 6],
    [7, 'Reflections', 7],
    [8, 'The unfinished', 8],
    [9, 'Scale — very small or very large', 9],
    [10, 'Contrast', 10],
    [11, "A place you've never been", 11],
    [12, 'Portraits of things, not people', 12],
  ];
  for (const [id, theme, sortOrder] of seededPrompts) {
    await pool.query(`
      INSERT INTO challenge_prompts (id, theme, sort_order)
      VALUES ($1, $2, $3)
      ON CONFLICT (id) DO NOTHING
    `, [id, theme, sortOrder]);
  }
  await pool.query(`SELECT setval(pg_get_serial_sequence('challenge_prompts', 'id'), GREATEST((SELECT MAX(id) FROM challenge_prompts), 1))`);

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
      // Proposal 6 — open to outside collectors: reaches quorum (4) with a No
      // majority (1 Yes / 3 No) → decides as failed → "Not passed" badge.
      [6, 9001, 'staging-artist-1', 'against'],
      [6, 9003, 'staging-artist-3', 'against'],
      [6, 9004, 'staging-artist-4', 'for'],
      [6, 9005, 'staging-artist-5', 'against'],
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

    // Seed this week's challenge submissions + likes so the gallery renders
    // populated. challenge_submissions uses ON CONFLICT ... DO UPDATE (not DO
    // NOTHING) so that when the ISO week rolls over across staging rebuilds,
    // these fixed-id demo rows get re-attached to the new current week's
    // challenge_id instead of pointing at a past week.
    const currentChallenge = await getOrCreateCurrentChallenge();
    const mockSubmissions = [
      [900001, currentChallenge.id, 9001, 'staging-artist-1', 'https://placehold.co/600x400/png?text=Staging+demo+1', 'Staging demo — chasing the last of the golden hour'],
      [900002, currentChallenge.id, 9002, 'staging-artist-2', 'https://placehold.co/600x400/png?text=Staging+demo+2', 'Staging demo — moody blues for the theme'],
      [900003, currentChallenge.id, 9003, 'staging-artist-3', 'https://placehold.co/600x400/png?text=Staging+demo+3', 'Staging demo — first attempt, feedback welcome'],
      [900004, currentChallenge.id, 9004, 'staging-artist-4', 'https://placehold.co/600x400/png?text=Staging+demo+4', 'Staging demo — a quick sketch tonight'],
    ];
    for (const [id, challengeId, uid, uname, imageUrl, caption] of mockSubmissions) {
      await pool.query(`
        INSERT INTO challenge_submissions (id, challenge_id, user_id, username, image_url, caption)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO UPDATE SET challenge_id = EXCLUDED.challenge_id
      `, [id, challengeId, uid, uname, imageUrl, caption]);
    }
    const mockLikes = [
      [900001, 900001, 9002, 'staging-artist-2'],
      [900002, 900001, 9003, 'staging-artist-3'],
      [900003, 900001, 9004, 'staging-artist-4'],
      [900004, 900002, 9001, 'staging-artist-1'],
      [900005, 900003, 9001, 'staging-artist-1'],
      [900006, 900003, 9002, 'staging-artist-2'],
    ];
    for (const [id, submissionId, uid, uname] of mockLikes) {
      await pool.query(`
        INSERT INTO challenge_likes (id, submission_id, user_id, username)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO NOTHING
      `, [id, submissionId, uid, uname]);
    }
    await pool.query(`SELECT setval(pg_get_serial_sequence('challenge_submissions', 'id'), GREATEST((SELECT MAX(id) FROM challenge_submissions), 1))`);
    await pool.query(`SELECT setval(pg_get_serial_sequence('challenge_likes', 'id'), GREATEST((SELECT MAX(id) FROM challenge_likes), 1))`);

    // Resolve every proposal's outcome from the seeded votes so the demo
    // (/?demo=1) shows a mix of badges: Fee Split (#1) and dividend (#4) Passed
    // (Fee Split also updates the fee to 15%), outside-collectors (#6) Not
    // passed, and marketing (#3) / featured-artist (#5) still Voting open.
    {
      const { rows: seededIds } = await pool.query(`SELECT id FROM governance_proposals`);
      for (const { id } of seededIds) {
        await evaluateProposalOutcome(id);
      }
    }
  }

  app.listen(port, () => console.log(`Listening on :${port}`));
}

start().catch(err => { console.error(err); process.exit(1); });
