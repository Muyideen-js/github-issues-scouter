import express from 'express';
import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const PORT = Number(process.env.PORT || 3000);
const SYNC_MINUTES = Number(process.env.SYNC_MINUTES || 15);
const SECURE_COOKIE = process.env.SECURE_COOKIE === '1';

// ---------- encryption key (for stored GitHub tokens) ----------
const keyFile = path.join(DATA_DIR, 'secret.key');
if (!process.env.APP_SECRET && !fs.existsSync(keyFile)) {
  fs.writeFileSync(keyFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
}
const KEY = crypto
  .createHash('sha256')
  .update(process.env.APP_SECRET || fs.readFileSync(keyFile, 'utf8').trim())
  .digest();

// ---------- database ----------
const db = new DatabaseSync(path.join(DATA_DIR, 'app.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
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
`);

const STATUSES = ['todo','in_progress', 'blocked', 'pr_open', 'merged', 'closed', 'unassigned'];
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
function log(userId, action, detail = '') {
  db.prepare('INSERT INTO activity (user_id, action, detail, at) VALUES (?,?,?,?)').run(userId, action, detail, now());
}
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
  return prState === 'closed' ? 'in_progress' : 'todo'; // PR was closed unmerged, or issue reopened/reassigned
}

const syncing = new Set();
async function syncScouter(id) {
  if (syncing.has(id)) return;
  syncing.add(id);
  const u = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'scouter'").get(id);
  try {
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
    const manual = db.prepare("SELECT id, pr_url FROM issues WHERE scouter_id = ? AND pr_auto = 0 AND pr_url IS NOT NULL AND status != 'merged'").all(id);
    const manualState = new Map();
    for (const row of manual) {
      const m = row.pr_url.match(PR_URL_RE);
      if (!m) continue;
      try {
        const pr = await gh(token, `/repos/${m[1]}/pulls/${m[2]}`);
        manualState.set(row.id, pr.merged_at ? 'merged' : pr.state);
      } catch { /* leave as is */ }
    }

    const getExisting = db.prepare('SELECT * FROM issues WHERE scouter_id = ? AND gh_id = ?');
    const insert = db.prepare(`INSERT INTO issues
      (scouter_id, gh_id, repo, number, title, url, state, labels, gh_created, gh_updated, status, pr_url, pr_state, pr_auto, first_seen, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    const update = db.prepare(`UPDATE issues SET repo=?, number=?, title=?, url=?, state=?, labels=?, gh_updated=?,
      status=?, pr_url=?, pr_state=?, pr_auto=?, updated_at=? WHERE id=?`);

    const seen = new Set();
    db.exec('BEGIN');
    try {
      for (const it of [...open, ...closed]) {
        if (seen.has(it.id)) continue;
        seen.add(it.id);
        const repo = repoOf(it);
        const labels = JSON.stringify((it.labels || []).map((l) => ({ name: l.name, color: l.color })));
        const ex = getExisting.get(id, it.id);
        let prUrl = ex?.pr_url ?? null;
        let prState = ex?.pr_state ?? null;
        let prAuto = ex ? ex.pr_auto : 0;
        const pr = findPr(repo, it.number, it.html_url);
        if (pr && (!prUrl || prAuto || pr.url === prUrl)) { prUrl = pr.url; prState = pr.state; prAuto = pr.url === ex?.pr_url ? prAuto : 1; }
        if (ex && manualState.has(ex.id)) prState = manualState.get(ex.id);
        const status = deriveStatus(ex?.status ?? 'todo', it.state, prState);
        const t = now();

        if (ex) {
          update.run(repo, it.number, it.title, it.html_url, it.state, labels, it.updated_at, status, prUrl, prState, prAuto, t, ex.id);
          if (ex.status !== status) log(null, 'status', `${repo}#${it.number}: ${ex.status} → ${status} (from GitHub)`);
        } else {
          insert.run(id, it.id, repo, it.number, it.title, it.html_url, it.state, labels, it.created_at, it.updated_at, status, prUrl, prState, prAuto, t, t);
          log(null, 'new_issue', `@${login} was assigned ${repo}#${it.number}`);
        }
      }
      // Open issues we had before but GitHub no longer lists as assigned to this account.
      const prev = db.prepare("SELECT id, gh_id, repo, number, status FROM issues WHERE scouter_id = ? AND state = 'open'").all(id);
      for (const r of prev) {
        if (seen.has(r.gh_id)) continue;
        const status = r.status === 'merged' ? 'merged' : 'unassigned';
        db.prepare("UPDATE issues SET state = 'unassigned', status = ?, updated_at = ? WHERE id = ?").run(status, now(), r.id);
        log(null, 'unassigned', `@${login} is no longer assigned ${r.repo}#${r.number}`);
      }
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
    db.prepare('UPDATE users SET last_sync = ?, sync_error = NULL WHERE id = ?').run(now(), id);
  } catch (e) {
    const msg = e.status === 401 ? 'GitHub token is invalid or expired. The scouter needs to paste a new one.' : e.message;
    db.prepare('UPDATE users SET last_sync = ?, sync_error = ? WHERE id = ?').run(now(), msg, id);
    console.error(`sync failed for user ${id}:`, e.message);
  } finally {
    syncing.delete(id);
  }
}
async function syncMany(ids) {
  for (const id of ids) await syncScouter(id);
}
function allScouterIds() {
  return db.prepare("SELECT id FROM users WHERE role = 'scouter' AND active = 1").all().map((r) => r.id);
}

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Require JSON for writes (blocks simple cross-site form posts).
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && !req.is('application/json')) return res.status(415).json({ error: 'JSON required' });
  next();
});

function parseCookies(h = '') {
  const out = {};
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const maxAge = 14 * 86400;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?,?,?)').run(sha256(token), userId, Date.now() + maxAge * 1000);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${SECURE_COOKIE ? '; Secure' : ''}`);
}
app.use((req, res, next) => {
  const sid = parseCookies(req.headers.cookie).sid;
  if (sid) {
    const u = db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires > ? AND u.active = 1`).get(sha256(sid), Date.now());
    if (u) { req.user = u; req.sidHash = sha256(sid); }
  }
  next();
});
const auth = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Not logged in' });
  if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Not allowed' });
  next();
};

// Very small login rate limit: 10 failed tries per username+IP per 15 min.
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

const adminExists = () => !!db.prepare("SELECT 1 FROM users WHERE role = 'admin'").get();

app.get('/api/session', (req, res) => {
  res.json({ user: publicUser(req.user), setupNeeded: !adminExists() });
});

app.post('/api/setup', (req, res) => {
  if (adminExists()) return res.status(400).json({ error: 'Admin already exists' });
  const { username, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3–32 letters, numbers, _ . -' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const r = db.prepare("INSERT INTO users (username, pass_hash, role, created_at) VALUES (?,?,'admin',?)").run(username, hashPassword(password), now());
  log(Number(r.lastInsertRowid), 'setup', `Admin ${username} created`);
  startSession(res, Number(r.lastInsertRowid));
  res.json({ ok: true });
});

app.post('/api/signup/scouter', async (req, res) => {
  const { token, username, password } = req.body || {};
  if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Paste your GitHub token' });
  if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3–32 letters, numbers, _ . -' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return res.status(400).json({ error: 'That username is taken' });
  let ghUser;
  try {
    ghUser = await gh(token.trim(), '/user');
  } catch (e) {
    return res.status(400).json({ error: e.status === 401 ? 'GitHub rejected that token' : `Could not check token: ${e.message}` });
  }
  if (db.prepare('SELECT 1 FROM users WHERE github_login = ?').get(ghUser.login)) {
    return res.status(400).json({ error: `GitHub account @${ghUser.login} is already registered` });
  }
  const r = db.prepare("INSERT INTO users (username, pass_hash, role, github_login, token_enc, created_at) VALUES (?,?,'scouter',?,?,?)")
    .run(username, hashPassword(password), ghUser.login, encrypt(token.trim()), now());
  const id = Number(r.lastInsertRowid);
  log(id, 'signup', `Scouter ${username} joined with GitHub @${ghUser.login}`);
  startSession(res, id);
  syncScouter(id);
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const k = failKey(req, username);
  if (tooManyFails(k)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const u = typeof username === 'string' && db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u || typeof password !== 'string' || !verifyPassword(password, u.pass_hash)) {
    recordFail(k);
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  if (!u.active) return res.status(403).json({ error: 'This account is deactivated. Contact the admin.' });
  fails.delete(k);
  startSession(res, u.id);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  if (req.sidHash) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(req.sidHash);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.post('/api/me/password', auth(), (req, res) => {
  const { current, password } = req.body || {};
  if (typeof current !== 'string' || !verifyPassword(current, req.user.pass_hash)) return res.status(400).json({ error: 'Current password is wrong' });
  if (!validPassword(password)) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hashPassword(password), req.user.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(req.user.id, req.sidHash);
  res.json({ ok: true });
});

app.post('/api/me/token', auth('scouter'), async (req, res) => {
  const token = String(req.body?.token || '').trim();
  if (!token) return res.status(400).json({ error: 'Paste your GitHub token' });
  let ghUser;
  try { ghUser = await gh(token, '/user'); } catch { return res.status(400).json({ error: 'GitHub rejected that token' }); }
  if (ghUser.login.toLowerCase() !== req.user.github_login.toLowerCase()) {
    return res.status(400).json({ error: `That token belongs to @${ghUser.login}, not @${req.user.github_login}` });
  }
  db.prepare('UPDATE users SET token_enc = ?, sync_error = NULL WHERE id = ?').run(encrypt(token), req.user.id);
  log(req.user.id, 'token', `@${req.user.github_login} updated their GitHub token`);
  await syncScouter(req.user.id);
  res.json({ ok: true });
});

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

function visibleScouterIds(u) {
  if (u.role === 'admin') return allScouterIds();
  if (u.role === 'scouter') return [u.id];
  return db.prepare('SELECT scouter_id FROM assignments WHERE dev_id = ?').all(u.id).map((r) => r.scouter_id);
}

app.get('/api/issues', auth(), (req, res) => {
  const u = req.user;
  let issues, accounts;
  if (u.role === 'admin') {
    issues = db.prepare(`${ISSUE_SELECT} ORDER BY i.gh_updated DESC`).all();
    accounts = db.prepare(`${ACCOUNT_SELECT} ORDER BY s.github_login`).all();
  } else if (u.role === 'scouter') {
    issues = db.prepare(`${ISSUE_SELECT} WHERE i.scouter_id = ? ORDER BY i.gh_updated DESC`).all(u.id);
    accounts = db.prepare(`${ACCOUNT_SELECT} AND s.id = ?`).all(u.id);
  } else {
    issues = db.prepare(`${ISSUE_SELECT} WHERE a.dev_id = ? ORDER BY i.gh_updated DESC`).all(u.id);
    accounts = db.prepare(`${ACCOUNT_SELECT} AND a.dev_id = ? ORDER BY s.github_login`).all(u.id);
  }
  issues.forEach((i) => { i.labels = JSON.parse(i.labels); });
  res.json({ issues, accounts });
});

app.patch('/api/issues/:id', auth('admin', 'dev'), (req, res) => {
  const issue = db.prepare(`${ISSUE_SELECT} WHERE i.id = ?`).get(Number(req.params.id));
  if (!issue) return res.status(404).json({ error: 'Issue not found' });
  if (req.user.role === 'dev' && issue.dev_id !== req.user.id) return res.status(403).json({ error: 'This issue is not on one of your accounts' });

  const { status, note, pr_url } = req.body || {};
  const changes = [];
  let newStatus = issue.status, newNote = issue.note, newPr = issue.pr_url, prAuto = null, prState = issue.pr_state;

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

  db.prepare(`UPDATE issues SET status = ?, note = ?, pr_url = ?, pr_state = ?, pr_auto = COALESCE(?, pr_auto), updated_at = ? WHERE id = ?`)
    .run(newStatus, newNote, newPr, prState, prAuto, now(), issue.id);
  log(req.user.id, 'issue', `${req.user.username} on ${issue.repo}#${issue.number}: ${changes.join(', ')}`);
  res.json({ ok: true });
});

app.post('/api/sync', auth(), async (req, res) => {
  const ids = visibleScouterIds(req.user);
  const only = req.body?.scouter_id;
  const target = only ? ids.filter((x) => x === Number(only)) : ids;
  // Wait up to 25s, then return; the sync keeps running in the background.
  await Promise.race([syncMany(target), new Promise((r) => setTimeout(r, 25000))]);
  res.json({ ok: true });
});

// ----- admin -----
app.get('/api/admin/overview', auth('admin'), (req, res) => {
  const users = db.prepare('SELECT * FROM users ORDER BY role, username').all().map(publicUser);
  const assignments = db.prepare('SELECT scouter_id, dev_id FROM assignments').all();
  const counts = db.prepare('SELECT scouter_id, status, COUNT(*) AS n FROM issues GROUP BY scouter_id, status').all();
  res.json({ users, assignments, counts });
});

app.post('/api/admin/devs', auth('admin'), (req, res) => {
  const { username, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3–32 letters, numbers, _ . -' });
  if (!validPassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return res.status(400).json({ error: 'That username is taken' });
  db.prepare("INSERT INTO users (username, pass_hash, role, created_at) VALUES (?,?,'dev',?)").run(username, hashPassword(password), now());
  log(req.user.id, 'dev_created', `Dev ${username} created`);
  res.json({ ok: true });
});

app.post('/api/admin/assign', auth('admin'), (req, res) => {
  const scouter = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'scouter'").get(Number(req.body?.scouter_id));
  if (!scouter) return res.status(404).json({ error: 'Scouter not found' });
  const devId = req.body?.dev_id ? Number(req.body.dev_id) : null;
  if (devId === null) {
    db.prepare('DELETE FROM assignments WHERE scouter_id = ?').run(scouter.id);
    log(req.user.id, 'assign', `@${scouter.github_login} unassigned from any dev`);
    return res.json({ ok: true });
  }
  const dev = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'dev'").get(devId);
  if (!dev) return res.status(404).json({ error: 'Dev not found' });
  db.prepare(`INSERT INTO assignments (scouter_id, dev_id, assigned_at) VALUES (?,?,?)
    ON CONFLICT(scouter_id) DO UPDATE SET dev_id = excluded.dev_id, assigned_at = excluded.assigned_at`).run(scouter.id, dev.id, now());
  log(req.user.id, 'assign', `@${scouter.github_login} → ${dev.username}`);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/active', auth('admin'), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (u.role === 'admin') return res.status(400).json({ error: 'Cannot deactivate an admin' });
  const active = req.body?.active ? 1 : 0;
  db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active, u.id);
  if (!active) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
  log(req.user.id, 'user', `${u.username} ${active ? 'reactivated' : 'deactivated'}`);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/password', auth('admin'), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!u) return res.status(404).json({ error: 'User not found' });
  if (!validPassword(req.body?.password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  db.prepare('UPDATE users SET pass_hash = ? WHERE id = ?').run(hashPassword(req.body.password), u.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
  log(req.user.id, 'user', `Password reset for ${u.username}`);
  res.json({ ok: true });
});

app.get('/api/admin/tokens', auth('admin'), (req, res) => {
  const rows = db.prepare("SELECT id, username, github_login, token_enc, active, sync_error FROM users WHERE role = 'scouter' ORDER BY id").all();
  const tokens = rows.map((r) => {
    let token = null;
    try { token = r.token_enc ? decrypt(r.token_enc) : null; } catch { token = null; }
    return { id: r.id, username: r.username, github_login: r.github_login, active: !!r.active, token_ok: !r.sync_error, token };
  });
  log(req.user.id, 'tokens_viewed', `${req.user.username} opened the token list`);
  res.json({ tokens });
});

app.get('/api/admin/activity', auth('admin'), (req, res) => {
  const rows = db.prepare(`SELECT a.id, a.action, a.detail, a.at, u.username FROM activity a
    LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 300`).all();
  res.json({ activity: rows });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
// SPA routes (/, /scouter, /dev, /admin) all serve the single page; the app picks the view from the path.
app.get(['/', '/scouter', '/dev', '/admin'], (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

// housekeeping + background sync
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now()), 3600e3);
setInterval(() => syncMany(allScouterIds()), SYNC_MINUTES * 60e3);
setTimeout(() => syncMany(allScouterIds()), 5000);

app.listen(PORT, () => {
  console.log(`Issue Scouter running at http://localhost:${PORT}`);
  if (!adminExists()) console.log('No admin yet — open the site to create the admin account.');
});
