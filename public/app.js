'use strict';

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const STATUS = {
  in_progress: 'In progress', blocked: 'Blocked', pr_open: 'PR open', todo: 'To do',
  merged: 'Merged', closed: 'Closed', unassigned: 'Unassigned',
};
const ACTIVE = ['todo', 'in_progress', 'blocked', 'pr_open'];
const app = $('#app');

const ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  issue: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="1.5"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14.8c2 .7 3.2 2.5 3.6 5.2"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14 9l2 2"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  refresh: '<path d="M20 11a8 8 0 0 0-14.7-4.3L3 9"/><path d="M3 4v5h5"/><path d="M4 13a8 8 0 0 0 14.7 4.3L21 15"/><path d="M21 20v-5h-5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  logout: '<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="M10 17l-5-5 5-5M5 12h11"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeoff: '<path d="M3 3l18 18"/><path d="M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.8M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.6 9.6 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
  warn: '<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18v.01"/>',
  pr: '<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M6 8.5v7M18 15.5V9a3 3 0 0 0-3-3h-4"/><path d="M13 3.5L10.5 6 13 8.5"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>',
};
const icon = (n) => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n]}</svg>`;

let me = null;
let data = {};
let tab = null;
let selected = null; // issue id open in detail panel
let draft = null;    // unsaved edits in the detail panel
const filters = { status: 'active', scouter: '', dev: '', q: '' };
const revealed = new Set();

// ---------------- helpers ----------------
async function api(path, body, method) {
  const r = await fetch('/api' + path, {
    method: method || (body ? 'POST' : 'GET'),
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && !['/login', '/session'].includes(path)) { me = null; boot(); }
  if (!r.ok) throw new Error(j.error || `Request failed (${r.status})`);
  return j;
}
let toastTimer;
function toast(msg, bad) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 2800);
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}
function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso)) / 1000;
  if (s < 60) return 'now';
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)}d`;
  return new Date(iso).toLocaleDateString();
}
const shortPr = (u) => (u || '').replace('https://github.com/', '').replace('/pull/', '#');
const pill = (s) => `<span class="pill s-${s}">${STATUS[s] || s}</span>`;
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};
function countBy(issues) {
  const c = Object.fromEntries(Object.keys(STATUS).map((k) => [k, 0]));
  for (const i of issues) c[i.status] = (c[i.status] || 0) + 1;
  return c;
}
const canEdit = () => me.role === 'admin' || me.role === 'dev';

// ---------------- boot / auth ----------------
// Each role has its own URL. The path decides which login page shows.
const PAGE_LINKS = { admin: ['/', 'Admin'], scouter: ['/scouter', 'Scouter'], dev: ['/dev', 'Developer'] };
function pageCfg() {
  const p = location.pathname.replace(/\/+$/, '') || '/';
  if (p === '/scouter') return { role: 'scouter', title: 'Scouter', signup: true };
  if (p === '/dev') return { role: 'dev', title: 'Developer' };
  return { role: 'admin', title: 'Admin', isAdmin: true };
}

async function boot() {
  try {
    const s = await api('/session');
    me = s.user;
    if (!me) return renderAuth(s.setupNeeded && pageCfg().isAdmin ? 'setup' : 'login');
    const ids = tabsFor(me.role).map((t) => t.id);
    tab = ids.includes(store.get('tab')) ? store.get('tab') : ids[0];
    await load();
  } catch (e) {
    app.innerHTML = `<p class="loading err">${esc(e.message)}</p>`;
  }
}

function renderAuth(mode) {
  const cfg = pageCfg();
  if (mode === 'signup' && !cfg.signup) mode = 'login';
  const setup = mode === 'setup';
  const title = setup ? 'Set up admin' : mode === 'signup' ? 'Create scouter account' : `${cfg.title} log in`;
  const sub = setup ? 'First run. This account controls everything.'
    : mode === 'signup' ? 'Paste your GitHub token once. After that you just use your username and password.'
    : cfg.role === 'scouter' ? 'Log in to see the issues assigned to your account.'
    : cfg.role === 'dev' ? 'Log in to see the issues assigned to you.'
    : 'Admin access to the whole platform.';
  const btn = setup ? 'Create admin' : mode === 'signup' ? 'Create account' : 'Log in';
  const links = Object.entries(PAGE_LINKS).filter(([role]) => role !== cfg.role).map(([, [href, label]]) => `<a href="${href}">${label} →</a>`).join('');
  app.innerHTML = `
  <div class="auth"><div class="auth-box">
    <div class="logo"><span class="logo-mark">◆</span>Issue Scouter</div>
    <h1>${title}</h1>
    <p class="sub">${sub}</p>
    ${cfg.signup && !setup ? `<div class="seg">
      <button type="button" class="${mode === 'login' ? 'on' : ''}" data-auth="login">Log in</button>
      <button type="button" class="${mode === 'signup' ? 'on' : ''}" data-auth="signup">Sign up</button>
    </div>` : ''}
    <form class="stack" data-form="${mode}" data-label="${btn}">
      ${mode === 'signup' ? `
        <label>GitHub token
          <input name="token" type="password" autocomplete="off" required placeholder="ghp_… or github_pat_…" class="mono">
          <span class="hint">Create one at <a href="https://github.com/settings/tokens" target="_blank" rel="noopener">github.com/settings/tokens</a>. Classic token, scopes <code>read:user</code> + <code>public_repo</code>. Stored encrypted. Your admin can view it; devs can't.</span>
        </label>` : ''}
      <label>Username <input name="username" autocomplete="username" required minlength="3" maxlength="32"></label>
      <label>Password <input name="password" type="password" autocomplete="${mode === 'login' ? 'current-password' : 'new-password'}" required minlength="${mode === 'login' ? 1 : 8}"></label>
      ${mode !== 'login' ? '<label>Confirm password <input name="confirm" type="password" autocomplete="new-password" required></label>' : ''}
      <p class="err" data-err hidden style="margin:0"></p>
      <button class="btn primary" type="submit">${btn}</button>
      ${mode === 'login' && cfg.role !== 'scouter' ? '<p class="hint" style="margin:0;text-align:center">No account? Your admin creates it.</p>' : ''}
    </form>
    <div class="auth-links">${links}</div>
  </div></div>`;
  $('input', app)?.focus();
}

async function submitAuth(form) {
  const mode = form.dataset.form;
  const f = Object.fromEntries(new FormData(form));
  const err = $('[data-err]', form);
  const btn = $('button[type=submit]', form);
  if (f.confirm !== undefined && f.confirm !== f.password) { err.hidden = false; err.textContent = 'Passwords do not match'; return; }
  btn.disabled = true; err.hidden = true;
  if (mode === 'signup') btn.textContent = 'Checking token…';
  try {
    const path = { setup: '/setup', signup: '/signup/scouter', login: '/login' }[mode];
    await api(path, { username: f.username, password: f.password, token: f.token });
    await boot();
  } catch (e) {
    err.hidden = false; err.textContent = e.message;
    btn.disabled = false; btn.textContent = form.dataset.label;
  }
}

// ---------------- data ----------------
function tabsFor(role) {
  if (role === 'admin') return [
    { id: 'overview', label: 'Overview', icon: 'grid' },
    { id: 'issues', label: 'Issues', icon: 'issue' },
    { id: 'team', label: 'Team', icon: 'users' },
    { id: 'tokens', label: 'Tokens', icon: 'key' },
    { id: 'activity', label: 'Activity', icon: 'activity' },
  ];
  if (role === 'dev') return [{ id: 'issues', label: 'My issues', icon: 'issue' }];
  return [{ id: 'issues', label: 'My issues', icon: 'issue' }, { id: 'account', label: 'Account', icon: 'user' }];
}

async function load() {
  const jobs = { iss: api('/issues') };
  if (me.role === 'admin') jobs.ov = api('/admin/overview');
  if (me.role === 'admin' && tab === 'activity') jobs.act = api('/admin/activity');
  if (me.role === 'admin' && tab === 'tokens') jobs.tok = api('/admin/tokens');
  const keys = Object.keys(jobs);
  const vals = await Promise.all(Object.values(jobs));
  const r = Object.fromEntries(keys.map((k, i) => [k, vals[i]]));
  data = { ...r.iss, overview: r.ov, activity: r.act?.activity, tokens: r.tok?.tokens ?? data.tokens };
  if (selected && !data.issues.find((i) => i.id === selected)) selected = null;
  render();
}

// ---------------- shell ----------------
function sidebar() {
  const tabs = tabsFor(me.role);
  const accts = me.role === 'scouter' ? [] : data.accounts;
  const activeByAcct = (id) => data.issues.filter((i) => i.scouter_id === id && ACTIVE.includes(i.status)).length;
  const issueCount = data.issues.filter((i) => ACTIVE.includes(i.status)).length;
  return `
  <aside class="side">
    <div class="logo"><span class="logo-mark">◆</span>Issue Scouter</div>
    <div class="side-scroll">
      ${tabs.map((t) => `<button class="nav ${t.id === tab ? 'on' : ''}" data-tab="${t.id}">${icon(t.icon)}${t.label}
        ${t.id === 'issues' ? `<span class="count">${issueCount}</span>` : ''}</button>`).join('')}
      ${accts.length ? `<div class="side-label"><span>Accounts</span><span>${accts.length}</span></div>
        ${accts.map((a) => `<button class="nav acct-nav ${tab === 'issues' && filters.scouter === String(a.id) ? 'on' : ''}" data-acct="${a.id}" title="${esc(a.sync_error || `@${a.github_login}${a.dev_username ? ' → ' + a.dev_username : ''}`)}">
          <span class="dot ${!a.active ? 'off' : a.sync_error ? 'bad' : 'ok'}"></span>
          <span class="acct">@${esc(a.github_login)}</span><span class="count">${activeByAcct(a.id)}</span></button>`).join('')}` : ''}
    </div>
    <div class="side-foot">
      <span class="avatar">${esc(me.username.slice(0, 2))}</span>
      <div class="who"><div>${esc(me.username)}</div><div class="muted">${me.role}${me.github_login ? ` · @${esc(me.github_login)}` : ''}</div></div>
      <button class="btn ghost icon" data-action="password" title="Change password">${icon('lock')}</button>
      <button class="btn ghost icon" data-action="logout" title="Log out">${icon('logout')}</button>
    </div>
  </aside>`;
}

function topbar(title, sub, actions = '') {
  return `<div class="topbar"><h1>${title}</h1>${sub ? `<span class="sub">${sub}</span>` : ''}<div class="right">${actions}</div></div>`;
}
const syncBtn = () => `<button class="btn" data-action="sync">${icon('refresh')}Sync</button>`;

function render() {
  const focusKey = document.activeElement?.dataset?.filter;
  const caret = document.activeElement?.selectionStart;
  let view;
  if (me.role === 'admin') view = { overview: adminOverview, issues: issuesView, team: adminTeam, tokens: adminTokens, activity: adminActivity }[tab]();
  else if (tab === 'account') view = scouterAccount();
  else view = issuesView();
  const issue = selected && data.issues.find((i) => i.id === selected);
  app.innerHTML = `<div class="layout">${sidebar()}<div class="main"><div class="content">${view}</div>${issue ? detailPanel(issue) : ''}</div></div>`;
  if (focusKey) {
    const el = $(`[data-filter="${focusKey}"]`);
    if (el) { el.focus(); if (caret != null && el.setSelectionRange) el.setSelectionRange(caret, caret); }
  }
}

// ---------------- issue list + detail ----------------
function labelsHtml(labels) {
  if (!labels?.length) return '<span class="faint">none</span>';
  return `<div class="labels">${labels.map((l) => {
    const c = /^[0-9a-f]{6}$/i.test(l.color) ? `#${l.color}` : '#888888';
    return `<span class="label" style="--lc:${c}">${esc(l.name)}</span>`;
  }).join('')}</div>`;
}

function row(i) {
  return `<button class="row ${i.id === selected ? 'on' : ''}" data-open="${i.id}">
    <span class="dot s-${i.status}"></span>
    <span class="repo">${esc(i.repo)}#${i.number}</span>
    <span class="title">${i.pr_url ? `<span class="pr-ic">${icon('pr')}</span>` : ''}${esc(i.title)}</span>
    <span class="who">@${esc(i.github_login)}${me.role !== 'dev' ? ` → ${i.dev_username ? esc(i.dev_username) : '—'}` : ''}</span>
    <span class="time">${ago(i.gh_updated)}</span>
  </button>`;
}

function issueList(issues, { grouped = true, empty = 'No issues match.' } = {}) {
  if (!issues.length) return `<div class="empty">${empty}</div>`;
  if (!grouped) return `<div class="list">${issues.map(row).join('')}</div>`;
  return `<div class="list">${Object.keys(STATUS).map((s) => {
    const g = issues.filter((i) => i.status === s);
    return g.length ? `<div class="list-group"><span class="dot s-${s}"></span>${STATUS[s]}<span class="count">${g.length}</span></div>${g.map(row).join('')}` : '';
  }).join('')}</div>`;
}

function detailPanel(i) {
  const d = draft && draft.id === i.id ? draft : { id: i.id, status: i.status, pr_url: i.pr_url || '', note: i.note || '' };
  return `
  <aside class="detail" aria-label="Issue details">
    <div class="detail-h">
      <span class="dot s-${i.status}"></span><span class="mono">${esc(i.repo)}#${i.number}</span>
      <div class="right">
        <a class="btn ghost icon" href="${esc(i.url)}" target="_blank" rel="noopener" title="Open on GitHub">${icon('ext')}</a>
        <button class="btn ghost icon" data-action="close" title="Close (Esc)">${icon('x')}</button>
      </div>
    </div>
    <div class="detail-b">
      <h2>${esc(i.title)}</h2>
      <dl class="props">
        <dt>Status</dt><dd>${pill(i.status)}</dd>
        <dt>Account</dt><dd class="mono">@${esc(i.github_login)}</dd>
        <dt>Dev</dt><dd>${i.dev_username ? esc(i.dev_username) : '<span class="faint">not assigned</span>'}</dd>
        <dt>Labels</dt><dd>${labelsHtml(i.labels)}</dd>
        <dt>Pull request</dt><dd>${i.pr_url ? `<a href="${esc(i.pr_url)}" target="_blank" rel="noopener" class="mono">${esc(shortPr(i.pr_url))}</a>${i.pr_state ? ` <span class="faint">${esc(i.pr_state)}</span>` : ''}` : '<span class="faint">none</span>'}</dd>
        <dt>Updated</dt><dd>${ago(i.gh_updated)} ago <span class="faint">on GitHub</span></dd>
        <dt>Tracked since</dt><dd>${new Date(i.first_seen).toLocaleDateString()}</dd>
      </dl>
      ${canEdit() ? `
        <div>
          <span class="field-l">Set status</span>
          <div class="status-pick">${Object.keys(STATUS).map((s) => `<button type="button" class="s-${s} ${s === d.status ? 'on' : ''}" data-pick="${s}">${STATUS[s]}</button>`).join('')}</div>
        </div>
        <label>Pull request link
          <input class="mono" data-draft="pr_url" placeholder="https://github.com/owner/repo/pull/123" value="${esc(d.pr_url)}">
        </label>
        <label>Notes
          <textarea data-draft="note" placeholder="What's done, what's left, blockers…">${esc(d.note)}</textarea>
        </label>
        <div style="display:flex;align-items:center;gap:10px">
          <button class="btn primary" data-action="save-issue">Save</button>
          <span class="kbd">Ctrl ↵</span>
          ${draft && draft.id === i.id ? '<span class="faint">unsaved changes</span>' : ''}
        </div>`
      : i.note ? `<div><span class="field-l">Dev notes</span><p class="note-ro">${esc(i.note)}</p></div>` : ''}
    </div>
  </aside>`;
}

function applyFilters(issues) {
  const q = filters.q.trim().toLowerCase();
  return issues.filter((i) => {
    if (filters.status === 'active' && !ACTIVE.includes(i.status)) return false;
    if (!['active', 'all', ''].includes(filters.status) && i.status !== filters.status) return false;
    if (filters.scouter && String(i.scouter_id) !== filters.scouter) return false;
    if (filters.dev === 'none' && i.dev_id) return false;
    if (filters.dev && filters.dev !== 'none' && String(i.dev_id) !== filters.dev) return false;
    if (q && !`${i.repo}#${i.number} ${i.title} ${i.github_login}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

function toolbar() {
  const showAcct = me.role !== 'scouter' && data.accounts.length > 1;
  const devs = me.role === 'admin' ? data.overview.users.filter((u) => u.role === 'dev') : null;
  return `<div class="toolbar">
    <div class="search">${icon('search')}<input data-filter="q" placeholder="Search issues, repos, accounts…" value="${esc(filters.q)}"></div>
    <select data-filter="status" aria-label="Status">
      <option value="active" ${filters.status === 'active' ? 'selected' : ''}>Active</option>
      <option value="all" ${filters.status === 'all' ? 'selected' : ''}>All statuses</option>
      ${Object.entries(STATUS).map(([k, v]) => `<option value="${k}" ${filters.status === k ? 'selected' : ''}>${v}</option>`).join('')}
    </select>
    ${showAcct ? `<select data-filter="scouter" aria-label="Account"><option value="">All accounts</option>
      ${data.accounts.map((s) => `<option value="${s.id}" ${filters.scouter === String(s.id) ? 'selected' : ''}>@${esc(s.github_login)}</option>`).join('')}</select>` : ''}
    ${devs ? `<select data-filter="dev" aria-label="Dev"><option value="">All devs</option><option value="none" ${filters.dev === 'none' ? 'selected' : ''}>No dev</option>
      ${devs.map((d) => `<option value="${d.id}" ${filters.dev === String(d.id) ? 'selected' : ''}>${esc(d.username)}</option>`).join('')}</select>` : ''}
  </div>`;
}

function statStrip(issues, extra = []) {
  const c = countBy(issues);
  const tiles = [...extra,
    { n: c.todo, l: 'To do', s: 'todo' }, { n: c.in_progress, l: 'In progress', s: 'in_progress' },
    { n: c.blocked, l: 'Blocked', s: 'blocked' }, { n: c.pr_open, l: 'PRs open', s: 'pr_open' }, { n: c.merged, l: 'Merged', s: 'merged' }];
  return `<div class="stats">${tiles.map((t) => `<div class="stat"><div class="n">${t.n}</div><div class="l">${t.s ? `<span class="dot s-${t.s}"></span>` : ''}${t.l}</div></div>`).join('')}</div>`;
}

const warnBox = (html) => `<div class="warn">${icon('warn')}<div>${html}</div></div>`;
function syncWarnings(accounts) {
  return accounts.filter((a) => a.sync_error && a.active)
    .map((a) => warnBox(`<span class="mono">@${esc(a.github_login)}</span>: ${esc(a.sync_error)}`)).join('');
}

// ---------------- views ----------------
function issuesView() {
  const list = applyFilters(data.issues);
  const acct = filters.scouter && data.accounts.find((a) => String(a.id) === filters.scouter);
  let title = me.role === 'admin' ? 'Issues' : 'My issues';
  let sub = `${list.length} of ${data.issues.length}`;
  if (acct) { title = `@${esc(acct.github_login)}`; sub = acct.dev_username ? `→ ${esc(acct.dev_username)}` : 'no dev assigned'; }

  let top = '';
  if (me.role === 'dev' && !data.accounts.length) {
    return topbar(title) + `<div class="page"><div class="empty"><b>No accounts assigned to you yet.</b><br>Once the admin links a GitHub account to you, its issues show up here.</div></div>`;
  }
  if (me.role === 'scouter') {
    const a = data.accounts[0] || {};
    top = (a.sync_error ? warnBox(`${esc(a.sync_error)} <a href="#" data-tab="account">Update token</a>`) : '') +
      `<div class="box pad">Your issues go to ${a.dev_username ? `<b>${esc(a.dev_username)}</b>` : '<span class="muted">no dev yet. The admin will assign one.</span>'}<span class="faint"> · synced ${ago(a.last_sync)} ago</span></div>`;
  } else {
    top = syncWarnings(acct ? [acct] : data.accounts);
  }
  const emptyMsg = data.issues.length ? 'No issues match these filters.'
    : me.role === 'scouter' ? `<b>No issues assigned to @${esc(me.github_login)} yet.</b><br>Apply for issues on GitHub. Once a maintainer assigns you, they show up here automatically.`
    : '<b>No issues yet.</b><br>Issues appear when a GitHub account is assigned one.';

  return topbar(title, sub, (acct ? `<button class="btn ghost" data-action="clear-acct">${icon('x')}Clear</button>` : '') + syncBtn()) + `
    <div class="page">
      ${top}
      ${statStrip(acct ? data.issues.filter((i) => i.scouter_id === acct.id) : data.issues)}
      ${toolbar()}
      ${issueList(list, { empty: emptyMsg })}
    </div>`;
}

function adminOverview() {
  const { users, assignments } = data.overview;
  const devs = users.filter((u) => u.role === 'dev' && u.active);
  const scouters = users.filter((u) => u.role === 'scouter' && u.active);
  const unrouted = scouters.filter((s) => !assignments.find((a) => a.scouter_id === s.id));
  const rows = devs.map((d) => {
    const c = countBy(data.issues.filter((i) => i.dev_id === d.id));
    const accts = data.accounts.filter((a) => a.dev_id === d.id).map((a) => '@' + esc(a.github_login)).join(', ');
    return `<tr><td>${esc(d.username)}</td><td class="mono muted">${accts || '<span class="faint">—</span>'}</td>
      <td class="num">${c.todo}</td><td class="num">${c.in_progress}</td><td class="num">${c.blocked}</td><td class="num">${c.pr_open}</td><td class="num">${c.merged}</td></tr>`;
  }).join('');
  const attention = data.issues.filter((i) => i.status === 'blocked' || (ACTIVE.includes(i.status) && !i.dev_id));
  const recent = data.issues.filter((i) => ACTIVE.includes(i.status)).slice(0, 8);
  return topbar('Overview', '', syncBtn()) + `
    <div class="page">
      ${syncWarnings(data.accounts)}
      ${unrouted.length ? warnBox(`${unrouted.length} account${unrouted.length > 1 ? 's have' : ' has'} no dev: <span class="mono">${unrouted.map((s) => '@' + esc(s.github_login)).join(', ')}</span>. <a href="#" data-tab="team">Assign in Team</a>`) : ''}
      ${statStrip(data.issues, [{ n: scouters.length, l: 'Accounts' }, { n: devs.length, l: 'Devs' }])}
      <section>
        <div class="section-h"><h2>Devs</h2></div>
        ${devs.length ? `<div class="box tablewrap"><table>
          <thead><tr><th>Dev</th><th>Accounts</th><th>To do</th><th>In progress</th><th>Blocked</th><th>PR open</th><th>Merged</th></tr></thead>
          <tbody>${rows}</tbody></table></div>` : `<div class="empty">No devs yet. <a href="#" data-tab="team">Create one in Team</a></div>`}
      </section>
      ${attention.length ? `<section><div class="section-h"><h2>Needs attention</h2></div>${issueList(attention, { grouped: false })}</section>` : ''}
      <section>
        <div class="section-h"><h2>Latest active</h2><div class="right"><button class="btn ghost sm" data-tab="issues">View all</button></div></div>
        ${issueList(recent, { grouped: false, empty: 'No active issues yet. They appear once a scouter account gets assigned on GitHub.' })}
      </section>
    </div>`;
}

function adminTeam() {
  const { users, assignments, counts } = data.overview;
  const devs = users.filter((u) => u.role === 'dev');
  const scouters = users.filter((u) => u.role === 'scouter');
  const sum = (sid, pred) => counts.filter((c) => c.scouter_id === sid && pred(c.status)).reduce((a, c) => a + c.n, 0);
  const userActions = (u) => `<div class="actions">
    ${u.role === 'scouter' ? `<button class="btn ghost sm" data-action="sync-one" data-id="${u.id}">Sync</button>` : ''}
    <button class="btn ghost sm" data-action="reset-pw" data-id="${u.id}" data-name="${esc(u.username)}">Reset password</button>
    <button class="btn ghost sm ${u.active ? 'danger' : ''}" data-action="toggle-active" data-id="${u.id}" data-active="${u.active ? 0 : 1}" data-name="${esc(u.username)}">${u.active ? 'Deactivate' : 'Reactivate'}</button>
  </div>`;

  const sRows = scouters.map((s) => {
    const a = assignments.find((x) => x.scouter_id === s.id);
    return `<tr class="${s.active ? '' : 'inactive'}">
      <td><div class="mono">@${esc(s.github_login)}</div><div class="faint">${esc(s.username)}</div></td>
      <td><select data-assign="${s.id}" aria-label="Dev for @${esc(s.github_login)}">
        <option value="">— no dev —</option>
        ${devs.filter((d) => d.active).map((d) => `<option value="${d.id}" ${a?.dev_id === d.id ? 'selected' : ''}>${esc(d.username)}</option>`).join('')}
      </select></td>
      <td class="num">${sum(s.id, (st) => ACTIVE.includes(st))}</td>
      <td class="num">${sum(s.id, (st) => st === 'merged')}</td>
      <td><span class="dot ${s.sync_error ? 'bad' : 'ok'}" title="${esc(s.sync_error || 'OK')}"></span> <span class="muted">${ago(s.last_sync)}</span></td>
      <td>${userActions(s)}</td></tr>`;
  }).join('');

  const dRows = devs.map((d) => {
    const accts = assignments.filter((a) => a.dev_id === d.id).map((a) => scouters.find((s) => s.id === a.scouter_id)).filter(Boolean);
    return `<tr class="${d.active ? '' : 'inactive'}"><td>${esc(d.username)}</td>
      <td class="mono muted">${accts.map((s) => '@' + esc(s.github_login)).join(', ') || '<span class="faint">—</span>'}</td>
      <td>${userActions(d)}</td></tr>`;
  }).join('');

  return topbar('Team', `${scouters.length} accounts · ${devs.length} devs`) + `
    <div class="page">
      <section>
        <div class="section-h"><h2>Accounts → devs</h2></div>
        ${scouters.length ? `<div class="box tablewrap"><table>
          <thead><tr><th>GitHub account</th><th>Dev</th><th>Active</th><th>Merged</th><th>Sync</th><th></th></tr></thead>
          <tbody>${sRows}</tbody></table></div>` : '<div class="empty"><b>No scouters yet.</b><br>They sign up themselves on the login page with their GitHub token.</div>'}
      </section>
      <div class="two">
        <section>
          <div class="section-h"><h2>Devs</h2></div>
          ${devs.length ? `<div class="box tablewrap"><table><thead><tr><th>Dev</th><th>Accounts</th><th></th></tr></thead><tbody>${dRows}</tbody></table></div>` : '<div class="empty">No devs yet.</div>'}
        </section>
        <section>
          <div class="section-h"><h2>Add dev</h2></div>
          <form class="stack box pad" data-form="new-dev">
            <label>Username <input name="username" required minlength="3" maxlength="32" autocomplete="off"></label>
            <label>Password <input name="password" class="mono" type="text" required minlength="8" autocomplete="off"><span class="hint">Send it to the dev. They can change it after logging in.</span></label>
            <button class="btn primary" type="submit">Create dev</button>
          </form>
        </section>
      </div>
    </div>`;
}

function adminTokens() {
  const list = data.tokens || [];
  const withTok = list.filter((t) => t.token);
  const allShown = withTok.length > 0 && withTok.every((t) => revealed.has(t.id));
  const mask = (t) => (t.length > 10 ? `${t.slice(0, 4)}${'•'.repeat(18)}${t.slice(-4)}` : '•'.repeat(12));
  const rows = list.map((t, idx) => {
    const shown = revealed.has(t.id);
    return `<div class="tok-row">
      <span class="n">${idx + 1}.</span>
      <span>${esc(t.username)}${t.active ? '' : ' <span class="faint">(inactive)</span>'}</span>
      <span class="mono muted gh">@${esc(t.github_login)}</span>
      <span class="tok ${shown ? 'shown' : ''}" title="${t.token_ok ? '' : 'Last sync failed: token may be expired'}">${t.token ? esc(shown ? t.token : mask(t.token)) : '<span class="faint">none</span>'}${t.token && !t.token_ok ? ' <span class="err">· may be expired</span>' : ''}</span>
      <span class="actions">${t.token ? `
        <button class="btn ghost icon" data-action="reveal" data-id="${t.id}" title="${shown ? 'Hide' : 'Show'}">${icon(shown ? 'eyeoff' : 'eye')}</button>
        <button class="btn ghost icon" data-action="copy-one" data-id="${t.id}" title="Copy token">${icon('copy')}</button>` : ''}
      </span>
    </div>`;
  }).join('');
  return topbar('Tokens', `${withTok.length} account${withTok.length === 1 ? '' : 's'}`, list.length ? `
      <button class="btn ghost" data-action="reveal-all">${icon(allShown ? 'eyeoff' : 'eye')}${allShown ? 'Hide all' : 'Show all'}</button>
      <button class="btn" data-action="copy-all" data-mode="tokens">${icon('copy')}Copy tokens</button>
      <button class="btn primary" data-action="copy-all" data-mode="names">${icon('copy')}Copy with names</button>` : '') + `
    <div class="page">
      <div class="notice">${icon('warn')}<div>Anyone with these tokens can act as these GitHub accounts. Don't paste them in public chats. Every time this page is opened, it's logged in Activity.</div></div>
      ${list.length ? `<div class="list">
        <div class="tok-row tok-head"><span class="n">#</span><span>Name</span><span class="gh">GitHub</span><span>Token</span><span></span></div>
        ${rows}</div>` : '<div class="empty"><b>No scouter accounts yet.</b></div>'}
    </div>`;
}

function adminActivity() {
  const a = data.activity || [];
  return topbar('Activity', `last ${a.length}`) + `<div class="page">
    ${a.length ? `<ul class="feed box">${a.map((r) => `<li><time title="${esc(new Date(r.at).toLocaleString())}">${ago(r.at)} ago</time><span>${r.username ? `<b>${esc(r.username)}</b> <span class="faint">·</span> ` : ''}${esc(r.detail || r.action)}</span></li>`).join('')}</ul>` : '<div class="empty">Nothing yet.</div>'}
  </div>`;
}

function scouterAccount() {
  const a = data.accounts[0] || {};
  return topbar('Account') + `
  <div class="page"><div class="two">
    <section>
      <div class="section-h"><h2>Profile</h2></div>
      <div class="box pad"><dl class="props">
        <dt>Username</dt><dd>${esc(me.username)}</dd>
        <dt>GitHub</dt><dd><a class="mono" href="https://github.com/${esc(me.github_login)}" target="_blank" rel="noopener">@${esc(me.github_login)}</a></dd>
        <dt>Dev</dt><dd>${a.dev_username ? esc(a.dev_username) : '<span class="faint">not assigned yet</span>'}</dd>
        <dt>Last sync</dt><dd>${ago(a.last_sync)}${a.last_sync ? ' ago' : ''} ${a.sync_error ? `<div class="err">${esc(a.sync_error)}</div>` : ''}</dd>
      </dl></div>
    </section>
    <section>
      <div class="section-h"><h2>Replace GitHub token</h2></div>
      <form class="stack box pad" data-form="token">
        <label>New token <input name="token" class="mono" type="password" autocomplete="off" required placeholder="ghp_… or github_pat_…">
          <span class="hint">Use this if your token expired. It must belong to @${esc(me.github_login)}.</span></label>
        <button class="btn primary" type="submit">Save token</button>
      </form>
    </section>
  </div></div>`;
}

// ---------------- events ----------------
async function saveIssue() {
  const i = data.issues.find((x) => x.id === selected);
  if (!i) return;
  const d = draft && draft.id === i.id ? draft : null;
  if (!d) return toast('Nothing to save');
  await api(`/issues/${i.id}`, { status: d.status, pr_url: d.pr_url, note: d.note }, 'PATCH');
  draft = null;
  await load();
  toast('Saved');
}
function ensureDraft() {
  const i = data.issues.find((x) => x.id === selected);
  if (!draft || draft.id !== selected) draft = { id: i.id, status: i.status, pr_url: i.pr_url || '', note: i.note || '' };
  return draft;
}
function setTab(t) {
  tab = t;
  store.set('tab', t);
  if (t !== 'issues') filters.scouter = '';
  if (['activity', 'tokens'].includes(t)) return load();
  render();
}

app.addEventListener('click', async (e) => {
  const authBtn = e.target.closest('[data-auth]');
  if (authBtn) return renderAuth(authBtn.dataset.auth);

  const tabEl = e.target.closest('[data-tab]');
  if (tabEl) { e.preventDefault(); return setTab(tabEl.dataset.tab); }

  const acct = e.target.closest('[data-acct]');
  if (acct) { filters.scouter = acct.dataset.acct; tab = 'issues'; store.set('tab', tab); return render(); }

  const open = e.target.closest('[data-open]');
  if (open) {
    const id = Number(open.dataset.open);
    if (selected !== id) draft = null;
    selected = selected === id ? null : id;
    return render();
  }

  const pick = e.target.closest('[data-pick]');
  if (pick) {
    ensureDraft().status = pick.dataset.pick;
    pick.parentElement.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b === pick));
    return;
  }

  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  try {
    switch (action) {
      case 'logout':
        await api('/logout', {}); me = null; selected = null; data = {}; return boot();
      case 'password': {
        const current = prompt('Current password');
        if (!current) return;
        const next = prompt('New password (at least 8 characters)');
        if (!next) return;
        await api('/me/password', { current, password: next });
        return toast('Password changed');
      }
      case 'close':
        selected = null; draft = null; return render();
      case 'clear-acct':
        filters.scouter = ''; return render();
      case 'sync':
      case 'sync-one':
        btn.disabled = true;
        await api('/sync', action === 'sync-one' ? { scouter_id: Number(btn.dataset.id) } : {});
        await load();
        return toast('Synced with GitHub');
      case 'save-issue':
        return await saveIssue();
      case 'reset-pw': {
        const pw = prompt(`New password for ${btn.dataset.name} (at least 8 characters)`);
        if (!pw) return;
        await api(`/admin/users/${btn.dataset.id}/password`, { password: pw });
        return toast(`Password reset for ${btn.dataset.name}`);
      }
      case 'toggle-active': {
        const on = btn.dataset.active === '1';
        if (!on && !confirm(`Deactivate ${btn.dataset.name}? They'll be logged out and blocked from logging in.`)) return;
        await api(`/admin/users/${btn.dataset.id}/active`, { active: on });
        await load();
        return toast(`${btn.dataset.name} ${on ? 'reactivated' : 'deactivated'}`);
      }
      case 'reveal': {
        const id = Number(btn.dataset.id);
        revealed.has(id) ? revealed.delete(id) : revealed.add(id);
        return render();
      }
      case 'reveal-all': {
        const withTok = (data.tokens || []).filter((t) => t.token);
        const allShown = withTok.every((t) => revealed.has(t.id));
        revealed.clear();
        if (!allShown) withTok.forEach((t) => revealed.add(t.id));
        return render();
      }
      case 'copy-one': {
        const t = data.tokens.find((x) => x.id === Number(btn.dataset.id));
        if (t?.token && await copyText(t.token)) toast(`Copied token for ${t.username}`);
        return;
      }
      case 'copy-all': {
        const lines = [];
        (data.tokens || []).forEach((t, idx) => {
          if (!t.token) return;
          lines.push(btn.dataset.mode === 'names' ? `${idx + 1}. ${t.username} (@${t.github_login}): ${t.token}` : `${idx + 1}. ${t.token}`);
        });
        if (!lines.length) return toast('No tokens to copy', true);
        if (await copyText(lines.join('\n'))) toast(`Copied ${lines.length} token${lines.length > 1 ? 's' : ''}`);
        else toast('Copy failed. Show all and copy manually.', true);
        return;
      }
    }
  } catch (err) {
    toast(err.message, true);
    btn.disabled = false;
  }
});

app.addEventListener('change', async (e) => {
  const t = e.target;
  if (t.dataset.filter && t.tagName === 'SELECT') { filters[t.dataset.filter] = t.value; return render(); }
  if (t.dataset.assign) {
    try {
      await api('/admin/assign', { scouter_id: Number(t.dataset.assign), dev_id: t.value ? Number(t.value) : null });
      await load();
      toast('Assignment saved');
    } catch (err) { toast(err.message, true); }
  }
});

app.addEventListener('input', (e) => {
  const t = e.target;
  if (t.dataset.filter === 'q') { filters.q = t.value; return render(); }
  if (t.dataset.draft) ensureDraft()[t.dataset.draft] = t.value;
});

app.addEventListener('submit', async (e) => {
  const form = e.target.closest('form[data-form]');
  if (!form) return;
  e.preventDefault();
  const kind = form.dataset.form;
  if (['login', 'signup', 'setup'].includes(kind)) return submitAuth(form);
  const f = Object.fromEntries(new FormData(form));
  const btn = $('button[type=submit]', form);
  const label = btn.textContent;
  btn.disabled = true;
  try {
    if (kind === 'new-dev') { await api('/admin/devs', f); toast(`Dev ${f.username} created`); }
    if (kind === 'token') { btn.textContent = 'Checking…'; await api('/me/token', f); toast('Token updated and synced'); }
    await load();
  } catch (err) {
    toast(err.message, true);
    btn.disabled = false; btn.textContent = label;
  }
});

document.addEventListener('keydown', (e) => {
  if (!me) return;
  if (e.key === 'Escape' && selected) { selected = null; draft = null; render(); }
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && selected && canEdit()) {
    e.preventDefault();
    saveIssue().catch((err) => toast(err.message, true));
  }
});

boot();
