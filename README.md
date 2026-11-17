# Issue Scouter

Team platform for GitHub issues:

- **Scouters** apply for issues on GitHub. They sign up once with a GitHub token, then log in with a username and password.
- **Admin** links each scouter account to a dev and monitors everything.
- **Devs** see every issue assigned to their linked accounts, fix it, attach the PR, and update the status.

## Run

```
npm install
npm start
```

On first run, open http://localhost:3000 to create the admin account.

Each role has its own page:

| URL | Who |
|---|---|
| `/` | Admin login (and first-run setup) |
| `/scouter` | Scouters log in and sign up |
| `/dev` | Developers log in |

## How it works

1. A scouter signs up on the login page: GitHub token + username + password. The token is checked against GitHub and stored encrypted (AES-256-GCM).
2. Every 15 minutes (or when someone clicks **Sync**), the server pulls issues assigned to each scouter's GitHub account, plus their PRs.
3. Admin → **Team**: create devs and pick a dev for each scouter account.
4. The dev sees the issues grouped by account and sets the status, PR link and notes.
5. PRs that mention the issue (`#42`, `Fixes #42`, or the issue URL) are linked automatically. Merged PR → **Merged**; issue closed → **Closed**; unassigned on GitHub → **Unassigned**.

## Deploy to Vercel

The app runs as a serverless function on Vercel, with the database on **Turso** (hosted libSQL) since Vercel has no persistent disk.

1. **Create a Turso database** (free) at [turso.tech](https://turso.tech) — or add the **Turso integration** from the Vercel Marketplace, which sets the two `TURSO_*` env vars for you. Note the database URL (`libsql://…`) and an auth token.
2. In Vercel: **New Project → Import** this GitHub repo.
3. Add **Environment Variables**:
   - `TURSO_DATABASE_URL` — your `libsql://…` URL
   - `TURSO_AUTH_TOKEN` — the Turso token
   - `APP_SECRET` — any long random string (used to encrypt GitHub tokens; keep it stable or stored tokens stop decrypting)
   - `CRON_SECRET` — any random string (protects the sync cron endpoint)
4. **Deploy.** Open the site and create the admin account at `/`.

`vercel.json` adds a cron that hits `/api/cron/sync` hourly to refresh issues. On Vercel's free (Hobby) plan crons effectively run about once a day — in between, anyone can press **Sync** in the UI to refresh on demand.

Locally (no Turso vars) it falls back to a SQLite file in `data/`, so `npm start` still works unchanged.

## Config (env vars)

| Var | Default | Meaning |
|---|---|---|
| `PORT` | 3000 | Port |
| `SYNC_MINUTES` | 15 | Auto-sync interval |
| `APP_SECRET` | auto-generated in `data/secret.key` | Key used to encrypt tokens. Back it up: if it's lost, every scouter must paste a new token. |
| `SECURE_COOKIE` | off | Set to `1` when serving over HTTPS |

Everything is stored in `data/` (SQLite). Back up that folder.
