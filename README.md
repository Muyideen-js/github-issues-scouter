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

## Config (env vars)

| Var | Default | Meaning |
|---|---|---|
| `PORT` | 3000 | Port |
| `SYNC_MINUTES` | 15 | Auto-sync interval |
| `APP_SECRET` | auto-generated in `data/secret.key` | Key used to encrypt tokens. Back it up: if it's lost, every scouter must paste a new token. |
| `SECURE_COOKIE` | off | Set to `1` when serving over HTTPS |

Everything is stored in `data/` (SQLite). Back up that folder.
