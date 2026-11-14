# Tamper-Proof Cybersecurity Evidence Ledger

**Sign a message. Prove it is genuine. Make the history impossible to edit quietly.**

A web application in which a sender signs a message (or an evidence file) in the browser and a
receiver can check, at any time, that it really came from the claimed sender and has not been
changed. Every send and every check is written to a hash-chained, append-only ledger, so the
history cannot be edited without detection.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3-black)
![ECDSA](https://img.shields.io/badge/ECDSA-P--256-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-database-blue)
![Tests](https://img.shields.io/badge/tests-pytest-orange)

> SRM University B.Tech CSE (Cyber Security), Live Project 23CS0303A, 2026-27.
> Team: Chayan Das, Aditya Kaushik, Deepanshu Semwal.

---

## Contents
1. [What it does](#what-it-does)
2. [How it works](#how-it-works)
3. [Run it on your own computer](#run-it-on-your-own-computer)
4. [Set up Supabase](#set-up-supabase-external-anchor-and-file-storage)
5. [Deploy on Render, step by step](#deploy-on-render-step-by-step)
6. [Create an admin account](#create-an-admin-account)
7. [Using the application](#using-the-application)
8. [API overview](#api-overview)
9. [Tests](#tests)
10. [Project structure](#project-structure)
11. [Troubleshooting](#troubleshooting)
12. [Security notes and limits](#security-notes-and-limits)

---

## What it does

| Feature | Description |
|---|---|
| Browser-side signing | Each user creates an ECDSA P-256 key pair with the WebCrypto API. The private key stays in the browser; only the public key is sent to the server. |
| Seven verdicts | `GENUINE`, `TAMPERED`, `INVALID_SIGNATURE`, `UNKNOWN_SENDER`, `REPLAY`, `EXPIRED`, `REVOKED_KEY`. |
| Hash-chained ledger | Every send and every verification is an entry that stores the hash of the previous entry. Changing an old entry breaks the chain. |
| External anchor | The latest ledger hash is published to a separate service (Supabase), so rewriting the whole ledger is also detectable. |
| Alerts | Any verdict other than `GENUINE` raises an alert. |
| Per-message expiry | The sender can choose how long a signed message stays valid. |
| Evidence attachments | Files up to 10 MB (`pdf`, `txt`, `csv`, `png`, `jpg`, `jpeg`, `docx`) are hashed and kept in private storage. |
| Key backup | Download a private key backup, or keep a password-encrypted backup (PBKDF2 + AES-256-GCM, encrypted in the browser). |
| Attack demo | Admin-only page that runs six attacks and shows how each is detected. |

## How it works

```
 Sender's browser                         Server                         Receiver's browser
 ----------------                         ------                         ------------------
 1. create key pair (WebCrypto)
 2. send public key  ------------------>  store public key
 3. build canonical payload
    {sender, receiver, timestamp,
     nonce, message}
 4. SHA-256 hash + ECDSA sign
 5. send message + signature ---------->  store message
                                          append SENT to ledger  ----+
                                                                      |   hash chain
                                          6. receiver clicks "check"  |   + external anchor
                                          recompute hash, verify      |
                                          signature, nonce, expiry,   |
                                          key status                  |
                                          append VERIFIED to ledger --+
                                          verdict + alert if not GENUINE ---> shown to receiver
```

The canonical payload is built identically in the browser and in Python (fixed key order,
compact JSON, UTF-8), so non-English text and emoji verify correctly.

---

## Run it on your own computer

You need **Python 3.10 or newer** and **Git**. Redis and PostgreSQL are *not* needed locally:
the app falls back to SQLite and in-memory rate limiting in development.

**1. Clone the repository**
```bash
git clone https://github.com/project-deployer-s/Tamper-Proof_Cybersecurity_Evidence_Ledger.git
cd Tamper-Proof_Cybersecurity_Evidence_Ledger
```

**2. Create and activate a virtual environment**
```bash
python -m venv .venv
# Windows (Command Prompt):  .venv\Scripts\activate
# Windows (PowerShell):      .venv\Scripts\Activate.ps1
# macOS / Linux:             source .venv/bin/activate
```

**3. Install the dependencies**
```bash
pip install -r requirements.txt
```

**4. Create your settings file**
```bash
# Windows:        copy .env.example .env
# macOS / Linux:  cp .env.example .env
```
Open `.env` and set at least `SECRET_KEY`. Generate one with:
```bash
python -c "import secrets; print(secrets.token_hex(48))"
```
Leave `APP_ENV=development` and `DATABASE_URL=sqlite:///evidence_ledger.db` for local use.

**5. Create the database tables**
```bash
flask --app wsgi db upgrade
```

**6. Start the app**
```bash
flask --app wsgi run
```
Open <http://127.0.0.1:5000>.

> Always start the app through `wsgi.py` (`flask --app wsgi ...` or `gunicorn wsgi:app`).
> The `app/` folder is the application package; the top-level `app.py` is not used.

**What works without Supabase:** registration, key creation, signing, sending and checking
messages, alerts and the attack demos that do not touch the anchor. **What needs Supabase:**
the ledger's **Check the chain** button (it compares against the external anchor) and file
attachments. To enable them locally, follow the next section and put the two Supabase values in `.env`.

---

## Set up Supabase (external anchor and file storage)

Supabase holds the part of the evidence that must live *outside* your database: the published
ledger hash, and uploaded files. The free plan is enough.

1. Create a project at <https://supabase.com>.
2. Open **SQL Editor** and run this once:

```sql
-- Latest published ledger hash (always one row, id = 1)
create table if not exists public.ledger_anchor (
  id          integer primary key,
  latest_seq  bigint      not null,
  latest_hash text        not null,
  updated_at  timestamptz not null default now()
);

-- Every checkpoint ever published
create table if not exists public.ledger_anchor_history (
  seq         bigint      primary key,
  entry_hash  text        not null,
  anchored_at timestamptz not null default now()
);

-- Lock both tables to the public; the server's secret key bypasses this.
alter table public.ledger_anchor         enable row level security;
alter table public.ledger_anchor_history enable row level security;
```

3. Open **Storage**, create a bucket named exactly **`evidence-attachments`**, and leave it
   **private** (do not tick "Public bucket").
4. Open **Project Settings > API** and copy:
   - the **Project URL** into `SUPABASE_URL`
   - the **secret / service-role key** into `SUPABASE_SECRET_KEY`

The secret key is a server-side password. Never put it in front-end code, never commit it.

---

## Deploy on Render, step by step

You need free accounts on [GitHub](https://github.com), [Render](https://render.com) and
[Supabase](https://supabase.com). Do the Supabase section above first.

### 1. Put the code in your own GitHub repository
Fork this repository (or push a copy to your own account). Render deploys from GitHub.

### 2. Create the PostgreSQL database
Render dashboard > **New** > **PostgreSQL**. Pick a name and the region closest to you. When it
is ready, copy the **Internal Database URL**.

### 3. Create the Redis-compatible store
In production the app refuses to start without shared rate-limiting storage.
Render dashboard > **New** > **Key Value**. Use the **same region** as the database. Copy its
**Internal URL** (it begins with `redis://`).

### 4. Create the web service
Render dashboard > **New** > **Web Service** > connect your GitHub repository, then set:

| Setting | Value |
|---|---|
| Language / Runtime | Python 3 |
| Branch | `main` |
| Region | same as the database and Key Value |
| Build Command | `pip install -r requirements.txt && flask --app wsgi db upgrade` |
| Start Command | `gunicorn wsgi:app` |
| Health Check Path | `/health` |

### 5. Add the environment variables
In the web service > **Environment**:

| Variable | Value |
|---|---|
| `APP_ENV` | `production` |
| `PYTHON_VERSION` | `3.12.7` |
| `SECRET_KEY` | 64 or more random characters (`python -c "import secrets; print(secrets.token_hex(48))"`) |
| `DATABASE_URL` | Internal Database URL from step 2 |
| `REDIS_URL` | Internal URL from step 3 |
| `SUPABASE_URL` | from the Supabase section |
| `SUPABASE_SECRET_KEY` | from the Supabase section |

In production the app **will not start** unless `SECRET_KEY` is at least 64 characters,
`DATABASE_URL` is PostgreSQL and `REDIS_URL` is set. That is intentional.

### 6. Deploy
Click **Create Web Service**. The build installs the packages and creates the tables
(`flask --app wsgi db upgrade`). When the log shows the service is live, open:

- `https://<your-service>.onrender.com/health` -> should answer `{"status": "healthy"}`
- `https://<your-service>.onrender.com/` -> the sign-in page

### 7. Create an admin account
The attack demo and the alerts list need an admin. See the next section.

### 8. Before a demonstration
Render's free web service sleeps when idle. Open the site five minutes beforehand so it wakes
up. Check Render's current free-plan terms: free databases may expire or be limited, so do not
rely on one for data you must keep.

Every later `git push` to the branch redeploys automatically.

---

## Create an admin account

There is deliberately no public sign-up for admins. Register a normal account on the site
first (for example `admin`), then promote it.

**Local:**
```bash
flask --app wsgi shell
```
```python
from app.models import User
from app.extensions import db
u = User.query.filter_by(username="admin").first()
u.role = "admin"
db.session.commit()
exit()
```

**On Render:** use the database's **External Database URL** with `psql`
(or any PostgreSQL client):
```sql
UPDATE users SET role = 'admin' WHERE username = 'admin';
```
Sign out and sign in again so the new role takes effect.

---

## Using the application

| Page | What it does |
|---|---|
| `/` | Create an account, sign in, create your signing key |
| `/send.html` | Write a message, choose its expiry, attach a file, sign and send |
| `/inbox.html` | Open a received message and check it |
| `/ledger.html` | See the hash chain, **Check the chain**, and the alerts |
| `/demo.html` | Run the six attack demonstrations (admin only) |
| `/health` | Health check used by Render |

### Keep your private key safe
After creating your key, click **Download private key backup** and store the file somewhere
safe. Use the same browser for a demo, and not a private window, because the key lives in that
browser. If the key is lost, revoke it and create a new one. Anyone holding the backup file
can sign as you, so never share it or commit it.

### Five-minute demonstration
1. Register `alice` and `bob`. Let each create a key.
2. As alice, send "Hello Bob". As bob, open the inbox and check it: **Genuine**.
3. Sign in as the admin and open **Attack demo**. Run message tampering, forged signature,
   replay, expired message and revoked key. Each shows its expected verdict.
4. Open **Ledger**, click **Check the chain**: valid. Run the ledger-tampering demo and check
   again: the first broken entry is named.
5. Say the limit plainly: someone who rewrites the whole database *and* the external anchor
   together cannot be detected.

| Attack | Expected verdict |
|---|---|
| Message text changed | `TAMPERED` |
| Text changed and hash rewritten | `INVALID_SIGNATURE` |
| Same message submitted again | `REPLAY` |
| Signed message past its expiry | `EXPIRED` |
| Sender's key revoked | `REVOKED_KEY` |
| Ledger entry edited | Chain check reports the first broken entry |

---

## API overview

All routes are under `/api`. Everything except registration and login needs
`Authorization: Bearer <token>` (JWT, valid 30 minutes).

| Area | Routes |
|---|---|
| Accounts | `POST /users`, `POST /login`, `GET /users` |
| Keys | `POST` and `GET /users/{id}/keys`, `POST /users/{id}/keys/{key_id}/revoke`, `GET` and `PUT /users/{id}/keys/{key_id}/backup` |
| Messages | `POST /messages`, `GET /messages/inbox`, `GET /messages/sent`, `POST /messages/{id}/verify` |
| Ledger | `GET /ledger`, `GET /ledger/verify` |
| Alerts | `GET /alerts` (admin) |
| Attack demo | `GET /demo/attacks`, `POST /demo/attacks/{type}`, step-by-step `/demo/...` routes (admin) |

---

## Tests
```bash
python -m pytest
```
The suite covers hashing, canonical JSON, ECDSA signing and the browser signature format,
nonce and expiry rules, the seven verdicts, authentication, anchor integrity and the demos.

---

## Project structure
```
app/
  __init__.py        application factory (create_app)
  config.py          settings and production safety checks
  extensions.py      database, migrations, rate limiter, JWT
  models.py          users, keys, messages, ledger, alerts, outbox, attachments
  routes/api.py      the JSON API
  services/          ledger, verification, anchoring, storage, attachments, demos
security/            hashing, canonical JSON, ECDSA, nonce/expiry, verdicts
templates/ static/   the web pages, styles and browser scripts
pages.py             routes for the web pages
migrations/          database migrations (Flask-Migrate / Alembic)
tests/               automated tests
wsgi.py              entry point (gunicorn wsgi:app)
migrate_sqlite_to_postgres.py   one-off helper to copy a local SQLite database to PostgreSQL
.env.example         template for your settings
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Render deploy fails with "Production requires a SECRET_KEY..." | Use a `SECRET_KEY` of 64+ characters. |
| "Production requires a PostgreSQL database" | `DATABASE_URL` must be the Render PostgreSQL URL. |
| "Production requires REDIS_URL" | Create a Key Value instance and set `REDIS_URL`. |
| `ModuleNotFoundError` on build | Make sure `requirements.txt` is the one in this repository. |
| **Check the chain** says the check failed | `SUPABASE_URL` / `SUPABASE_SECRET_KEY` are missing or wrong, or the two anchor tables were not created. |
| Attachments fail | The bucket must be named `evidence-attachments`. |
| "Admin access required" in the attack demo | Promote the account (see above) and sign in again. |
| First page load takes about a minute on Render | The free service was asleep. Wait and refresh. |
| Messages cannot be signed after changing browser | The private key is stored per browser. Restore it from your backup file. |

---

## Security notes and limits

- The ledger is **tamper-evident, not tamper-proof**. An attacker who can rewrite the database
  and the external anchor together cannot be detected by this system.
- This is a tool for detecting tampering. It is not a guarantee of legal admissibility and not
  a replacement for established digital-forensics procedures.
- Private keys never leave the browser. The server stores public keys, signatures and
  hashes only.
- Keep all secrets in environment variables. `.env` is ignored by Git; never commit it, and
  never commit database dumps or key backups.

## License
MIT. See [LICENSE](LICENSE).
