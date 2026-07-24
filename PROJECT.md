# ZERONODE — Project Architecture

## Overview
ZeroNode is a strictly architected Flask application with a modular, *explicitly-registered* dashboard system and an E2EE (End-to-End Encrypted) user data vault.
Dashboard pages are self-contained **modules** loaded into a global shell template.

---

## Directory Structure

```
x:\projects\valt\
├── run.py                          # Server entrypoint
├── server_data.db                  # SQLite database (auto-created on startup)
├── requirements.txt
├── download_fonts.py               # One-shot utility to download Google Fonts locally
├── PROJECT.md                      # This file
├── E2EE_FLOW.md                    # Chunked encryption protocol specification
│
├── data/                           # User-isolated encrypted storage (gitignored)
│   └── <user_id>/
│       ├── <user_id>.db            # Per-user SQLite (files, config, custom tables)
│       └── <uuid>.bin              # Encrypted file blobs
│
└── app/
    ├── __init__.py                 # Flask App Factory (registers blueprints + mounts modules)
    ├── config.py                   # SSO credentials, CORS origins, DATA_DIR, session cookie
    │
    ├── modules/                    # Backend utility modules (pure Python, no Flask routes)
    │   ├── __init__.py
    │   ├── db_handler.py           # SQLite: users, whitelist, sessions (WAL mode)
    │   └── user_data.py            # E2EE UserDataManager + get_user_manager() helper
    │
    ├── routes/                     # Public routes (no auth required)
    │   ├── __init__.py
    │   ├── client.py               # / (landing), /login, /dash shortcut
    │   └── auth.py                 # /auth/login, /auth/callback, /auth/logout + session helpers
    │
    ├── static/                     # Global static assets
    │   ├── css/fonts.css           # Local Google Fonts CSS
    │   ├── fonts/                  # .woff2 font binaries
    │   └── js/tailwind.js          # Local Tailwind CDN script
    │
    ├── templates/view/             # Public page templates (unauthenticated)
    │   ├── index.html              # Landing page (/)
    │   └── login.html              # SSO login page (/login)
    │
    └── dash/                       # Protected dashboard system + REST API
        ├── __init__.py             # Dashboard Blueprint + auth gate + File API endpoints
        ├── loader.py               # Module Loader (manifest validator + route registrar)
        ├── shell.html              # Global shell template (bottom nav + content canvas)
        └── modules/                # Dashboard modules (addons)
            └── <module_name>/
                ├── manifest.py     # Module declaration (name, routes, view handler)
                └── index.html      # Main template (extends shell.html)
```

---

## Authentication Flow

```
User → /login → "AUTH WITH DKYDIVYANSH SSO"
  → /auth/login
      Sets sso_state cookie (CSRF protection, 5 min TTL)
      Redirects to: sso.sixthminds.com/api/authorize?client_id=...&scope=...&state=...

SSO → User logs in & consents → redirects to:
  /auth/callback?code=<JWT>&state=<original_state>

  → CSRF check: state cookie vs URL param
  → POST /api/token { client_id, client_secret, code }   ← server-to-server
      Returns: access_token (JWT)
  → POST /api/userinfo { client_id, client_secret, access_token }
      Returns: user profile
  → Whitelist check: email in whitelist table?
      NO  → redirect /login?error=access_denied
      YES → upsert user in DB, create 24h session token
          → Set httponly cookie → redirect /app/home
```

### Session Rules
- **24-hour lifetime** — enforced in both the DB `expires_at` column and the cookie `max_age`
- **All `/app/*` routes** enforce auth via Blueprint `before_request` hook — zero exceptions
- **Session purging** — expired sessions are automatically deleted on every validation call
- `/auth/logout` destroys the DB session row and clears the cookie

---

## Module Loader System

### How It Works

```
App Factory starts
  → registers dashboard Blueprint (/app prefix)
  → calls init_modules(app)
       → calls loader.load_modules(blueprint)
            → reads REGISTERED_MODULES list in loader.py
            → for each module name:
                 1. Check dash/modules/<name>/ exists
                 2. Check dash/modules/<name>/manifest.py exists
                 3. Import manifest.py → instantiate Manifest()
                 4. Validate: name and routes must be non-empty
                 5. For each route in manifest.routes:
                      blueprint.add_url_rule(/<name><route>, view=manifest.get_view)
                 6. Log: ✓ Module 'Home' mounted → ['/app/home']
```

### Route Mounting Logic

A module declaring `routes = ["/", "/<path:sub>"]` with folder name `home` gets:

| Manifest route | Mounted at    |
|----------------|---------------|
| `/`            | `/app/home`   |
| `/<path:sub>`  | `/app/home/<path:sub>` |

### Adding a New Module

**Step 1** — Create the module folder:
```
app/dash/modules/settings/
├── manifest.py
└── index.html
```

**Step 2** — Write `manifest.py`:
```python
from flask import render_template, g
from app.dash.loader import ModuleManifest

class Manifest(ModuleManifest):
    name        = "Settings"
    description = "User settings and preferences."
    routes      = ["/"]   # mounts at /app/settings

    def get_view(self, module_name, **kwargs):
        return render_template(f"modules/{module_name}/index.html", user=g.user)
```

**Step 3** — Write `index.html` (extends shell):
```html
{% extends "shell.html" %}
{% block title %}SETTINGS{% endblock %}

{% block dynamic_menu %}
<button onclick="alert('Action!')" class="font-label text-[10px] text-primary interactive-el uppercase">Settings Action</button>
{% endblock %}

{% block content %}
<div class="p-8">
    <h1 class="font-headline text-3xl text-on-surface">Settings</h1>
</div>
{% endblock %}
```

**Step 4** — Register in `loader.py`:
```python
REGISTERED_MODULES = [
    "home",
    "settings",   # ← add here
]
```

**Step 5** — Restart server. Module is live at `/app/settings`.

> ⚠️ A module NOT in `REGISTERED_MODULES` is **completely invisible** to the router — its folder can exist on disk but will never be routable.

### Global Navigation & Dynamic Menus

The dashboard leverages a dynamic layout rendered entirely by the Python backend via Jinja2 Context Processors (`app/dash/__init__.py`).
*   **The Left Navigation List:** The system passes `app_modules` into every template context, automatically constructing the global tab bar. The currently active app is highlighted natively via Jinja conditional evaluation (`module_name == mod_id`).
*   **The Right Module Menu Block:** Individual module templates can override `{% block dynamic_menu %}` to inject their own highly custom buttons and Javascript onclick functions into the bottom shell menu bar.

## Client-Side Cryptography (`VaultCrypto`)

ZeroNode utilizes a true End-to-End Encrypted (E2EE) architecture. The server **never** stores the user's Master Password, nor the plaintext decryption keys. All cryptographic operations occur exclusively in the browser using the native `WebCrypto API` (`app/static/js/main.js`).

### The Vault Key Exchange Flow
Every payload stored in the vault is encrypted with its own unique File AES Key (the DEK - Data Encryption Key). To securely store these DEKs, ZeroNode wraps them using an overarching ECDH Keypair generated by the user's browser.

1. **Master Credential Setup (PBKDF2):** When a user initializes their vault, the browser hashes their Master Credentials (password) using `PBKDF2` (SHA-256, 250,000 iterations) and a random salt to derive a 256-bit `Master_Vault_Key`.
2. **Elliptic Curve Generation (ECDH):** The browser generates a highly secure, microscopic `P-256 ECDH Keypair`. 
3. **Key Wrapping (AES-GCM):** The `Master_Vault_Key` is used to encrypt the user's ECDH Private Key using `AES-GCM`.
4. **Cloud Backup (Blind Storage):** The browser uploads the Public Key, the *encrypted* Private Key, and the salt to the server (`/api/key/save`). The server stores these blindly.

### The Session Unlock Flow
When a user launches the app, an unskippable "Secured Interface Overlay" intercepts the screen (`shell.html`).
1. The frontend hits `GET /api/key/load` to retrieve the encrypted Private Key bundle.
2. The user provides their Master Credentials to the interface.
3. The browser re-derives the PBKDF2 `Master_Vault_Key` and attempts to decrypt the Private Key bundle.
4. If successful, the raw Private Key is held strictly in `sessionStorage` (memory) for the duration of the active tab. The overlay fades out, and the dashboard modules render, now possessing the keys required to decode files on the fly.

---

## E2EE Data Vault (`UserDataManager`)

ZeroNode features an **End-to-End Encrypted (E2EE) User Data Architecture**. All user files and configuration overrides are localized into isolated directories on the filesystem. The server is cryptographically blind — it stores only raw `.bin` blobs and encrypted AES keys it cannot read.

### File Structure & Isolation
```
x:\projects\valt\data\
└── <user_id>\
    ├── <user_id>.db       # User-localized database (Config & metadata)
    └── <uuid>.bin         # Encrypted raw file blobs
```

### REST API Endpoints

All endpoints live under `/app/api/` and are strictly auth-gated by the `before_request` session hook. No unauthenticated access is possible.

#### Chunked Upload (3-Phase)

| Phase | Method | Endpoint | Input | Output |
|-------|--------|----------|-------|--------|
| **Init** | `POST` | `/app/api/file/init` | JSON: `{ "file_name": "report.pdf", "aes_key": "enc..." }` | `{ "uuid": "abcd-1234" }` (201) |
| **Chunk** | `POST` | `/app/api/file/<uuid>/chunk` | Header: `X-Chunk-Offset: <byte_int>`, Body: raw bytes | `{ "status": "ok", "offset": 0, "size": 1048576 }` (200) |
| **Finalize** | `POST` | `/app/api/file/<uuid>/finalize` | — | `{ "uuid": "...", "file_name": "...", "size": 10485760, "last_modified": "..." }` (200) |

> **Parallel Uploads:** Because each chunk specifies its byte offset via `X-Chunk-Offset`, the frontend can fire multiple chunk requests simultaneously from Web Workers. The backend uses OS-level `seek()` to write each chunk to the correct position independently.

#### Download

| Method | Endpoint | Notes |
|--------|----------|-------|
| `GET` | `/app/api/file/<uuid>` | Streams via `send_file()` with WSGI FileWrapper. Supports HTTP `Range` headers for resume/partial content. Zero RAM footprint. |

#### Metadata

| Method | Endpoint | Input | Output |
|--------|----------|-------|--------|
| `GET` | `/app/api/file/<uuid>/meta` | — | File metadata JSON (uuid, file_name, aes_key, etc.) |
| `PATCH` | `/app/api/file/<uuid>/meta` | JSON: `{ "file_name": "new.pdf" }` and/or `{ "aes_key": "new_key" }` | `{ "status": "updated" }` |

#### Listing & Deletion

| Method | Endpoint | Input | Output |
|--------|----------|-------|--------|
| `GET` | `/app/api/files` | Query: `?limit=100&offset=0` (max limit: 500) | `{ "files": [...], "limit": 100, "offset": 0, "count": 42 }` |
| `DELETE` | `/app/api/file/<uuid>` | — | `{ "status": "deleted", "uuid": "..." }` |

### Module Backend Usage (Python)
Modules interact with the `UserDataManager` internally. The `get_user_manager()` helper locks all operations to the authenticated user automatically.

```python
from app.modules.user_data import get_user_manager

def secure_route():
    manager = get_user_manager()
    
    # Small file (backward compat) — stores entire blob at once
    file_uuid = manager.store_file("secret.txt", b"enc_blob", "aes_key_enc")
    
    # Chunked upload — for large files
    uuid = manager.init_file_upload("big_video.mp4", "aes_key_enc")
    manager.write_file_chunk(uuid, chunk_bytes, offset=0)
    manager.write_file_chunk(uuid, chunk_bytes2, offset=1048576)
    result = manager.finalize_file(uuid)
    
    # Metadata modification (strict: only file_name and aes_key are mutable)
    manager.update_file_metadata(uuid, file_name="renamed.mp4")
    
    # Config key/value store
    manager.config_set("theme", "dark")
    manager.config_get("theme")        # → "dark"
    manager.config_delete("theme")     # → True
```

### Dedicated Custom Data Stores
Modules can create their own tables inside the user's localized database using raw SQL queries, fully sandboxed from other users.

```python
manager = get_user_manager()
manager.execute_query("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, note TEXT)")
manager.execute_query("INSERT INTO notes (note) VALUES (?)", ("Encrypted note",))
rows = manager.fetch_all("SELECT * FROM notes")
```

### User Schema (`<user_id>.db`)
Each localized SQLite database contains:
- `files`: `uuid` (PK), `file_name`, `last_modified`, `owner`, `aes_key` (encrypted).
- `config`: `id`, `key` (UNIQUE), `value`.
- *Custom module tables*: Created dynamically via `execute_query()`.

> **Security Note:** The server only possesses raw `.bin` bytes and encrypted `aes_key`s. The actual keys to decrypt the `aes_key`s never touch the server — keeping the vault perfectly blind.

---

## Global Database (`server_data.db`)

| Table       | Columns (key ones)                          | Purpose                        |
|-------------|---------------------------------------------|--------------------------------|
| `users`     | user_id, email, first_name, last_name, profile_photo, access_token, scope | SSO user profiles |
| `admins`    | email, added_at                             | Privileged access ledger       |
| `whitelist` | email, added_at                             | Access control gate            |
| `sessions`  | session_token, user_id, expires_at          | Active login sessions          |

---

## Administrative Security Model

ZeroNode implements a multi-tier security topology to protect both user data and system integrity.

### Root-of-Trust Bootstrapping
The system utilizes an **Environmental Bootstrap Vector** to establish its first administrator without manual database intervention:
1. **Detection**: Upon every boot, the system scans the host environment for the `ADMIN_EMAIL` variable.
2. **Promotion**: If detected, the system autonomously performs a **Mutual Whitelisting** (adding the email to the `whitelist` and `admins` ledger simultaneously).
3. **Persistence**: Once whitelisted, the administrator remains privileged even if the environment variable is removed, as the record is committed to the physical `admins` ledger.

### Tiered Role Architecture
Access levels are verified in a strict, sequential chain:
*   **Tier 0 (SSO)**: Identity is verified by the trusted SSO provider.
*   **Tier 1 (Whitelisting)**: Access to the application dashboard is restricted to emails in the `whitelist` ledger.
*   **Tier 2 (Administrative)**: Privileged operations (User management, system overrides) are restricted to emails in the `admins` ledger. Access is physically enforced by the `admin_only` flag in the module manifests.

---

## Forensic Telemetry & Analytics

ZeroNode includes a built-in **Administrative Telemetry Suite** for real-time resource monitoring.

### System Telemetry
- **OS-Level Disk Health**: Live tracking of the host machine's disk usage (Total/Used/Free) via `shutil.disk_usage()`.
- **Global Storage Scanner**: Forensic aggregation of the physical disk footprint across every identity in the vault.

### Administrative API (Tier-2)
The `admin` module exposes a high-integrity API cluster at `/app/admin/api/*`:

| Endpoint | Method | Purpose |
|----------|:---:|---------|
| `/stats` | `GET` | Unified payload: storage reports, disk health, whitelist, and admin ranks. |
| `/promote` | `POST` | Authoritative elevation of a whitelisted user to Admin status. |
| `/demote` | `POST` | Revocation of administrative privileges (protected against self-demotion). |
| `/whitelist/add` | `POST` | Global registration of and identity in the access ledger. |
| `/whitelist/remove` | `POST` | Physical eviction of an identity from the vault entry point. |

> [!IMPORTANT]
> **Privilege Isolation**: All administrative API routes inherit the strict `admin_only` protection defined in the `loader.py`, ensuring zero-bypass security for privileged operations.

---

---

## Security Analysis

### ✅ Implemented Correctly
- CSRF state verification on OAuth callback (cookie vs URL param comparison)
- `httponly=True` on session cookies (no JS access)
- `samesite='Lax'` on both cookies (CSRF protection for cross-site requests)
- Server-to-server token exchange (client_secret never exposed to browser)
- Session expiry enforced in DB + cookie simultaneously
- All `/app/*` routes use `before_request` — not per-route decorators (no accidental bypass)
- Whitelist check performed *after* SSO verification (no pre-auth bypass)
- No directory traversal in old asset route (removed in current version)
- WAL mode SQLite (concurrent reads without blocking writes)

### ⚠️ Known Risks (Dev vs Production)
| Risk | Current State | Fix for Production |
|------|:---:|---|
| `secure=False` on cookie | Dev only | Set `secure=True` + enforce HTTPS |
| Client secret hardcoded in `config.py` | Dev convenience | Move to env vars / secrets manager |
| SQLite not suitable for multi-process | Single process OK | Migrate to PostgreSQL for scaled deploy |
| Flask debug mode exposes PIN | Dev only | `FLASK_ENV=prod` disables debugger |
| No rate limiting on `/auth/callback` | Low risk (SSO validates codes) | Add `flask-limiter` for production |

### ✅ Module Loader Security
- Modules are **whitelist-only** — filesystem presence ≠ routability
- `importlib` import path is constructed from the registry (not from URL/user input)
- Endpoint names are sanitized via `replace()` before registration

---

## Tech Stack
- **Backend**: Python Flask (App Factory + Blueprints, no ORM)
- **Database**: SQLite with WAL mode (`server_data.db`)
- **Auth**: OAuth 2.0 Authorization Code Grant (Dkydivyansh SSO)
- **Frontend**: Tailwind CSS (locally served), Jinja2 templates
- **CORS**: `flask-cors` with strict origin whitelist
- **Zero npm** — all assets fetched once via Python and served locally
