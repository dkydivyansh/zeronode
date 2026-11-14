# ZERONODE — System Architecture & Developer Manual

## 1. Executive Summary

ZeroNode is an ultra-secure, privacy-first, zero-knowledge vault application built on Flask, SQLite, and the browser's native WebCrypto API. The architecture enforces a **cryptographically blind server model**:

- **Server-Side Blindness:** The host server stores only raw AES-GCM ciphertext payloads (`.bin` files) and wrapped Data Encryption Keys (DEKs).
- **Zero Plaintext Ingestion:** The server never receives, knows, or processes master passwords, private keys, or unencrypted file bytes.
- **Strict User Partitioning:** Global server operations, authentication records, and whitelist ledgers reside in `data/server_data.db`, while each user's encrypted vault operates within an isolated directory `data/<user_id>/` featuring its own localized SQLite metadata database (`<user_id>.db`).

---

## 2. Global Repository Structure

```
zeronode/
├── run.py                          # Server entrypoint (Waitress WSGI / Flask Dev)
├── requirements.txt                # Python runtime dependencies
├── Dockerfile                      # Production container image definition
├── docker-compose.yml              # Container orchestration & persistent volume mapping
├── .env / .env.example             # Secret configurations, SSO bindings, paths
├── E2EE_FLOW.md                    # Cryptographic chunking & key exchange specification
├── PROJECT.md                      # System architecture and developer manual (this file)
│
├── backup-server/                  # Standalone PHP/SQLite Remote Backup Server
│   ├── config.php                  # API authentication keys, retention limits, storage paths
│   ├── db.php                      # SQLite PDO layer, schema auto-migration, auth guards
│   ├── index.php                   # Diagnostic visual landing & request router
│   ├── README.md                   # Deployment guide for PHP standalone server
│   └── api/                        # REST API endpoints
│       ├── init.php                # Upload session initiation & target binding
│       ├── chunk.php               # Chunk receiver with per-chunk SHA-256 validation
│       ├── finalize.php            # Assembly, file-level SHA-256 check, & retention pruning
│       ├── list.php                # Query stored remote archives & telemetry
│       ├── download.php            # Secure streaming of backup packages
│       ├── delete.php              # Manual archive purging
│       └── health.php              # Diagnostic node health check
│
├── data/                           # User-isolated encrypted storage & master DB (gitignored)
│   ├── server_data.db              # Master SQLite database (users, sessions, whitelist, admins)
│   └── <user_id>/                  # Individual user vault directory
│       ├── <user_id>.db            # User-localized metadata database (Drive hierarchy & config)
│       └── <uuid>.bin              # Raw AES-GCM encrypted file chunks (5MB chunked blocks)
│
└── app/                            # Application source code
    ├── __init__.py                 # Flask App Factory (blueprints, security headers, CORS)
    ├── config.py                   # Environment configuration & credential manager
    │
    ├── modules/                    # Pure Python backend engines (no Flask route decorators)
    │   ├── __init__.py
    │   ├── db_handler.py           # Master DB operations, sessions, admins, server liquidation
    │   ├── user_data.py            # Per-user E2EE filesystem & SQLite manager (UserDataManager)
    │   └── backup_manager.py       # Chunked uploader, background scheduler, disaster recovery engine
    │
    ├── routes/                     # Public / unauthenticated route controllers
    │   ├── __init__.py
    │   ├── client.py               # Landing page (/), login view, dash shortcut
    │   └── auth.py                 # OAuth 2.0 / SSO handshake, state validation, sessions, exit
    │
    ├── dash/                       # Authenticated dashboard framework (/app/*)
    │   ├── __init__.py             # Dashboard Blueprint, auth gate, core File & Key REST APIs
    │   ├── loader.py               # Pluggable dynamic module loader & manifest registrar
    │   ├── shell.html              # Master layout shell, bottom bar, PBKDF2 vault unlock modal
    │   └── modules/                # Self-contained dashboard feature modules
    │       ├── home/               # System overview module (identity, quota stats, quick actions)
    │       ├── drive/              # E2EE file explorer, folder trees, note editor, previewer
    │       ├── backup/             # Vault disaster recovery, manual backups, upload restore
    │       └── admin/              # Node administration, whitelist, disk stats, system wipe
    │
    ├── static/                     # Static assets (offline self-hosted, zero external CDNs)
    │   ├── css/                    # Typography (fonts.css) & global styles (style.css)
    │   ├── fonts/                  # Self-hosted WOFF2 font files (Inter, Noto Serif, Space Grotesk)
    │   ├── js/                     # Client crypto (main.js), drive (drive.js), wordlist (wordlist.js), tailwind runtime
    │   ├── vendor/                 # Markdown parser (marked.min.js), HTML parser (turndown.js)
    │   ├── icon.ico                # Favicon
    │   └── profile.avif            # Fallback avatar
    │
    └── templates/view/             # Public unauthenticated web templates
        ├── index.html              # Responsive landing hero page with interactive canvas
        ├── login.html              # SSO initialization interface
        ├── logout.html             # Client-side cryptographic cache purging screen
        └── deprovisioned.html      # System liquidation confirmation landing screen
```

---

## 3. Application Lifecycle & Configuration

### 3.1 Application Factory (`app/__init__.py`)
1. **Instantiation**: `create_app(config_name)` creates the Flask instance and loads `DevelopmentConfig` or `ProductionConfig`.
2. **Database Initialization**: Invokes `db_handler.init_db()` to configure WAL mode, create master tables (`users`, `whitelist`, `admins`, `sessions`), and bootstrap root administrator credentials from `ADMIN_EMAIL`.
3. **CORS Configuration**: Binds `flask_cors.CORS` with explicit origin reflection from `ALLOWED_ORIGINS` and credential support.
4. **Dynamic Module Mounting**: Calls `load_modules(dashboard_bp)` before blueprint registration, dynamically loading manifests from `app/dash/modules/`.
5. **Blueprint Registration**:
   - `client_bp` mounted at `/`
   - `auth_bp` mounted at `/auth`
   - `dashboard_bp` mounted at `/app`
6. **Mandatory Security Headers**: Injected via `@app.after_request`:
   - `Content-Security-Policy`: Disallows unauthorized script execution and frame embedding.
   - `Cross-Origin-Opener-Policy`: `same-origin` isolates browsing contexts.
   - `Cross-Origin-Resource-Policy`: `same-origin` prevents cross-origin asset leakage.
   - `X-Frame-Options`: `DENY` eliminates clickjacking vectors.
   - `X-Content-Type-Options`: `nosniff` prevents MIME confusion attacks.

### 3.2 Configuration Engine (`app/config.py`)
- Reads `.env` from disk or environment variables.
- Defaults `DATA_DIR` to `zeronode/data` (can be overridden via environment variable for Docker volume mappings).
- Configures `SSO_BASE_URL`, `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_REDIRECT_URI`, `SSO_SCOPE`.
- Configures session cookie parameters: `SESSION_COOKIE_NAME = 'znode_session'`, `24-hour` lifetime, `httponly=True`, `samesite='Lax'`.

---

## 4. Authentication & Session Architecture

ZeroNode utilizes an **OAuth 2.0 Authorization Code Grant** flow integrated with Dkydivyansh SSO (`app/routes/auth.py`).

```
User               ZeroNode Server                 SSO Provider
 |                        |                              |
 |-- 1. GET /login ------>|                              |
 |                        |-- 2. Redirect /api/auth ---->| (Sets sso_state CSRF cookie)
 |                        |<-- User authenticates -------|
 |<-- 3. Redirect back ---|                              |
 |    with ?code=&state=  |                              |
 |                        |                              |
 |-- 4. GET /callback --->|                              |
 |                        |-- 5. POST /api/token ------->| Server-to-server code exchange
 |                        |<-- Returns access_token -----|
 |                        |                              |
 |                        |-- 6. POST /api/userinfo ---->| Retrieve user profile
 |                        |<-- Returns email, name, etc -|
 |                        |                              |
 |                        |-- 7. Whitelist Check --------+ Enforces whitelist table
 |                        |   (Rejects unlisted users)   |
 |                        |                              |
 |                        |-- 8. Upsert user in DB       |
 |                        |-- 9. Create 24h session token|
 |<-- 10. Set-Cookie -----|                              | (Redirects to /app/home)
```

### 4.1 Key Security Protocols in Auth
1. **CSRF State Validation**: A cryptographic token (`secrets.token_urlsafe(32)`) is set in a 5-minute HTTP-only `sso_state` cookie and verified against the callback parameter.
2. **Server-to-Server Token Exchange**: The `client_secret` is kept exclusively on the server and is never exposed to the client.
3. **Forced IPv4 Resolution**: `socket.getaddrinfo` is monkey-patched in `auth.py` (`_getaddrinfo_ipv4`) to prevent Docker/WSL DNS resolution timeouts caused by unsupported IPv6 network stacks.
4. **Pre-Authorization Whitelist Gate**: Even after authenticating with SSO, users whose emails are absent from the `whitelist` table are instantly rejected (`/login?error=access_denied`).
5. **Cryptographic Cache Purge on Logout**: Navigating to `/auth/logout` revokes the database session, clears cookies, and redirects to `/auth/exit`. The rendered interface (`logout.html`) runs an automated client-side script that authoritatively clears:
   - IndexedDB `ZNodeSession` (unwrapped private keys)
   - IndexedDB `ZeroNodeVaultCache` (cached encrypted file blobs)
   - `sessionStorage` and `localStorage` session artifacts.

---

## 5. Dynamic Module Loader System (`app/dash/`)

The authenticated dashboard (/app/*) uses an extensible, manifest-driven plugin architecture (`app/dash/loader.py`).

### 5.1 Registration & Route Mounting
Modules are activated strictly through `REGISTERED_MODULES` in `loader.py`:
```python
REGISTERED_MODULES = [
    "home",
    "drive",
    "admin",
]
```
For every entry in `REGISTERED_MODULES`:
1. Verifies that `app/dash/modules/<name>/manifest.py` exists.
2. Dynamically imports `Manifest` inheriting from `ModuleManifest`.
3. Validates declared route endpoints.
4. Registers routes on `dashboard_bp` mapped to `/<name><route>`.
5. Enforces `admin_only` privilege isolation at route dispatch time.

### 5.2 Active Modules
| Module | Manifest Route | Mounted Endpoint | Access | Purpose |
|--------|----------------|------------------|:------:|---------|
| **Home** | `/` | `/app/home` | Authenticated | System status, storage telemetry, identity card, quick access |
| **Drive** | `/`, `/<path:sub>` | `/app/drive`, `/app/drive/*` | Authenticated | E2EE file explorer, folder manager, notes, PDF viewer |
| **Admin** | `/`, `/api/*` | `/app/admin`, `/app/admin/api/*` | Admin Only | User whitelist, admin ranks, storage reports, nuclear liquidation |

---

## 6. End-to-End Cryptography Architecture

All client cryptographic routines are encapsulated within `VaultCrypto` (`app/static/js/main.js`) and `DriveCrypto` (`app/static/js/drive.js`).

### 6.1 Cryptographic Primitives & Derivations
- **Master Password Derivation**:
  - Algorithm: `PBKDF2-SHA256`
  - Rounds: `250,000 iterations`
  - Salt: 16-byte random cryptographically secure salt (`Uint8Array(16)`)
  - Output: 256-bit AES-GCM Key (`Master_Vault_Key`)
- **Asymmetric Vault Keypair**:
  - Algorithm: `ECDH` over NIST `P-256` curve
  - Export: Public Key as `spki` (Base64), Private Key as `pkcs8`
- **Dual-Wrap Key Hierarchy**:
  - **Wrap A (Password):** Private Key encrypted with `Master_Vault_Key` using `AES-256-GCM` (12-byte random IV) $\rightarrow$ `encrypted_private_key`.
  - **Wrap B (BIP-39 Seed Phrase):** 12 random words generated from a 2048-word dictionary (`wordlist.js`), derived via `PBKDF2-SHA256` with `recovery_salt` $\rightarrow$ `recovery_encrypted_private_key`.
  - Both wrapped bundles are stored blindly in `<user_id>.db` `config` table.
- **Session Protection**:
  - The unwrapped private key is imported into WebCrypto with `extractable = false`.
  - It is stored in IndexedDB (`ZNodeSession`, objectStore: `keys`, key: `vault_priv`).
  - Active session state is flagged in `sessionStorage` (`vault_unlocked = "true"`).
- **File Data Encryption Keys (DEKs)**:
  - **VaultMasterKey Derivation:** The client performs self-ECDH derivation (`crypto.subtle.deriveKey({ name: "ECDH", public }, priv, { name: "AES-GCM", length: 256 })`) to obtain a symmetric wrapping key.
  - **File Key Generation:** Each file is encrypted with a unique 256-bit AES-GCM DEK (`fileKey`).
  - **DEK Wrapping:** The DEK is exported, encrypted with `VaultMasterKey` using AES-256-GCM with a 12-byte random IV, packed as:
    $$[\text{12-byte IV}] \parallel [\text{32-byte Encrypted DEK}] \parallel [\text{16-byte Auth Tag}]$$
    and Base64-encoded as `aes_key` in the `files` database table.

---

## 7. Chunked File Storage Pipeline (`UserDataManager`)

ZeroNode utilizes **5 MB chunked encryption** (`OPFS_CHUNK_SIZE = 5,242,880 bytes`).

### 7.1 Deterministic IV Derivation per Chunk
To prevent nonce reuse without adding overhead to chunk payloads, the 12-byte IV is derived deterministically from the 32-bit chunk index:
```javascript
const iv = new Uint8Array(12);
new DataView(iv.buffer).setUint32(8, chunkIdx, false); // Bytes 8..11 = Big-Endian index
```
Since every file has a unique, random 256-bit DEK, this guarantees mathematical uniqueness per chunk across the entire vault.

### 7.2 Three-Phase Chunked Upload
1. **Init (`POST /app/api/file/init`)**:
   - Takes `{ "file_name": "...", "aes_key": "...", "folder_id": null }`.
   - Triggers `_cleanup_stale_uploads()` (purges incomplete uploads older than 5 minutes).
   - Generates UUID, touches empty `<uuid>.bin` on disk, records row in `files` table with `file_size = -1`.
2. **Chunk (`POST /app/api/file/<uuid>/chunk`)**:
   - Client sends up to 4 parallel chunk uploads (`MAX_CONCURRENT = 4`).
   - Header: `X-Chunk-Offset: <integer_byte_offset>`.
   - Body: Raw encrypted chunk (`5 MB plaintext + 16-byte AES-GCM tag = 5,242,896 bytes`).
   - Server validates ownership and seeks directly to `offset` on disk using OS `seek()`.
3. **Finalize (`POST /app/api/file/<uuid>/finalize`)**:
   - Validates file size on disk via `os.path.getsize()`.
   - Updates `file_size` and `last_modified` in the database.
   - Clears user storage telemetry cache.

### 7.3 Dual Download Engines
- **Engine A (RAM & Cache Engine for $\le$ 100 MB):** Fetches the binary stream, verifies tags per block, and caches in IndexedDB `ZeroNodeVaultCache`.
- **Engine B (OPFS Parallel Engine for $>$ 100 MB):** Computes `numChunks = Math.ceil(fileSize / CHUNK_WITH_TAG)`, dispatches 4 concurrent workers with HTTP `Range: bytes=${start}-${end}` headers, decrypts chunks in WebCrypto, writes to temporary storage in the browser's **Origin Private File System (OPFS)** with a write mutex lock, and streams the decrypted file to disk.

---

## 8. Database Schemas

### 8.1 Global Master Database (`data/server_data.db`)
Governed by `app/modules/db_handler.py`:

```sql
CREATE TABLE users (
    user_id         TEXT PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    first_name      TEXT NOT NULL DEFAULT '',
    last_name       TEXT NOT NULL DEFAULT '',
    gender          TEXT DEFAULT '',
    date_of_birth   TEXT DEFAULT '',
    phone_number    TEXT DEFAULT '',
    profile_photo   TEXT DEFAULT '',
    access_token    TEXT DEFAULT '',
    scope           TEXT DEFAULT 'basic',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE whitelist (
    email           TEXT PRIMARY KEY,
    added_at        INTEGER NOT NULL
);

CREATE TABLE admins (
    email           TEXT PRIMARY KEY,
    added_at        INTEGER NOT NULL
);

CREATE TABLE sessions (
    session_token   TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
```

### 8.2 User Vault Database (`data/<user_id>/<user_id>.db`)
Governed by `app/modules/user_data.py`:

```sql
CREATE TABLE files (
    uuid            TEXT PRIMARY KEY,
    file_name       TEXT NOT NULL,
    last_modified   TIMESTAMP NOT NULL,
    owner           TEXT NOT NULL,
    aes_key         TEXT NOT NULL,
    folder_id       TEXT DEFAULT NULL REFERENCES folders(id) ON DELETE CASCADE,
    file_size       INTEGER DEFAULT 0
);

CREATE TABLE folders (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    parent_id       TEXT DEFAULT NULL REFERENCES folders(id) ON DELETE CASCADE,
    owner           TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    last_modified   TIMESTAMP NOT NULL
);

CREATE TABLE config (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key             TEXT UNIQUE NOT NULL,
    value           TEXT NOT NULL
);

CREATE TABLE trash (
    id                  TEXT PRIMARY KEY,
    original_type       TEXT NOT NULL,
    original_id         TEXT NOT NULL,
    original_name       TEXT NOT NULL,
    original_parent_id  TEXT,
    metadata            TEXT,
    deleted_at          TIMESTAMP NOT NULL,
    expires_at          TIMESTAMP NOT NULL,
    owner               TEXT NOT NULL
);
```

---

## 9. Comprehensive REST API Reference

All `/app/*` endpoints require an active session cookie (`znode_session`).

### 9.1 Authentication & Public Endpoints
| Route | Method | Access | Description |
|-------|:------:|:------:|-------------|
| `/` | `GET` | Public | Landing page |
| `/login` | `GET` | Public | SSO login initiation view |
| `/auth/login` | `GET` | Public | Generates CSRF cookie and redirects to SSO provider |
| `/auth/callback` | `GET` | Public | Validates state, exchanges code for JWT, creates session |
| `/auth/logout` | `GET` | Public | Destroys session row and redirects to exit screen |
| `/auth/exit` | `GET` | Public | Renders security cache purge interface |

### 9.2 Vault Key Management API
| Route | Method | Input | Output | Description |
|-------|:------:|-------|--------|-------------|
| `/app/api/key/status` | `GET` | — | `{ "has_key": bool }` | Check if user vault has been initialized |
| `/app/api/key/save` | `POST` | JSON: `public_key`, `encrypted_private_key`, `salt`, `recovery_encrypted_private_key`, `recovery_salt` | Status `201` | Phase 1: Store blind key bundles |
| `/app/api/key/load` | `GET` | — | Wrapped private key, public key, salt | Phase 2: Retrieve bundles for password unlock |
| `/app/api/key/recovery` | `GET` | — | Recovery wrapped key, recovery salt, public key | Phase 3: Retrieve backup bundle for phrase recovery |
| `/app/api/key/reset` | `POST` | JSON: `encrypted_private_key`, `salt`, `recovery_encrypted_private_key`, `recovery_salt` | Status `200` | Phase 3: Overwrite password wrap & rotate seed |

### 9.3 File & Chunked Upload REST API
| Route | Method | Input | Output | Description |
|-------|:------:|-------|--------|-------------|
| `/app/api/file/init` | `POST` | JSON: `file_name`, `aes_key`, `folder_id` | `{ "uuid": "..." }` (201) | Phase 1: Reserve UUID and touch 0-byte `.bin` |
| `/app/api/file/<uuid>/chunk` | `POST` | Header: `X-Chunk-Offset: <int>`, Body: raw bytes | `{ "status": "ok", "offset": <int>, "size": <int> }` | Phase 2: Write chunk at byte offset |
| `/app/api/file/<uuid>/finalize` | `POST` | — | `{ "uuid": "...", "size": <int>, "last_modified": "..." }` | Phase 3: Validate and commit file size |
| `/app/api/file/<uuid>` | `GET` | Header: `Range: bytes=start-end` (optional) | Binary stream (`application/octet-stream`) | Download encrypted binary blob |
| `/app/api/file/<uuid>/meta` | `GET` | — | `{ "uuid": "...", "file_name": "...", "aes_key": "...", "file_size": <int> }` | Retrieve metadata without binary payload |
| `/app/api/file/<uuid>/meta` | `PATCH` | JSON: `file_name` and/or `aes_key` | `{ "status": "updated" }` | Rename file or rotate DEK |
| `/app/api/file/<uuid>/content` | `PUT` | Body: raw binary bytes, Optional Header: `X-AES-Key` | `{ "uuid": "...", "size": <int>, "last_modified": "..." }` | In-place file content overwrite (Markdown notes) |
| `/app/api/file/<uuid>` | `DELETE` | — | `{ "status": "deleted", "uuid": "..." }` | Permanently delete `.bin` and database record |
| `/app/api/files` | `GET` | Query: `?limit=100&offset=0` | Paginated file metadata listing | Flat file listing |

### 9.4 Drive Hierarchy & Folder Management API
| Route | Method | Input | Output | Description |
|-------|:------:|-------|--------|-------------|
| `/app/api/drive/folder` | `POST` | JSON: `name`, `parent_id` (optional) | `{ "status": "created", "id": "<folder_uuid>" }` | Create directory |
| `/app/api/drive/list` | `GET` | — | `{ "folders": [...], "files": [...], "path": [] }` | List root directory contents |
| `/app/api/drive/list/<folder_id>` | `GET` | — | Folder contents with breadcrumb tree path | List subfolder contents |
| `/app/api/drive/all_folders` | `GET` | — | `{ "folders": [...] }` | Flat directory list for UI move pickers |
| `/app/api/drive/folder/<folder_id>` | `PATCH` | JSON: `name` and/or `parent_id` | `{ "status": "updated" }` | Rename or relocate folder |
| `/app/api/drive/file/<uuid>/move` | `PATCH` | JSON: `folder_id` (can be null for root) | `{ "status": "moved" }` | Relocate file to folder |
| `/app/api/drive/delete/folder/<id>` | `POST` | — | `{ "status": "deleted" }` | Recursive cascade deletion of folder & contents |
| `/app/api/drive/delete/file/<uuid>` | `POST` | — | `{ "status": "deleted" }` | Delete file through drive interface |
| `/app/api/drive/search` | `GET` | Query: `?q=<query>&limit=50` | `{ "folders": [...], "files": [...] }` | Name search across files and folders |
| `/app/api/user/self_wipe` | `POST` | JSON: `{ "confirmation": "I want to wipe my data" }` | `{ "status": "IDENTITY_PURGED", "redirect": "..." }` | Self-erasure protocol |

### 9.5 Administrative API Cluster (`admin_only = True`)
| Route | Method | Input | Output | Description |
|-------|:------:|-------|--------|-------------|
| `/app/admin/api/stats` | `GET` | Query: `?search=<term>` | Storage report, host disk health, whitelist, admins | Telemetry report |
| `/app/admin/api/promote` | `POST` | JSON: `{ "email": "..." }` | `{ "status": "ok" }` | Elevate whitelisted user to Admin |
| `/app/admin/api/demote` | `POST` | JSON: `{ "email": "..." }` | `{ "status": "ok" }` | Revoke Admin status (self-demotion blocked) |
| `/app/admin/api/whitelist/add` | `POST` | JSON: `{ "email": "..." }` | `{ "status": "ok" }` | Add email to access control ledger |
| `/app/admin/api/whitelist/remove` | `POST` | JSON: `{ "email": "..." }` | `{ "status": "ok" }` | Evict email from access control ledger |
| `/app/admin/api/user/wipe` | `POST` | JSON: `{ "user_id": "..." }` | `{ "status": "ERASURE_COMMITTED" }` | Admin purge of target user vault & records |
| `/app/admin/api/server/wipe` | `POST` | JSON: `{ "confirmation": "ERASE ALL SERVER DATA" }` | `{ "status": "SYSTEM_LIQUIDATED" }` | Nuclear liquidation of entire node |

---

## 10. System Liquidation Protocols

ZeroNode includes multi-tier physical data erasure engines engineered to break file locks on Windows and Linux systems:

1. **`wipe_self(user_id)`**:
   - Removes user session tokens, admin entries, whitelist records, and user profile from `server_data.db`.
   - Traverses `data/<user_id>/`, clears readonly attributes (`os.chmod(path, stat.S_IWRITE)`), and physically unlinks all `.bin` blobs and `<user_id>.db`.
2. **`wipe_user(user_id, requester_email)`**:
   - Administrative gate prevents admins from wiping themselves via this protocol.
   - Authoritatively purges the target user's physical directory and database rows.
3. **`nuclear_wipe_server()`**:
   - Verifies the forensic confirmation phrase `"ERASE ALL SERVER DATA"`.
   - Purges `.env` credentials.
   - Purges `data/` root using a 3-iteration retry loop with Windows readonly attribute breakers.
   - Force unlinks `server_data.db`.
   - Spawns a background thread that executes `os._exit(0)` after 1.5 seconds, terminating the server process.

---

## 11. Production Deployment & Security Guidelines

### 11.1 Container Deployment (Docker & Compose)
ZeroNode is packaged as an Alpine/Debian-slim container running **Gunicorn** in production:
```yaml
version: '3.8'

services:
  zeronode:
    build: .
    container_name: zeronode_app
    ports:
      - "8862:8862"
    volumes:
      - /srv/data/zeronode:/app/data
    environment:
      - FLASK_ENV=production
      - DATA_DIR=/app/data
      - ADMIN_EMAIL=root@dkydivyansh.com
    restart: unless-stopped
```

### 11.2 Production Hardening Checklist
- [x] **Air-Gapped Assets**: All CSS, fonts (Inter, Space Grotesk, Noto Serif), vendor scripts (`marked.min.js`, `turndown.js`), and Tailwind runtime are local. Zero external CDN dependencies.
- [ ] **Enforce HTTPS**: Set `secure=True` on session cookies in `app/routes/auth.py` and front the container with Nginx or Caddy with TLS 1.3.
- [ ] **Rate Limiting**: Apply reverse-proxy rate limiting (or `flask-limiter`) to `/auth/callback`, `/app/api/file/init`, and `/app/api/key/*`.
- [x] **Strict CORS & Isolation**: Origin allowlist enforced; COOP and CORP headers set to `same-origin` on all responses.

---

## 12. Automated Remote Backup & Disaster Recovery Architecture

ZeroNode includes an enterprise-grade, automated disaster recovery subsystem featuring offsite zero-knowledge archive replication to a dedicated PHP/SQLite backup node.

### 12.1 Cryptographic & Zero-Knowledge Guarantee
The backup architecture strictly adheres to ZeroNode's zero-knowledge blind server principles:
- **No Plaintext Ingestion:** The backup engine never attempts to decrypt or inspect file contents.
- **Pre-Encrypted Binary Blobs:** Backups package pre-existing AES-GCM ciphertext chunks (`<uuid>.bin`) and the user's localized database (`<user_id>.db`).
- **Safe SQLite Snapshots:** Active SQLite databases in WAL mode are captured using SQLite Online Backup API (`src.backup(dst)`), preventing corrupted or torn pages.

### 12.2 Target Granularity & Default Policies
1. **System Server Backup:**
   - Packages `server_data.db` (users, sessions, whitelists, administrative ranks) and manifest metadata.
   - **Default:** Enabled, **Daily** schedule. Configurable on the Admin console (`/app/admin#backup-section`).
2. **Individual User Vault Backups:**
   - Packages each user's isolated vault (`<user_id>.db`, all encrypted chunks in `blobs/`, and `manifest.json`).
   - Formatted as `<user_id>_<timestamp>.zip.bin`.
   - **Administrators:** Enabled by default with **Daily** interval.
   - **Standard Users:** Disabled by default; selectively enabled by email with configurable interval (`daily` or `weekly`) on the Admin page.

### 12.3 3-Phase Chunked Upload with Integrity Checks
Large vault archives are transferred using resilient chunking (2 MB blocks):
1. **Phase 1: Initiation (`POST /api/init.php`)**
   - Transmits `target_type`, `target_id`, `filename`, `total_size`, `chunk_size`, `total_chunks`, and overall expected SHA-256 `file_hash`.
   - The backup node registers an `upload_sessions` row in SQLite and returns a `session_id`.
2. **Phase 2: Chunk Transmission (`POST /api/chunk.php`)**
   - Each chunk is transmitted with a per-chunk `X-Chunk-Hash` header (and query parameter fallback).
   - The backup node verifies the SHA-256 checksum of the incoming chunk against `X-Chunk-Hash` before saving it to `chunks/<session_id>/chunk_<idx>.part`.
   - Updates real-time progress (`10%` to `90%`) in `backup_tasks`.
3. **Phase 3: Finalization & Assembly (`POST /api/finalize.php`)**
   - Stitches all chunks in sequential order into `storage/<target_id>/<filename>`.
   - Computes overall file SHA-256 and asserts equivalence with `expected_hash`.
   - Cleans temporary chunk files and marks session complete.
   - **Automated Retention Auto-Pruning:** Evaluates count of archives for the target. If count exceeds retention limit (default: past 4 archives), older archives are automatically deleted from disk and SQLite.

### 12.4 Dedicated PHP Remote Backup Server (`backup-server/`)
- Pure PHP 8.x with PDO SQLite, zero external framework dependencies.
- Runs standalone: `php -S 0.0.0.0:8080 -t backup-server backup-server/index.php`.
- Bearer token / `X-API-Key` authentication defined in `backup-server/config.php`.
- Schema auto-initialization with WAL mode (`backups` and `upload_sessions` tables).

### 12.5 Real-Time Telemetry & UI Integration
- **Home Dashboard (`/app/home`):** Features a dedicated **Remote Backup Card** with live polling, visual progress bar, active upload target indicator, percentage display, last backup timestamp, size, SHA-256 checksum display, and a direct navigation link to `/app/backup`.
- **Navigation Bar & Dedicated Backup Module (`/app/backup`):** Dedicated authenticated vault disaster recovery interface providing one-click manual backup trigger, latest vault restore, local archive upload restore, and archive ledger.
- **Admin Console (`/app/admin`):** Comprehensive Disaster Recovery control center with remote node health tester, server backup scheduler, user policy table with toggle switches and interval selectors, and a remote archive vault table with download, restore, and on-demand purge capabilities.

---

### 12.6 Disaster Recovery Restore Architecture & Overwrite Safeguards

ZeroNode provides full bidirectional disaster recovery, allowing users and administrators to reconstruct vaults or entire system state from remote or local archives:

#### 1. Restore Modalities
- **User Vault Remote Restore (`POST /app/backup/api/user/restore`):** Authenticated user streams their latest snapshot (or a specific `backup_id`) from the PHP backup server into local storage.
- **User Vault File Upload Restore (`POST /app/backup/api/user/restore_upload`):** Authenticated user uploads an offline `.zip.bin` file to reconstruct their vault without remote server dependencies.
- **Server Master Remote Restore (`POST /app/admin/api/backup/remote/restore`):** Administrators restore master `server_data.db` or specific user vaults directly from the remote repository.

#### 2. Critical Overwrite Warning & Confirmation Safeguards
Restoring an archive is a destructive operation that replaces active records. The system enforces strict multi-layered safeguards:
- **High-Visibility Amber Callouts:** Both `/app/backup` and `/app/admin` display prominent warning notices:
  > **CRITICAL OVERWRITE NOTICE:** Executing a restore will permanently overwrite and replace active data for the target (Server master database or User vault). Files or records created after the archive timestamp will be replaced.
- **Explicit Confirmation Prompt:** Every restore action mandates typing the exact phrase `"RESTORE DATA"`. Any typo or mismatch aborts the operation immediately at both the client dialog and backend API gate (`HTTP 400`).
- **Cryptographic User Segregation:** `restore_archive()` parses embedded `manifest.json` and verifies that standard users can only restore archives matching their own `user_id`, blocking cross-tenant restore attempts (`PermissionError`).

#### 3. Windows-Safe SQLite Online Restoration
Because ZeroNode maintains active SQLite connections in WAL mode, replacing database files via standard `shutil.copyfile` or `os.replace` on Windows causes `PermissionError: [WinError 32]`. The restore engine resolves this by:
1. Extracting archive snapshots to a temporary directory.
2. Opening an in-process SQLite connection to the snapshot and executing `src_conn.backup(dst_conn)` directly into the target database.
3. Flushing WAL pages into the target database safely across active handles before unlinking temporary snapshot files.
4. Extracting ciphertext chunks (`blobs/*.bin`) directly into `data/<user_id>/` with automatic byte replacement.

---

### 12.7 Forensic Deletion, Stale Task Healing & Bulk Archive Operations

1. **Stale Task Auto-Healing (Stuck Progress Prevention):**
   - In distributed or multi-threaded backup workflows, server restarts or network interruptions could leave a `backup_tasks` row in `running` state indefinitely (e.g. at 2%).
   - `cleanup_stale_backup_tasks(timeout_seconds=180)` is automatically executed whenever active tasks or status telemetries are queried. Any task remaining in `running` state past the threshold is transitioned to `failed`.
   - On server boot, `init_db()` marks all dangling `running` tasks as failed.
   - When generating server database snapshots in `create_server_archive()`, active tasks in the temporary snapshot SQLite file are purged prior to archive compression, guaranteeing that restoring an archive never restores a stuck task into the live database.

2. **Automated Remote Backup Purge on User Deletion:**
   - When an identity is de-provisioned (via `wipe_self` or administrative `wipe_user`), `_atomic_erasure_internal()` issues a target purge request `backup_manager.delete_remote_backups_for_target(user_id)`.
   - The remote PHP backup server permanently removes the user's `storage/<user_id>/` directory and unlinks all associated records from SQLite.

3. **Remote Backup Server Reset on Full Server Wipe:**
   - Authorizing server reset triggers `backup_manager.delete_all_remote_backups()`.
   - The remote backup server deletes all user and server archives across all storage directories and truncates `backups` and `upload_sessions` tables.

4. **Bulk Selection & Deletion in Remote Storage Repository:**
   - Both `/app/admin` and `/app/backup` feature bulk selection checkboxes with a master "Select All" toggle.
   - Administrators can select multiple archives and delete them simultaneously via `POST /app/admin/api/backup/remote/delete_bulk`.

---

### 12.8 Real-Time WebSocket Progress & Granular Pipeline Execution

ZeroNode utilizes a persistent WebSocket event bus for zero-latency, real-time progress broadcasting during backup and restore workflows:

#### 1. WebSocket Infrastructure (`/ws/backup`)
- **Engine:** Built with `flask-sock` and `simple-websocket`, mounted at `/ws/backup`.
- **Session Authentication:** Handshakes authenticate against the active `zeronode_session` cookie (or query parameter token). Unauthenticated sockets are immediately rejected.
- **Tenant Isolation & Administrative Scoping:** The `BackupEventBroadcaster` enforces strict tenant scoping: administrators receive live progress updates for all system and user operations; standard users exclusively receive events matching their own `user_id`.
- **CSP Compliance:** `connect-src` in `Content-Security-Policy` explicitly permits `ws:` and `wss:` protocols.

#### 2. Strict Granular Backup Pipeline
Backups execute in a deterministic, phased sequence with continuous WebSocket updates:
1. **Compress Phase (0% - 25%):** Snapshots the active SQLite database using the SQLite Backup API and packages it with pre-encrypted ciphertext chunks into a temporary `.zip.bin` archive.
2. **Hash & Init Phase (25% - 30%):** Computes overall file SHA-256 and registers an upload session with the remote backup server.
3. **Upload Phase (30% - 85%):** Streams chunk by chunk (2 MB blocks) with chunk SHA-256 header validation, updating progress percent, chunk count, and transferred bytes.
4. **Verify Phase (85% - 95%):** Remote backup server stitches chunks, validates total SHA-256 against expected hash, and commits archive metadata.
5. **Cleanup Phase (95% - 99%):** The local temporary compressed `.zip.bin` archive is securely unlinked from the local host.
6. **Done Phase (100%):** Marks task as `success` in `backup_tasks` and broadcasts completion event with archive details.

#### 3. Strict Granular Restore Pipeline
Restores execute asynchronously in a background worker daemon (`trigger_restore_async`), emitting live events:
1. **Download Phase (0% - 40%):** Streams the remote archive from the backup repository, broadcasting live downloaded bytes, total file size, and download percentage.
2. **Verify Phase (40% - 50%):** Validates archive structure and `manifest.json`, asserting target user/server compatibility.
3. **Restore DB Phase (50% - 70%):** Restores SQLite database snapshot into the target database safely using in-process Online Backup API without Windows WAL file lock contention.
4. **Restore Blobs Phase (70% - 90%):** Reconstructs all encrypted binary chunk blobs into the user's drive directory with per-file progress updates.
5. **Cleanup Phase (90% - 98%):** Removes temporary staging files and downloaded archives from the local host.
6. **Done Phase (100%):** Marks restore task complete and broadcasts completion event.

#### 4. Frontend Live Operation Modal (`app/static/js/backup_live.js`)
- **Global Operation Hub:** Injected across all dashboard views (`shell.html`).
- **Visual Stepper:** Features a 5-stage pipeline stepper with active pulse animations and completed checkmarks (`✓`).
- **Precision Progress Bar:** Displays smooth animated percentage gradient with live status message and transfer speeds.
- **Live Event Log Terminal:** Timestamped event log stream for real-time visibility into internal phases.
- **Non-Blocking Minimization:** Users can minimize the dialog to work in other tabs while the background task completes unimpeded.
