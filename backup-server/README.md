# ZeroNode Remote Backup Server (PHP + SQLite)

A lightweight, dedicated, API-driven backup server for ZeroNode. It securely receives, verifies, and stores encrypted user archives and master server backups using **chunked uploads** and **per-chunk + overall SHA-256 hash validation**.

---

## Features

- 🔐 **Token-Based Authentication**: Gated via Bearer API Key (`Authorization: Bearer <KEY>` or `X-API-Key: <KEY>`).
- ⚡ **Reliable Chunked Uploads**: Accepts arbitrary file sizes split into chunks with byte-level verification.
- 🛡️ **Two-Tier Hash Verification**:
  1. Each chunk is verified immediately against its SHA-256 checksum.
  2. Assembled file is cryptographically verified against the expected whole-file SHA-256 checksum before persistence.
- 📁 **Target Partitioning**: User backups are saved in `storage/<user_id>/`, server backups in `storage/server/`.
- 🔄 **Automated Pruning**: Automatically rotates older backups beyond the configured retention limit (default: stores past 3–4 backups).
- 🗄️ **SQLite Registry**: Stores backup metadata, sizes, hashes, and timestamps in `storage/backup_registry.sqlite`.

---

## Quick Start

### 1. Run via PHP Built-in Server
You can launch the backup server with zero installation:

```bash
cd backup-server
php -S 0.0.0.0:8080 index.php
```

The backup server is now listening at `http://127.0.0.1:8080`.

### 2. Configuration
Edit `config.php` (or export environment variables):

```php
// API key for ZeroNode to connect
$API_KEY = getenv('BACKUP_API_KEY') ?: 'zeronode_secret_backup_key_2026';

// How many past backups to keep per user/server (default: 4)
$MAX_BACKUPS_PER_TARGET = (int)(getenv('BACKUP_RETENTION_COUNT') ?: 4);
```

### 3. API Reference

All requests require `Authorization: Bearer <API_KEY>` or `X-API-Key: <API_KEY>`.

- `POST /api/init.php` — Initialize upload session.
- `POST /api/chunk.php` — Upload chunk (`X-Session-ID`, `X-Chunk-Index`, `X-Chunk-Hash`).
- `POST /api/finalize.php` — Assemble chunks, verify file SHA-256, auto-prune old archives.
- `GET /api/list.php` — List available backups (`?target_id=...`).
- `GET /api/download.php?backup_id=...` — Download a backup archive.
- `POST /api/delete.php` — Delete a specific backup.
- `GET /api/health.php` — Ping health & storage metrics.

