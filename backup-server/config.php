<?php
/**
 * ZeroNode Backup Server Configuration
 */

// ─── AUTHENTICATION & ACCESS ─────────────────────────────────────────────────
// Secret API key required in Authorization header: Bearer <API_KEY> or X-API-Key: <API_KEY>
$API_KEY = getenv('BACKUP_API_KEY') ?: 'zeronode_secret_backup_key_2026';

// ─── STORAGE PATHS ───────────────────────────────────────────────────────────
$BASE_DIR     = __DIR__;
$STORAGE_DIR  = getenv('BACKUP_STORAGE_DIR') ?: ($BASE_DIR . '/storage');
$CHUNK_DIR    = $STORAGE_DIR . '/_chunks';
$DB_PATH      = $STORAGE_DIR . '/backup_registry.sqlite';

// ─── RETENTION POLICY ────────────────────────────────────────────────────────
// How many past backups to retain per target (user or server).
// Whenever a new backup is finalized, backups beyond this count are automatically purged.
$MAX_BACKUPS_PER_TARGET = (int)(getenv('BACKUP_RETENTION_COUNT') ?: 4);

// ─── UPLOAD LIMITS ───────────────────────────────────────────────────────────
$MAX_CHUNK_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB per chunk max
$UPLOAD_TIMEOUT_SECS  = 3600;              // 1 hour session expiration

// Ensure directories exist
if (!is_dir($STORAGE_DIR)) {
    @mkdir($STORAGE_DIR, 0755, true);
}
if (!is_dir($CHUNK_DIR)) {
    @mkdir($CHUNK_DIR, 0755, true);
}

