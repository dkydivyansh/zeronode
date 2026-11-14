<?php
/**
 * ZeroNode Backup Server — Health & Storage Diagnostic Check
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

global $STORAGE_DIR, $MAX_BACKUPS_PER_TARGET;

$db = get_db();
$totalBackups = $db->query("SELECT COUNT(*) FROM backups")->fetchColumn();
$totalUsers   = $db->query("SELECT COUNT(DISTINCT target_id) FROM backups WHERE target_type = 'user'")->fetchColumn();
$totalBytes   = $db->query("SELECT SUM(file_size) FROM backups")->fetchColumn() ?: 0;

$freeBytes    = disk_free_space($STORAGE_DIR) ?: 0;
$totalDisk    = disk_total_space($STORAGE_DIR) ?: 0;

json_response([
    'success'         => true,
    'status'          => 'healthy',
    'service'         => 'ZeroNode Remote Backup Server (PHP/SQLite)',
    'server_time'     => time(),
    'server_time_iso' => gmdate('Y-m-d\TH:i:s\Z'),
    'retention_limit' => $MAX_BACKUPS_PER_TARGET,
    'stats'           => [
        'total_backups'     => (int)$totalBackups,
        'backed_up_users'   => (int)$totalUsers,
        'total_bytes_stored'=> (int)$totalBytes,
        'disk_free_bytes'   => (int)$freeBytes,
        'disk_total_bytes'  => (int)$totalDisk,
    ]
]);

