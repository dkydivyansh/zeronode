<?php
/**
 * ZeroNode Backup Server — Stream / Download Backup Archive
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

$backupId = trim($_GET['backup_id'] ?? '');

if (empty($backupId)) {
    json_error("Missing backup_id parameter.", 400);
}

$db = get_db();
$stmt = $db->prepare("SELECT * FROM backups WHERE id = :id");
$stmt->execute([':id' => $backupId]);
$backup = $stmt->fetch();

if (!$backup || empty($backup['file_path']) || !file_exists($backup['file_path'])) {
    json_error("Backup archive not found on server.", 404);
}

$filePath = $backup['file_path'];
$filename = $backup['filename'];
$fileSize = filesize($filePath);

header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($filename) . '"');
header('Content-Length: ' . $fileSize);
header('X-Backup-Hash: ' . $backup['file_hash']);
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

$handle = fopen($filePath, 'rb');
if ($handle) {
    while (!feof($handle)) {
        echo fread($handle, 1048576); // 1 MB buffer
        flush();
    }
    fclose($handle);
}
exit;

