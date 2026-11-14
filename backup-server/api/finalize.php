<?php
/**
 * ZeroNode Backup Server — Finalize Chunk Assembly, Verify Hash & Auto-Prune
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error("Method Not Allowed. POST required.", 405);
}

$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true);

$sessionId = trim($data['session_id'] ?? ($_POST['session_id'] ?? ''));

if (empty($sessionId)) {
    json_error("Missing session_id.", 400);
}

$db = get_db();
$stmt = $db->prepare("SELECT * FROM upload_sessions WHERE session_id = :session_id");
$stmt->execute([':session_id' => $sessionId]);
$session = $stmt->fetch();

if (!$session) {
    json_error("Upload session not found.", 404);
}
if ($session['status'] !== 'uploading') {
    json_error("Upload session is already finalized or expired.", 409);
}

global $STORAGE_DIR, $CHUNK_DIR, $MAX_BACKUPS_PER_TARGET;

$totalChunks = (int)$session['total_chunks'];
$targetId    = $session['target_id'];
$targetType  = $session['target_type'];
$filename    = $session['filename'];

// 1. Verify all chunk parts exist
$chunkFiles = [];
for ($i = 0; $i < $totalChunks; $i++) {
    $partPath = sprintf("%s/%s_%05d.part", $CHUNK_DIR, $sessionId, $i);
    if (!file_exists($partPath)) {
        json_error("Missing chunk index {$i} of {$totalChunks}. Cannot finalize.", 400);
    }
    $chunkFiles[] = $partPath;
}

// 2. Prepare target directory: storage/<target_id>/
$targetDir = $STORAGE_DIR . '/' . preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $targetId);
if (!is_dir($targetDir)) {
    @mkdir($targetDir, 0755, true);
}

// Ensure unique target filename if needed
$destFilePath = $targetDir . '/' . basename($filename);

// 3. Assemble chunks
$outHandle = fopen($destFilePath, 'wb');
if (!$outHandle) {
    json_error("Failed to open destination file for writing.", 500);
}

$hashContext = hash_init('sha256');

foreach ($chunkFiles as $partPath) {
    $inHandle = fopen($partPath, 'rb');
    if (!$inHandle) {
        fclose($outHandle);
        @unlink($destFilePath);
        json_error("Failed reading chunk part: {$partPath}", 500);
    }

    while (!feof($inHandle)) {
        $buffer = fread($inHandle, 1048576); // 1 MB buffer
        if ($buffer !== false && strlen($buffer) > 0) {
            fwrite($outHandle, $buffer);
            hash_update($hashContext, $buffer);
        }
    }
    fclose($inHandle);
}

fclose($outHandle);

// 4. Final File Hash Verification
$finalHash = hash_final($hashContext);
$expectedHash = strtolower($session['expected_hash']);

if (!hash_equals($expectedHash, $finalHash)) {
    @unlink($destFilePath);
    // Cleanup chunk parts
    foreach ($chunkFiles as $partPath) { @unlink($partPath); }
    $db->prepare("UPDATE upload_sessions SET status = 'failed' WHERE session_id = :s")->execute([':s' => $sessionId]);
    json_error("Overall file integrity verification failed! Expected: {$expectedHash}, computed: {$finalHash}", 422);
}

$finalSize = filesize($destFilePath);

// 5. Cleanup chunk parts
foreach ($chunkFiles as $partPath) {
    @unlink($partPath);
}

// 6. Record Backup in Database
$backupId = bin2hex(random_bytes(16));
$now = time();

$ins = $db->prepare("
    INSERT INTO backups (
        id, target_type, target_id, filename, file_path,
        file_size, file_hash, metadata_json, created_at
    ) VALUES (
        :id, :target_type, :target_id, :filename, :file_path,
        :file_size, :file_hash, :metadata_json, :created_at
    )
");

$ins->execute([
    ':id'            => $backupId,
    ':target_type'   => $targetType,
    ':target_id'     => $targetId,
    ':filename'      => basename($destFilePath),
    ':file_path'     => $destFilePath,
    ':file_size'     => $finalSize,
    ':file_hash'     => $finalHash,
    ':metadata_json' => $session['metadata_json'],
    ':created_at'    => $now,
]);

// Mark session as completed
$db->prepare("UPDATE upload_sessions SET status = 'completed' WHERE session_id = :s")->execute([':s' => $sessionId]);

// 7. Retention Enforcement: Auto-delete older backups beyond $MAX_BACKUPS_PER_TARGET (e.g. past 3-4 backups)
$retQuery = $db->prepare("
    SELECT id, file_path, filename 
    FROM backups 
    WHERE target_id = :target_id 
    ORDER BY created_at DESC
");
$retQuery->execute([':target_id' => $targetId]);
$allBackups = $retQuery->fetchAll();

$purgedCount = 0;
if (count($allBackups) > $MAX_BACKUPS_PER_TARGET) {
    $toPurge = array_slice($allBackups, $MAX_BACKUPS_PER_TARGET);
    $delStmt = $db->prepare("DELETE FROM backups WHERE id = :id");

    foreach ($toPurge as $oldBackup) {
        if (!empty($oldBackup['file_path']) && file_exists($oldBackup['file_path'])) {
            @unlink($oldBackup['file_path']);
        }
        $delStmt->execute([':id' => $oldBackup['id']]);
        $purgedCount++;
    }
}

json_response([
    'success'         => true,
    'backup_id'       => $backupId,
    'target_type'     => $targetType,
    'target_id'       => $targetId,
    'filename'        => basename($destFilePath),
    'file_size'       => $finalSize,
    'file_hash'       => $finalHash,
    'created_at'      => $now,
    'retained_count'  => count($allBackups) - $purgedCount,
    'purged_count'    => $purgedCount,
], 200);

