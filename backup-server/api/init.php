<?php
/**
 * ZeroNode Backup Server — Initialize Chunked Upload Session
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error("Method Not Allowed. POST required.", 405);
}

$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true);

if (!is_array($data)) {
    json_error("Invalid JSON payload.", 400);
}

$targetType   = trim($data['target_type'] ?? '');
$targetId     = trim($data['target_id'] ?? '');
$filename     = trim($data['filename'] ?? '');
$totalSize    = (int)($data['total_size'] ?? 0);
$chunkSize    = (int)($data['chunk_size'] ?? 0);
$totalChunks  = (int)($data['total_chunks'] ?? 0);
$fileHash     = strtolower(trim($data['file_hash'] ?? ''));
$metadata     = $data['metadata'] ?? [];

if (!in_array($targetType, ['user', 'server'], true)) {
    json_error("Invalid target_type. Must be 'user' or 'server'.", 400);
}
if (empty($targetId) || empty($filename) || empty($fileHash)) {
    json_error("Missing required fields: target_id, filename, file_hash.", 400);
}
if ($totalSize <= 0 || $chunkSize <= 0 || $totalChunks <= 0) {
    json_error("total_size, chunk_size, and total_chunks must be positive integers.", 400);
}
if (strlen($fileHash) !== 64 || !ctype_xdigit($fileHash)) {
    json_error("file_hash must be a valid 64-character lowercase SHA-256 hex string.", 400);
}

// Generate unique session ID
$sessionId = bin2hex(random_bytes(16));
$now = time();

$db = get_db();
$stmt = $db->prepare("
    INSERT INTO upload_sessions (
        session_id, target_type, target_id, filename, total_size,
        chunk_size, total_chunks, expected_hash, metadata_json,
        received_chunks, created_at, status
    ) VALUES (
        :session_id, :target_type, :target_id, :filename, :total_size,
        :chunk_size, :total_chunks, :expected_hash, :metadata_json,
        0, :created_at, 'uploading'
    )
");

$stmt->execute([
    ':session_id'    => $sessionId,
    ':target_type'   => $targetType,
    ':target_id'     => $targetId,
    ':filename'      => $filename,
    ':total_size'    => $totalSize,
    ':chunk_size'    => $chunkSize,
    ':total_chunks'  => $totalChunks,
    ':expected_hash' => $fileHash,
    ':metadata_json' => json_encode($metadata, JSON_UNESCAPED_SLASHES),
    ':created_at'    => $now,
]);

json_response([
    'success'      => true,
    'session_id'   => $sessionId,
    'target_type'  => $targetType,
    'target_id'    => $targetId,
    'filename'     => $filename,
    'total_chunks' => $totalChunks,
    'chunk_size'   => $chunkSize,
    'expected_hash'=> $fileHash,
    'created_at'   => $now,
], 201);

