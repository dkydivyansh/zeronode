<?php
/**
 * ZeroNode Backup Server — Upload Chunk with SHA-256 Verification
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error("Method Not Allowed. POST required.", 405);
}

$sessionId  = trim($_POST['session_id'] ?? ($_GET['session_id'] ?? get_header_val('X-Session-ID')));
$chunkIndexRaw = $_POST['chunk_index'] ?? ($_GET['chunk_index'] ?? get_header_val('X-Chunk-Index', '-1'));
$chunkIndex = is_numeric($chunkIndexRaw) ? (int)$chunkIndexRaw : -1;
$chunkHash  = strtolower(trim($_POST['chunk_hash'] ?? ($_GET['chunk_hash'] ?? get_header_val('X-Chunk-Hash'))));

if (empty($sessionId) || $chunkIndex < 0 || empty($chunkHash)) {
    json_error("Missing required parameters: session_id, chunk_index, chunk_hash.", 400);
}

// Retrieve upload session
$db = get_db();
$stmt = $db->prepare("SELECT * FROM upload_sessions WHERE session_id = :session_id");
$stmt->execute([':session_id' => $sessionId]);
$session = $stmt->fetch();

if (!$session) {
    json_error("Upload session not found.", 404);
}
if ($session['status'] !== 'uploading') {
    json_error("Upload session is no longer active (status: {$session['status']}).", 409);
}
if ($chunkIndex >= (int)$session['total_chunks']) {
    json_error("chunk_index {$chunkIndex} out of bounds (total_chunks: {$session['total_chunks']}).", 400);
}

// Read chunk data: either raw request body or multipart upload
$chunkData = null;
if (isset($_FILES['chunk']) && is_uploaded_file($_FILES['chunk']['tmp_name'])) {
    $chunkData = file_get_contents($_FILES['chunk']['tmp_name']);
} else {
    $chunkData = file_get_contents('php://input');
}

if ($chunkData === false || strlen($chunkData) === 0) {
    json_error("Empty or invalid chunk data payload.", 400);
}

// Strict Hash Verification per chunk
$computedHash = hash('sha256', $chunkData);
if (!hash_equals($chunkHash, $computedHash)) {
    json_error("Chunk integrity verification failed! Expected hash: {$chunkHash}, computed: {$computedHash}", 400);
}

// Save chunk to disk
global $CHUNK_DIR;
$chunkFilePath = sprintf("%s/%s_%05d.part", $CHUNK_DIR, $sessionId, $chunkIndex);

if (file_put_contents($chunkFilePath, $chunkData) === false) {
    json_error("Failed to write chunk to storage disk.", 500);
}

// Count how many parts are saved
$existingParts = glob(sprintf("%s/%s_*.part", $CHUNK_DIR, $sessionId));
$receivedCount = count($existingParts);

$upd = $db->prepare("UPDATE upload_sessions SET received_chunks = :rc WHERE session_id = :session_id");
$upd->execute([':rc' => $receivedCount, ':session_id' => $sessionId]);

json_response([
    'success'         => true,
    'session_id'      => $sessionId,
    'chunk_index'     => $chunkIndex,
    'chunk_size'      => strlen($chunkData),
    'chunk_hash'      => $computedHash,
    'received_chunks' => $receivedCount,
    'total_chunks'    => (int)$session['total_chunks'],
]);
