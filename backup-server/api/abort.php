<?php
/**
 * ZeroNode Backup Server — Abort Upload Session & Cleanup Chunks
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error("Method Not Allowed. POST required.", 405);
}

$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true) ?: [];

$sessionId = trim($data['session_id'] ?? ($_POST['session_id'] ?? ($_GET['session_id'] ?? '')));
$reason    = trim($data['reason'] ?? ($_POST['reason'] ?? 'Aborted by client.'));

if (empty($sessionId)) {
    json_error("Missing required parameter: session_id", 400);
}

$db = get_db();
$stmt = $db->prepare("SELECT * FROM upload_sessions WHERE session_id = :session_id");
$stmt->execute([':session_id' => $sessionId]);
$session = $stmt->fetch();

if (!$session) {
    json_error("Upload session not found.", 404);
}

global $CHUNK_DIR;
$deletedCount = 0;

// Remove all chunk parts associated with this session
$parts = glob(sprintf("%s/%s_*.part", $CHUNK_DIR, $sessionId));
if ($parts) {
    foreach ($parts as $p) {
        if (file_exists($p)) {
            @unlink($p);
            $deletedCount++;
        }
    }
}

// Update session status to aborted/failed
$upd = $db->prepare("UPDATE upload_sessions SET status = 'failed' WHERE session_id = :session_id");
$upd->execute([':session_id' => $sessionId]);

json_response([
    'success'        => true,
    'session_id'     => $sessionId,
    'status'         => 'failed',
    'deleted_chunks' => $deletedCount,
    'reason'         => $reason,
]);

