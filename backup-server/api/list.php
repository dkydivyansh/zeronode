<?php
/**
 * ZeroNode Backup Server — List Backups
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

$targetId   = trim($_GET['target_id'] ?? '');
$targetType = trim($_GET['target_type'] ?? '');
$limit      = min(max((int)($_GET['limit'] ?? 100), 1), 500);

$db = get_db();
$params = [];
$sql = "SELECT id, target_type, target_id, filename, file_size, file_hash, metadata_json, created_at FROM backups";
$where = [];

if (!empty($targetId)) {
    $where[] = "target_id = :target_id";
    $params[':target_id'] = $targetId;
}
if (!empty($targetType)) {
    $where[] = "target_type = :target_type";
    $params[':target_type'] = $targetType;
}

if (!empty($where)) {
    $sql .= " WHERE " . implode(' AND ', $where);
}
$sql .= " ORDER BY created_at DESC LIMIT " . $limit;

$stmt = $db->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$backups = array_map(function($row) {
    return [
        'id'            => $row['id'],
        'target_type'   => $row['target_type'],
        'target_id'     => $row['target_id'],
        'filename'      => $row['filename'],
        'file_size'     => (int)$row['file_size'],
        'total_size'    => (int)$row['file_size'],
        'file_hash'     => $row['file_hash'],
        'metadata'      => json_decode($row['metadata_json'], true) ?: [],
        'created_at'    => (int)$row['created_at'],
        'created_at_iso'=> gmdate('Y-m-d\TH:i:s\Z', (int)$row['created_at']),
    ];
}, $rows);

json_response([
    'success' => true,
    'count'   => count($backups),
    'backups' => $backups,
]);
