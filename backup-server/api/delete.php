<?php
/**
 * ZeroNode Backup Server — Delete Backup(s) / Clear Target or All
 */

require_once __DIR__ . '/../db.php';
authenticate_request();

global $STORAGE_DIR;

$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true) ?: [];

$db = get_db();

// 1. Delete All Backups (System Reset)
if (!empty($data['all']) || !empty($_POST['all']) || !empty($_GET['all'])) {
    $rows = $db->query("SELECT id, file_path FROM backups")->fetchAll();
    foreach ($rows as $r) {
        if (!empty($r['file_path']) && file_exists($r['file_path'])) {
            @unlink($r['file_path']);
        }
    }
    $db->exec("DELETE FROM backups");
    $db->exec("DELETE FROM upload_sessions");
    
    // Delete subdirectories in storage
    if (is_dir($STORAGE_DIR)) {
        $items = scandir($STORAGE_DIR);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item === '.gitkeep') continue;
            $subPath = $STORAGE_DIR . '/' . $item;
            if (is_dir($subPath)) {
                $subFiles = scandir($subPath);
                foreach ($subFiles as $sf) {
                    if ($sf === '.' || $sf === '..') continue;
                    @unlink($subPath . '/' . $sf);
                }
                @rmdir($subPath);
            } elseif (is_file($subPath)) {
                @unlink($subPath);
            }
        }
    }

    json_response([
        'success'       => true,
        'deleted_count' => count($rows),
        'purged_count'  => count($rows),
        'message'       => 'All remote backup archives and storage successfully deleted.',
    ]);
}

// 2. Delete by Target ID (e.g., on User Account Deletion)
$targetId = trim($data['target_id'] ?? ($_POST['target_id'] ?? ($_GET['target_id'] ?? '')));
if (!empty($targetId)) {
    $stmt = $db->prepare("SELECT id, file_path FROM backups WHERE target_id = :target_id");
    $stmt->execute([':target_id' => $targetId]);
    $rows = $stmt->fetchAll();
    foreach ($rows as $r) {
        if (!empty($r['file_path']) && file_exists($r['file_path'])) {
            @unlink($r['file_path']);
        }
    }
    $del = $db->prepare("DELETE FROM backups WHERE target_id = :target_id");
    $del->execute([':target_id' => $targetId]);
    
    // Also remove target directory in storage
    $safeTargetDir = $STORAGE_DIR . '/' . preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $targetId);
    if (is_dir($safeTargetDir)) {
        $subFiles = scandir($safeTargetDir);
        foreach ($subFiles as $sf) {
            if ($sf === '.' || $sf === '..') continue;
            @unlink($safeTargetDir . '/' . $sf);
        }
        @rmdir($safeTargetDir);
    }

    json_response([
        'success'      => true,
        'target_id'    => $targetId,
        'purged_count' => count($rows),
        'message'      => "All backup archives for target [{$targetId}] deleted.",
    ]);
}

// 3. Bulk Delete by Array of Backup IDs (Bulk Selection in Remote Storage)
$backupIds = $data['backup_ids'] ?? ($_POST['backup_ids'] ?? null);
if (is_array($backupIds) && !empty($backupIds)) {
    $backupIds = array_values(array_filter(array_map('trim', $backupIds)));
    if (empty($backupIds)) {
        json_error("No valid backup IDs provided.", 400);
    }
    
    $placeholders = implode(',', array_fill(0, count($backupIds), '?'));
    $stmt = $db->prepare("SELECT id, file_path FROM backups WHERE id IN ($placeholders)");
    $stmt->execute($backupIds);
    $rows = $stmt->fetchAll();
    
    foreach ($rows as $r) {
        if (!empty($r['file_path']) && file_exists($r['file_path'])) {
            @unlink($r['file_path']);
        }
    }
    
    $delStmt = $db->prepare("DELETE FROM backups WHERE id IN ($placeholders)");
    $delStmt->execute($backupIds);
    $deletedCount = $delStmt->rowCount();

    json_response([
        'success'       => true,
        'deleted_count' => $deletedCount,
        'message'       => "{$deletedCount} backup archive(s) successfully deleted from storage.",
    ]);
}

// 4. Single Archive Delete
$backupId = trim($data['backup_id'] ?? ($_POST['backup_id'] ?? ($_GET['backup_id'] ?? '')));
if (!empty($backupId)) {
    $stmt = $db->prepare("SELECT * FROM backups WHERE id = :id");
    $stmt->execute([':id' => $backupId]);
    $backup = $stmt->fetch();

    if (!$backup) {
        json_error("Backup not found.", 404);
    }

    if (!empty($backup['file_path']) && file_exists($backup['file_path'])) {
        @unlink($backup['file_path']);
    }

    $del = $db->prepare("DELETE FROM backups WHERE id = :id");
    $del->execute([':id' => $backupId]);

    json_response([
        'success'   => true,
        'deleted_id'=> $backupId,
        'message'   => "Backup {$backupId} successfully deleted from storage.",
    ]);
}

json_error("Missing backup_id, backup_ids, target_id, or all parameter.", 400);
