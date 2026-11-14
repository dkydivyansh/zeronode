<?php
/**
 * ZeroNode Backup Server Database & Security Helpers
 */

require_once __DIR__ . '/config.php';

function get_db(): PDO {
    global $DB_PATH;
    static $pdo = null;

    if ($pdo === null) {
        $dsn = "sqlite:" . $DB_PATH;
        $pdo = new PDO($dsn, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);

        $pdo->exec("PRAGMA journal_mode = WAL;");
        $pdo->exec("PRAGMA foreign_keys = ON;");

        // Schema initialization
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS backups (
                id TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_hash TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}',
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_backups_target ON backups(target_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS upload_sessions (
                session_id TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                total_size INTEGER NOT NULL,
                chunk_size INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                expected_hash TEXT NOT NULL,
                metadata_json TEXT DEFAULT '{}',
                received_chunks INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                status TEXT DEFAULT 'uploading'
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_status ON upload_sessions(status);
        ");
    }

    return $pdo;
}

function get_header_val(string $name, string $default = ''): string {
    $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    if (!empty($_SERVER[$serverKey])) {
        return (string)$_SERVER[$serverKey];
    }
    $directKey = strtoupper(str_replace('-', '_', $name));
    if (!empty($_SERVER[$directKey])) {
        return (string)$_SERVER[$directKey];
    }
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        foreach ($headers as $k => $v) {
            if (strcasecmp($k, $name) === 0) {
                return (string)$v;
            }
        }
    }
    return $default;
}

function authenticate_request(): bool {
    global $API_KEY;

    $authHeader = get_header_val('Authorization');
    $providedKey = null;

    if (!empty($authHeader) && preg_match('/Bearer\s+(\S+)/i', $authHeader, $matches)) {
        $providedKey = $matches[1];
    } elseif ($apiKeyHeader = get_header_val('X-API-Key')) {
        $providedKey = $apiKeyHeader;
    } elseif (isset($_GET['api_key'])) {
        $providedKey = $_GET['api_key'];
    } elseif (isset($_POST['api_key'])) {
        $providedKey = $_POST['api_key'];
    }

    if (!$providedKey || !hash_equals($API_KEY, $providedKey)) {
        json_error("Unauthorized: Invalid or missing API key.", 401);
        exit;
    }

    return true;
}

function json_response(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function json_error(string $message, int $status = 400): void {
    json_response([
        'success' => false,
        'error'   => $message,
        'status'  => $status,
    ], $status);
}

// Polyfill getallheaders if not running under Apache
if (!function_exists('getallheaders')) {
    function getallheaders(): array {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}
