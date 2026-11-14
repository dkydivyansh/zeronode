<?php
/**
 * ZeroNode Backup Server — Router & Status Landing
 */

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Route API requests
$routes = [
    '/api/init'     => __DIR__ . '/api/init.php',
    '/api/chunk'    => __DIR__ . '/api/chunk.php',
    '/api/finalize' => __DIR__ . '/api/finalize.php',
    '/api/list'     => __DIR__ . '/api/list.php',
    '/api/download' => __DIR__ . '/api/download.php',
    '/api/delete'   => __DIR__ . '/api/delete.php',
    '/api/health'   => __DIR__ . '/api/health.php',
];

foreach ($routes as $route => $file) {
    if ($uri === $route || $uri === $route . '.php') {
        require $file;
        exit;
    }
}

// Fallback: If requesting an existing API script directly, let PHP serve it
if (preg_match('#^/api/([a-zA-Z0-9_\-]+)\.php$#', $uri, $m)) {
    $script = __DIR__ . '/api/' . $m[1] . '.php';
    if (file_exists($script)) {
        require $script;
        exit;
    }
}

// Otherwise show status landing
require_once __DIR__ . '/config.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroNode Remote Backup Server</title>
    <style>
        body { background: #0a0a0c; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; padding: 2rem; margin: 0; line-height: 1.6; }
        .card { max-width: 700px; margin: 3rem auto; background: #121318; border: 1px solid #27272a; border-radius: 8px; padding: 2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        h1 { font-size: 1.25rem; color: #a5b4fc; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0; border-bottom: 1px solid #27272a; padding-bottom: 1rem; }
        .badge { display: inline-block; background: #10b981; color: #000; font-weight: bold; font-size: 0.75rem; padding: 0.2rem 0.6rem; border-radius: 4px; text-transform: uppercase; }
        ul { padding-left: 1.2rem; }
        code { background: #1e1e24; color: #38bdf8; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.9em; }
        .footer { font-size: 0.8rem; color: #71717a; margin-top: 2rem; text-align: center; }
    </style>
</head>
<body>
    <div class="card">
        <h1>ZeroNode Backup Server <span class="badge">Online</span></h1>
        <p>This is the dedicated <b>ZeroNode Remote Chunked Backup Server</b>.</p>
        <p>It accepts authenticated, chunked, hash-verified encrypted user snapshots and system database backups.</p>
        
        <h3>API Endpoints</h3>
        <ul>
            <li><code>POST /api/init.php</code> — Initialize chunked upload session</li>
            <li><code>POST /api/chunk.php</code> — Upload chunk with SHA-256 validation</li>
            <li><code>POST /api/finalize.php</code> — Assemble chunks, verify file SHA-256 & auto-prune</li>
            <li><code>GET /api/list.php</code> — List remote backup archives</li>
            <li><code>GET /api/download.php?backup_id=...</code> — Download backup archive</li>
            <li><code>POST /api/delete.php</code> — Delete specific backup</li>
            <li><code>GET /api/health.php</code> — Service diagnostic ping</li>
        </ul>

        <p><strong>Configured Retention:</strong> Past <?= htmlspecialchars($MAX_BACKUPS_PER_TARGET) ?> backups retained per target (user or server).</p>
        <div class="footer">ZeroNode &bull; Encrypted Storage Platform</div>
    </div>
</body>
</html>

