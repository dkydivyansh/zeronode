import os
import sys
import json
import time
import math
import uuid
import zipfile
import hashlib
import sqlite3
import tempfile
import threading
import urllib.request
import urllib.parse
import urllib.error
import shutil
from datetime import datetime, timezone
from app.modules import db_handler

# Module-level scheduler lock and state
_scheduler_started = False
_scheduler_lock = threading.Lock()

CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB chunks for reliable streaming

def _make_sqlite_snapshot(source_db_path: str, target_db_path: str):
    """Safely snapshot a SQLite database using the SQLite backup API."""
    if not os.path.exists(source_db_path):
        return
    src = sqlite3.connect(source_db_path)
    dst = sqlite3.connect(target_db_path)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()

def create_user_archive(user_id: str) -> tuple[str, str, int, dict]:
    """
    Packages a user's vault (isolated SQLite DB, encrypted chunks, and metadata)
    into a compressed .zip.bin archive.
    Returns: (temp_archive_path, sha256_hex, file_size, manifest_metadata)
    """
    data_dir = db_handler.DATA_DIR
    user_vault_dir = os.path.normpath(os.path.join(data_dir, user_id))
    
    # Resolve user details from master database
    conn = db_handler._get_conn()
    user_row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()

    user_info = dict(user_row) if user_row else {"user_id": user_id, "email": "unknown"}
    now_iso = datetime.now(timezone.utc).isoformat()
    now_ts = int(time.time())

    manifest = {
        "format": "zeronode_user_backup",
        "version": 1,
        "type": "user",
        "user_id": user_id,
        "email": user_info.get("email", ""),
        "first_name": user_info.get("first_name", ""),
        "last_name": user_info.get("last_name", ""),
        "exported_at": now_iso,
        "exported_ts": now_ts,
    }

    # Create temporary zip archive
    temp_fd, temp_zip_path = tempfile.mkstemp(prefix=f"znode_user_{user_id[:8]}_", suffix=".zip.bin")
    os.close(temp_fd)

    with zipfile.ZipFile(temp_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. Manifest
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        if os.path.exists(user_vault_dir):
            # 2. SQLite Database Snapshot
            user_db_path = os.path.join(user_vault_dir, f"{user_id}.db")
            if os.path.exists(user_db_path):
                temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
                os.close(temp_db_fd)
                try:
                    _make_sqlite_snapshot(user_db_path, temp_db_path)
                    zf.write(temp_db_path, arcname=f"{user_id}.db")
                finally:
                    if os.path.exists(temp_db_path):
                        try:
                            os.remove(temp_db_path)
                        except OSError:
                            pass

            # 3. Encrypted Chunk Blobs (.bin)
            bin_count = 0
            for root, _, files in os.walk(user_vault_dir):
                for fname in files:
                    if fname.endswith(".bin"):
                        fpath = os.path.join(root, fname)
                        zf.write(fpath, arcname=f"blobs/{fname}")
                        bin_count += 1
            manifest["blob_count"] = bin_count

    # Compute overall archive SHA-256
    sha256 = hashlib.sha256()
    with open(temp_zip_path, 'rb') as f:
        while chunk := f.read(1048576):
            sha256.update(chunk)
            
    file_hash = sha256.hexdigest().lower()
    file_size = os.path.getsize(temp_zip_path)
    return temp_zip_path, file_hash, file_size, manifest


def create_server_archive() -> tuple[str, str, int, dict]:
    """
    Packages the master server database and global state into a compressed archive.
    Returns: (temp_archive_path, sha256_hex, file_size, manifest_metadata)
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    now_ts = int(time.time())

    manifest = {
        "format": "zeronode_server_backup",
        "version": 1,
        "type": "server",
        "exported_at": now_iso,
        "exported_ts": now_ts,
    }

    temp_fd, temp_zip_path = tempfile.mkstemp(prefix="znode_server_", suffix=".zip.bin")
    os.close(temp_fd)

    master_db_path = db_handler.DB_PATH

    with zipfile.ZipFile(temp_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        if os.path.exists(master_db_path):
            temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
            os.close(temp_db_fd)
            try:
                _make_sqlite_snapshot(master_db_path, temp_db_path)
                # Purge running tasks from snapshot so restored DB never has a dangling running task
                try:
                    snap_conn = sqlite3.connect(temp_db_path)
                    snap_conn.execute("DELETE FROM backup_tasks WHERE status = 'running'")
                    snap_conn.commit()
                    snap_conn.close()
                except Exception:
                    pass
                zf.write(temp_db_path, arcname="server_data.db")
            finally:
                if os.path.exists(temp_db_path):
                    try:
                        os.remove(temp_db_path)
                    except OSError:
                        pass

    sha256 = hashlib.sha256()
    with open(temp_zip_path, 'rb') as f:
        while chunk := f.read(1048576):
            sha256.update(chunk)

    file_hash = sha256.hexdigest().lower()
    file_size = os.path.getsize(temp_zip_path)
    return temp_zip_path, file_hash, file_size, manifest


def _send_request(url: str, method: str = 'POST', headers: dict = None, body: bytes = None) -> dict:
    """Helper to perform HTTP requests to the PHP backup server with error decoding."""
    headers = headers or {}
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
            return json.loads(data.decode('utf-8'))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='replace')
        try:
            parsed = json.loads(err_body)
            raise RuntimeError(parsed.get('error', f"HTTP {e.code}: {e.reason}"))
        except json.JSONDecodeError:
            raise RuntimeError(f"HTTP {e.code}: {err_body or e.reason}")
    except Exception as e:
        raise RuntimeError(f"Backup server connection failed: {e}")


def upload_chunked_backup(zip_path: str, target_type: str, target_id: str, file_hash: str, file_size: int, metadata: dict, task_id: str) -> dict:
    """
    Executes a 3-phase chunked upload with per-chunk SHA-256 validation
    and overall archive verification against the PHP backup server.
    """
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    chunk_size = CHUNK_SIZE
    total_chunks = max(1, math.ceil(file_size / chunk_size))
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target_id}_{timestamp_slug}.zip.bin"

    db_handler.update_backup_task(
        task_id, 
        progress=5, 
        current_step="Negotiating upload session with backup server...",
        backup_filename=filename,
        backup_hash=file_hash
    )

    # ── Phase 1: Initialize Upload Session ───────────────────────────────────
    init_url = f"{server_url}/api/init.php"
    init_payload = json.dumps({
        "target_type": target_type,
        "target_id": target_id,
        "filename": filename,
        "total_size": file_size,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "file_hash": file_hash,
        "metadata": metadata
    }).encode('utf-8')

    init_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    init_res = _send_request(init_url, method='POST', headers=init_headers, body=init_payload)
    if not init_res.get('success'):
        raise RuntimeError(init_res.get('error', "Upload session initialization rejected."))

    session_id = init_res['session_id']

    # ── Phase 2: Upload Chunks with SHA-256 Validation ───────────────────────
    chunk_url = f"{server_url}/api/chunk.php"

    with open(zip_path, 'rb') as f:
        for idx in range(total_chunks):
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break

            chunk_hash = hashlib.sha256(chunk_data).hexdigest().lower()
            chunk_url = f"{server_url}/api/chunk.php?session_id={session_id}&chunk_index={idx}&chunk_hash={chunk_hash}"
            chunk_headers = {
                "Authorization": f"Bearer {api_key}",
                "X-Session-ID": session_id,
                "X-Chunk-Index": str(idx),
                "X-Chunk-Hash": chunk_hash,
                "Content-Type": "application/octet-stream"
            }

            chunk_res = _send_request(chunk_url, method='POST', headers=chunk_headers, body=chunk_data)
            if not chunk_res.get('success'):
                raise RuntimeError(chunk_res.get('error', f"Chunk {idx} rejected by backup server."))

            # Update live progress (10% to 90%)
            pct = int(10 + ((idx + 1) / total_chunks) * 80)
            db_handler.update_backup_task(
                task_id, 
                progress=pct, 
                current_step=f"Uploading chunk {idx + 1}/{total_chunks} ({pct}%)"
            )

    # ── Phase 3: Finalize, Verify Full Hash & Auto-Prune ──────────────────────
    db_handler.update_backup_task(task_id, progress=92, current_step="Verifying remote checksum & auto-pruning...")
    finalize_url = f"{server_url}/api/finalize.php"
    finalize_payload = json.dumps({"session_id": session_id}).encode('utf-8')
    finalize_headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    finalize_res = _send_request(finalize_url, method='POST', headers=finalize_headers, body=finalize_payload)
    if not finalize_res.get('success'):
        raise RuntimeError(finalize_res.get('error', "Final assembly and verification failed."))

    db_handler.update_backup_task(
        task_id,
        status="success",
        progress=100,
        current_step="Backup verified and finalized successfully."
    )

    db_handler.record_backup_result(
        target_type, target_id,
        success=True,
        size=file_size,
        file_hash=file_hash
    )

    return finalize_res


def run_backup(target_type: str, target_id: str, task_id: str = None) -> bool:
    """
    Complete synchronous execution pipeline for backing up a user or server.
    """
    if not task_id:
        task_id = str(uuid.uuid4())
        db_handler.create_backup_task(task_id, target_type, target_id)

    temp_zip_path = None
    try:
        db_handler.update_backup_task(task_id, progress=2, current_step="Generating backup snapshot...")

        if target_type == 'user':
            # Target ID might be an email, resolve to user_id
            user_id = target_id
            if '@' in target_id:
                conn = db_handler._get_conn()
                u = conn.execute("SELECT user_id FROM users WHERE email = ?", (target_id.lower().strip(),)).fetchone()
                conn.close()
                if not u:
                    raise ValueError(f"User account not found for email: {target_id}")
                user_id = u['user_id']

            temp_zip_path, file_hash, file_size, metadata = create_user_archive(user_id)
        elif target_type == 'server':
            temp_zip_path, file_hash, file_size, metadata = create_server_archive()
        else:
            raise ValueError(f"Invalid target_type: {target_type}")

        # Stream chunked upload
        upload_chunked_backup(temp_zip_path, target_type, target_id, file_hash, file_size, metadata, task_id)
        return True

    except Exception as e:
        error_msg = str(e)
        db_handler.update_backup_task(
            task_id,
            status="failed",
            error_message=error_msg,
            current_step="Failed"
        )
        db_handler.record_backup_result(target_type, target_id, success=False, error=error_msg)
        return False

    finally:
        if temp_zip_path and os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except OSError:
                pass


def trigger_backup_async(target_type: str, target_id: str) -> str:
    """
    Asynchronously launches a backup job in a background daemon thread.
    Returns the task_id immediately for real-time progress polling.
    """
    task_id = str(uuid.uuid4())
    db_handler.create_backup_task(task_id, target_type, target_id)

    t = threading.Thread(
        target=run_backup,
        args=(target_type, target_id, task_id),
        name=f"BackupWorker-{task_id[:8]}",
        daemon=True
    )
    t.start()
    return task_id


def test_remote_connection() -> dict:
    """Diagnostic ping to the remote backup server."""
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {"Authorization": f"Bearer {api_key}"}
    return _send_request(f"{server_url}/api/health.php", method='GET', headers=headers)


def fetch_remote_backups(target_id: str = None) -> list:
    """Retrieves list of active archives stored on the backup server."""
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {"Authorization": f"Bearer {api_key}"}
    query = f"?target_id={urllib.parse.quote(target_id)}" if target_id else ""
    res = _send_request(f"{server_url}/api/list.php{query}", method='GET', headers=headers)
    return res.get('backups', [])


def delete_remote_backup(backup_id: str) -> bool:
    """Removes a specific backup archive from the backup server."""
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"backup_id": backup_id}).encode('utf-8')
    res = _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)
    return res.get('success', False)


def delete_remote_backups_bulk(backup_ids: list) -> dict:
    """Removes a list of backup archives from the remote backup server in bulk."""
    if not backup_ids:
        return {"success": True, "deleted_count": 0}
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"backup_ids": backup_ids}).encode('utf-8')
    return _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)


def delete_remote_backups_for_target(target_id: str) -> dict:
    """Deletes all remote backup archives belonging to a specific target (e.g. user_id on wipe)."""
    if not target_id:
        return {"success": True, "purged_count": 0}
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"target_id": target_id}).encode('utf-8')
    try:
        return _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)
    except Exception as e:
        print(f"[BackupManager] Error deleting remote backups for target {target_id}: {e}")
        return {"success": False, "error": str(e)}


def delete_all_remote_backups() -> dict:
    """Deletes ALL remote backup archives on the backup server (for full server reset)."""
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"all": True}).encode('utf-8')
    try:
        return _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)
    except Exception as e:
        print(f"[BackupManager] Error purging all remote backups during server wipe: {e}")
        return {"success": False, "error": str(e)}


def stream_remote_backup(backup_id: str):
    """
    Streams a remote backup archive from the PHP backup server using backend API credentials.
    Returns the urllib.response object.
    """
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    download_url = f"{server_url}/api/download.php?backup_id={urllib.parse.quote(backup_id)}"
    req = urllib.request.Request(download_url, headers={
        "Authorization": f"Bearer {api_key}"
    })
    try:
        return urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Remote backup download failed: HTTP {e.code}")
    except Exception as e:
        raise RuntimeError(f"Could not connect to backup server: {e}")


def download_backup_to_temp(backup_id: str) -> str:
    """Downloads a remote backup archive into a local temporary file."""
    remote_resp = stream_remote_backup(backup_id)
    temp_fd, temp_path = tempfile.mkstemp(prefix="znode_restore_", suffix=".zip.bin")
    with os.fdopen(temp_fd, 'wb') as f:
        while True:
            chunk = remote_resp.read(65536)
            if not chunk:
                break
            f.write(chunk)
    remote_resp.close()
    return temp_path


def _restore_sqlite_database(snapshot_path: str, target_db_path: str) -> None:
    """
    Safely restores an SQLite database using SQLite Backup API or atomic replace.
    Safe against concurrent WAL-mode file locks on Windows.
    """
    target_dir = os.path.dirname(os.path.abspath(target_db_path))
    os.makedirs(target_dir, exist_ok=True)
    
    # If target exists, try Online Backup API first
    if os.path.exists(target_db_path):
        try:
            src_conn = sqlite3.connect(snapshot_path)
            dst_conn = sqlite3.connect(target_db_path)
            src_conn.backup(dst_conn)
            src_conn.close()
            dst_conn.close()
            return
        except Exception:
            pass

    # Fallback to file copy with wal/shm cleanup
    wal_path = f"{target_db_path}-wal"
    shm_path = f"{target_db_path}-shm"
    if os.path.exists(wal_path):
        try: os.remove(wal_path)
        except OSError: pass
    if os.path.exists(shm_path):
        try: os.remove(shm_path)
        except OSError: pass

    shutil.copyfile(snapshot_path, target_db_path)


def restore_archive(archive_path: str, expected_target_type: str = None, expected_target_id: str = None) -> dict:
    """
    Restores user vault or server state from a .zip.bin archive.
    Validates manifest.json, overwrites database and chunk blobs.
    """
    if not os.path.exists(archive_path):
        raise FileNotFoundError("Backup archive file does not exist.")

    with zipfile.ZipFile(archive_path, 'r') as zf:
        # 1. Read & Validate Manifest
        try:
            manifest_data = zf.read("manifest.json")
            manifest = json.loads(manifest_data.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid backup archive: missing or corrupt manifest.json ({e})")

        format_type = manifest.get("format")

        # ── Branch A: User Vault Restore ─────────────────────────────────
        if format_type in ("zeronode_user_backup", "zeronode_vault_backup") or manifest.get("type") == "user":
            user_id = manifest.get("user_id")
            if not user_id:
                raise ValueError("Manifest missing user_id.")
            if expected_target_id and expected_target_id != user_id:
                raise PermissionError(f"Archive belongs to user '{user_id}', cannot restore to '{expected_target_id}'.")
            if expected_target_type and expected_target_type != 'user':
                raise ValueError(f"Expected target type '{expected_target_type}' but archive is 'user'.")

            from flask import current_app
            try:
                data_root = current_app.config['DATA_DIR']
            except Exception:
                data_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'data')

            user_dir = os.path.normpath(os.path.join(data_root, user_id))
            os.makedirs(user_dir, exist_ok=True)

            # A.1: Restore <user_id>.db
            db_arcname = f"{user_id}.db"
            if db_arcname in zf.namelist():
                temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
                os.close(temp_db_fd)
                try:
                    with open(temp_db_path, 'wb') as f:
                        f.write(zf.read(db_arcname))
                    target_db_path = os.path.join(user_dir, db_arcname)
                    _restore_sqlite_database(temp_db_path, target_db_path)
                finally:
                    if os.path.exists(temp_db_path):
                        try: os.remove(temp_db_path)
                        except OSError: pass

            # A.2: Restore Encrypted Blobs
            blob_count = 0
            for item in zf.namelist():
                if item.startswith("blobs/") and item.endswith(".bin"):
                    fname = os.path.basename(item)
                    if fname:
                        blob_bytes = zf.read(item)
                        dest_path = os.path.join(user_dir, fname)
                        with open(dest_path, 'wb') as f:
                            f.write(blob_bytes)
                        blob_count += 1

            return {
                "success": True,
                "target_type": "user",
                "target_id": user_id,
                "blob_count": blob_count,
                "restored_at": int(time.time()),
                "manifest": manifest
            }

        # ── Branch B: Master Server Restore ──────────────────────────────
        elif format_type in ("zeronode_server_backup", "zeronode_master_backup") or manifest.get("type") == "server":
            if expected_target_type and expected_target_type != 'server':
                raise ValueError(f"Expected target type '{expected_target_type}' but archive is 'server'.")

            # B.1: Restore server_data.db
            if "server_data.db" in zf.namelist():
                temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
                os.close(temp_db_fd)
                try:
                    with open(temp_db_path, 'wb') as f:
                        f.write(zf.read("server_data.db"))
                    target_db_path = db_handler.DB_PATH
                    _restore_sqlite_database(temp_db_path, target_db_path)
                finally:
                    if os.path.exists(temp_db_path):
                        try: os.remove(temp_db_path)
                        except OSError: pass

            return {
                "success": True,
                "target_type": "server",
                "target_id": "server",
                "restored_at": int(time.time()),
                "manifest": manifest
            }

        else:
            raise ValueError(f"Unsupported backup archive format: {format_type}")


def restore_from_backup_id(backup_id: str, expected_target_type: str = None, expected_target_id: str = None) -> dict:
    """
    Downloads remote backup archive and restores it locally.
    Cleans up the temporary download file when complete.
    """
    temp_archive = download_backup_to_temp(backup_id)
    try:
        return restore_archive(temp_archive, expected_target_type=expected_target_type, expected_target_id=expected_target_id)
    finally:
        if os.path.exists(temp_archive):
            try: os.remove(temp_archive)
            except OSError: pass


# ─── Automated Periodic Scheduler ─────────────────────────────────────────────

def _scheduler_loop():
    """Background worker loop checking for overdue automated backups."""
    time.sleep(10)  # Initial grace period after app startup

    while True:
        try:
            now = int(time.time())
            settings = db_handler.get_backup_settings()

            # 1. Server Master Backup Check
            server_enabled = settings.get('server_backup_enabled') == '1'
            if server_enabled:
                server_interval = settings.get('server_backup_interval', 'daily')
                threshold = 86400 if server_interval == 'daily' else 604800
                last_server_backup = int(settings.get('last_server_backup_at') or 0)

                if (now - last_server_backup) >= threshold:
                    # Check if already running
                    active = db_handler.get_active_backup_task('server', 'server')
                    if not active:
                        run_backup('server', 'server')

            # 2. Individual User Backup Check
            user_configs = db_handler.get_all_user_backup_configs()
            for u in user_configs:
                if u.get('enabled') == 1:
                    interval = u.get('interval', 'daily')
                    threshold = 86400 if interval == 'daily' else 604800
                    last_backup = int(u.get('last_backup_at') or 0)

                    if (now - last_backup) >= threshold:
                        active = db_handler.get_active_backup_task('user', u['user_id'])
                        if not active:
                            run_backup('user', u['user_id'])
                            time.sleep(2)  # Throttle sequential backups

        except Exception as e:
            print(f"[BackupScheduler] Error during scheduled check: {e}")

        time.sleep(60)  # Check every 60 seconds


def start_backup_scheduler():
    """Initializes the background scheduler thread once."""
    global _scheduler_started
    with _scheduler_lock:
        if not _scheduler_started:
            _scheduler_started = True
            t = threading.Thread(target=_scheduler_loop, name="ZeroNodeBackupScheduler", daemon=True)
            t.start()
