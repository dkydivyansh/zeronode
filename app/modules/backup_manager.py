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
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timezone
from app.modules import db_handler
from app.modules import backup_events

# Module-level scheduler lock and state
_scheduler_started = False
_scheduler_lock = threading.Lock()

CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB chunks for fast, reliable streaming

class BackupCancelledError(Exception):
    """Raised when an active backup or restore operation is cancelled or aborted."""
    pass

# Global cancellation event (e.g. for complete server reset)
_cancel_all_event = threading.Event()
# Granular tracking of active tasks, threads, and sessions
_task_cancel_events = {}       # task_id -> threading.Event()
_task_target_map = {}          # task_id -> (target_type, target_id)
_active_worker_threads = {}    # task_id -> threading.Thread()
_active_http_sessions = {}     # task_id -> requests.Session()
_tasks_lock = threading.Lock()

def _register_task(task_id: str, target_type: str, target_id: str, thread: threading.Thread = None):
    with _tasks_lock:
        _task_cancel_events[task_id] = threading.Event()
        _task_target_map[task_id] = (str(target_type), str(target_id))
        if thread:
            _active_worker_threads[task_id] = thread

def _register_session(task_id: str, session: requests.Session):
    with _tasks_lock:
        _active_http_sessions[task_id] = session

def _deregister_task(task_id: str):
    with _tasks_lock:
        _task_cancel_events.pop(task_id, None)
        _task_target_map.pop(task_id, None)
        _active_worker_threads.pop(task_id, None)
        _active_http_sessions.pop(task_id, None)

def is_cancelled(task_id: str = None) -> bool:
    """Checks whether system wipe has been initiated or the specific task was cancelled."""
    if _cancel_all_event.is_set():
        return True
    if task_id:
        with _tasks_lock:
            evt = _task_cancel_events.get(task_id)
            if evt and evt.is_set():
                return True
    return False

def cancel_task(task_id: str) -> bool:
    """Cancels a specific task by task_id and closes its socket connection if active."""
    with _tasks_lock:
        evt = _task_cancel_events.get(task_id)
        if evt:
            evt.set()
        sess = _active_http_sessions.get(task_id)
        if sess:
            try:
                sess.close()
            except Exception:
                pass
        return evt is not None

def cancel_target_operations(target_type: str, target_id: str) -> int:
    """Cancels any running backup/restore task targeting a specific user or server."""
    target_type = str(target_type)
    target_id = str(target_id)
    with _tasks_lock:
        to_cancel = [
            tid for tid, (ttype, tid_val) in _task_target_map.items()
            if (ttype == target_type and tid_val == target_id) or (target_type == 'user' and tid_val.lower() == target_id.lower())
        ]
    for tid in to_cancel:
        cancel_task(tid)
    return len(to_cancel)

def cancel_all_operations(timeout: float = 2.0) -> int:
    """
    Aborts all running backup and restore tasks immediately and stops the scheduler.
    Waits up to `timeout` seconds for active worker threads to terminate cleanly.
    """
    _cancel_all_event.set()
    with _tasks_lock:
        for evt in _task_cancel_events.values():
            evt.set()
        for sess in _active_http_sessions.values():
            try:
                sess.close()
            except Exception:
                pass
        threads = list(_active_worker_threads.values())

    end_time = time.time() + timeout
    for t in threads:
        remaining = end_time - time.time()
        if remaining > 0 and t.is_alive():
            t.join(timeout=remaining)
    return len(threads)

def reset_cancellation_state():
    """Resets the cancellation state (e.g. for testing or system re-initialization)."""
    _cancel_all_event.clear()
    with _tasks_lock:
        _task_cancel_events.clear()
        _task_target_map.clear()
        _active_worker_threads.clear()
        _active_http_sessions.clear()

def _get_backup_session(pool_connections: int = 5, pool_maxsize: int = 10, retries: int = 3) -> requests.Session:
    """Returns a requests.Session configured with HTTP Keep-Alive connection pooling."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        raise_on_status=False
    )
    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=retry_strategy
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def abort_remote_session(session_id: str, reason: str = ""):
    """Notifies the PHP backup server to mark an upload session as failed and delete partial chunks."""
    if not session_id or _cancel_all_event.is_set():
        return
    try:
        settings = db_handler.get_backup_settings()
        server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
        api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'
        abort_url = f"{server_url}/api/abort.php"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        with requests.Session() as s:
            s.post(abort_url, json={"session_id": session_id, "reason": reason}, headers=headers, timeout=5)
    except Exception as e:
        print(f"[BackupManager] Remote abort call failed (ignored): {e}")

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

    with zipfile.ZipFile(temp_zip_path, 'w') as zf:
        # 1. Manifest (Deflated)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2), compress_type=zipfile.ZIP_DEFLATED)

        if os.path.exists(user_vault_dir):
            # 2. SQLite Database Snapshot (Deflated)
            user_db_path = os.path.join(user_vault_dir, f"{user_id}.db")
            if os.path.exists(user_db_path):
                temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
                os.close(temp_db_fd)
                try:
                    _make_sqlite_snapshot(user_db_path, temp_db_path)
                    zf.write(temp_db_path, arcname=f"{user_id}.db", compress_type=zipfile.ZIP_DEFLATED)
                finally:
                    if os.path.exists(temp_db_path):
                        try:
                            os.remove(temp_db_path)
                        except OSError:
                            pass

            # 3. Encrypted Chunk Blobs (.bin) -> Stored uncompressed (already AES-GCM encrypted)
            # This drastically accelerates packaging of multi-gigabyte user drives (e.g. 34 GB)
            bin_count = 0
            for root, _, files in os.walk(user_vault_dir):
                for fname in files:
                    if fname.endswith(".bin"):
                        fpath = os.path.join(root, fname)
                        zf.write(fpath, arcname=f"blobs/{fname}", compress_type=zipfile.ZIP_STORED)
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
                # Clean up running tasks from snapshot so restored DB never has a dangling running task
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


def _send_request(url: str, method: str = 'POST', headers: dict = None, body: bytes = None, timeout: int = 60) -> dict:
    """Helper to perform HTTP requests to the PHP backup server with error decoding."""
    headers = headers or {}
    try:
        resp = requests.request(method, url, data=body, headers=headers, timeout=timeout)
        try:
            return resp.json()
        except Exception:
            if resp.ok:
                return {"success": True}
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
    except requests.RequestException as e:
        raise RuntimeError(f"Backup server connection failed: {e}")


def upload_chunked_backup(zip_path: str, target_type: str, target_id: str, file_hash: str, file_size: int, metadata: dict, task_id: str) -> dict:
    """
    Executes chunked upload with per-chunk SHA-256 validation,
    HTTP Keep-Alive socket pooling, and auto-abort cleanup on the PHP backup server.
    Emits real-time progress events over WebSockets at every phase.
    """
    if is_cancelled(task_id):
        raise BackupCancelledError("Backup operation cancelled before upload.")

    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    chunk_size = CHUNK_SIZE
    total_chunks = max(1, math.ceil(file_size / chunk_size))
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{target_id}_{timestamp_slug}.zip.bin"

    step_msg = "Negotiating upload session with remote backup server..."
    if not is_cancelled(task_id):
        try:
            db_handler.update_backup_task(
                task_id, 
                progress=28, 
                current_step=step_msg,
                backup_filename=filename,
                backup_hash=file_hash
            )
            backup_events.broadcast_event({
                "type": "backup_progress",
                "operation": "backup",
                "task_id": task_id,
                "target_type": target_type,
                "target_id": target_id,
                "phase": "init",
                "progress": 28,
                "step": step_msg
            })
        except Exception:
            pass

    session_id = None
    http_session = _get_backup_session()
    _register_session(task_id, http_session)

    try:
        if is_cancelled(task_id):
            raise BackupCancelledError("Backup operation cancelled before upload session initialization.")

        # ── Phase 1: Initialize Upload Session ───────────────────────────────────
        init_url = f"{server_url}/api/init.php"
        init_payload = {
            "target_type": target_type,
            "target_id": target_id,
            "filename": filename,
            "total_size": file_size,
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "file_hash": file_hash,
            "metadata": metadata
        }
        init_headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        init_resp = http_session.post(init_url, json=init_payload, headers=init_headers, timeout=60)
        try:
            init_res = init_resp.json()
        except Exception:
            raise RuntimeError(f"HTTP {init_resp.status_code}: {init_resp.text}")

        if not init_res.get('success'):
            raise RuntimeError(init_res.get('error', "Upload session initialization rejected."))

        session_id = init_res['session_id']

        # ── Phase 2: Upload Chunks with SHA-256 Validation & Persistent Pooling ──
        chunk_url = f"{server_url}/api/chunk.php"

        with open(zip_path, 'rb') as f:
            for idx in range(total_chunks):
                if is_cancelled(task_id):
                    raise BackupCancelledError("Backup operation cancelled during chunk upload.")

                chunk_data = f.read(chunk_size)
                if not chunk_data:
                    break

                chunk_hash = hashlib.sha256(chunk_data).hexdigest().lower()
                target_chunk_url = f"{server_url}/api/chunk.php?session_id={session_id}&chunk_index={idx}&chunk_hash={chunk_hash}"
                chunk_headers = {
                    "Authorization": f"Bearer {api_key}",
                    "X-Session-ID": session_id,
                    "X-Chunk-Index": str(idx),
                    "X-Chunk-Hash": chunk_hash,
                    "Content-Type": "application/octet-stream"
                }

                # Upload chunk with robust per-chunk retry resilience
                max_chunk_retries = 5
                chunk_ok = False
                last_err = None

                for attempt in range(1, max_chunk_retries + 1):
                    if is_cancelled(task_id):
                        raise BackupCancelledError("Backup operation cancelled.")
                    try:
                        resp = http_session.post(
                            target_chunk_url,
                            data=chunk_data,
                            headers=chunk_headers,
                            timeout=90
                        )
                        if resp.status_code == 200:
                            chunk_res = resp.json()
                            if chunk_res.get('success'):
                                chunk_ok = True
                                break
                            raise RuntimeError(chunk_res.get('error', f"Chunk {idx} rejected by server."))
                        elif resp.status_code in [500, 502, 503, 504, 408]:
                            last_err = f"Server returned HTTP {resp.status_code}"
                            time.sleep(attempt * 1.5)
                        else:
                            try:
                                err_data = resp.json()
                                err_text = err_data.get('error', f"HTTP {resp.status_code}")
                            except Exception:
                                err_text = f"HTTP {resp.status_code}: {resp.text[:100]}"
                            if is_cancelled(task_id) or (resp.status_code == 404 and "session" in err_text.lower()):
                                if is_cancelled(task_id):
                                    raise BackupCancelledError("Backup cancelled: upload session cleared during system reset.")
                            raise RuntimeError(err_text)
                    except (requests.RequestException, ConnectionError, OSError) as ce:
                        if is_cancelled(task_id):
                            raise BackupCancelledError("Backup operation cancelled.")
                        last_err = str(ce)
                        if attempt < max_chunk_retries:
                            time.sleep(attempt * 1.5)
                            continue
                        raise RuntimeError(f"Backup server connection failed on chunk {idx + 1}/{total_chunks} after {max_chunk_retries} attempts: {last_err}")

                if not chunk_ok:
                    if is_cancelled(task_id):
                        raise BackupCancelledError("Backup operation cancelled.")
                    raise RuntimeError(f"Chunk {idx + 1}/{total_chunks} failed: {last_err}")

                # Live upload progress scales from 30% to 85%
                pct = int(30 + ((idx + 1) / total_chunks) * 55)
                step_msg = f"Uploading chunk {idx + 1}/{total_chunks} ({pct}%)..."
                if not is_cancelled(task_id):
                    try:
                        db_handler.update_backup_task(
                            task_id, 
                            progress=pct, 
                            current_step=step_msg
                        )
                        backup_events.broadcast_event({
                            "type": "backup_progress",
                            "operation": "backup",
                            "task_id": task_id,
                            "target_type": target_type,
                            "target_id": target_id,
                            "phase": "upload",
                            "progress": pct,
                            "step": step_msg,
                            "chunk_index": idx + 1,
                            "total_chunks": total_chunks
                        })
                    except Exception:
                        pass

        if is_cancelled(task_id):
            raise BackupCancelledError("Backup operation cancelled before finalization.")

        # ── Phase 3: Finalize, Verify Full Hash & Auto-Prune ──────────────────────
        step_msg = "Verifying remote checksum & auto-pruning archives on backup server..."
        if not is_cancelled(task_id):
            try:
                db_handler.update_backup_task(task_id, progress=88, current_step=step_msg)
                backup_events.broadcast_event({
                    "type": "backup_progress",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "verify",
                    "progress": 88,
                    "step": step_msg
                })
            except Exception:
                pass

        finalize_url = f"{server_url}/api/finalize.php"
        finalize_payload = {"session_id": session_id}
        finalize_headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        fin_resp = http_session.post(finalize_url, json=finalize_payload, headers=finalize_headers, timeout=120)
        try:
            finalize_res = fin_resp.json()
        except Exception:
            raise RuntimeError(f"HTTP {fin_resp.status_code}: {fin_resp.text}")

        if not finalize_res.get('success'):
            raise RuntimeError(finalize_res.get('error', "Final assembly and verification failed."))

        if not is_cancelled(task_id):
            try:
                db_handler.record_backup_result(
                    target_type, target_id,
                    success=True,
                    size=file_size,
                    file_hash=file_hash
                )
            except Exception:
                pass

        return finalize_res

    except BackupCancelledError:
        if session_id and not _cancel_all_event.is_set():
            abort_remote_session(session_id, reason="Backup cancelled.")
        raise
    except Exception as e:
        if is_cancelled(task_id):
            raise BackupCancelledError("Backup cancelled.")
        if session_id and not _cancel_all_event.is_set():
            abort_remote_session(session_id, reason=str(e))
        raise
    finally:
        try:
            http_session.close()
        except Exception:
            pass


def run_backup(target_type: str, target_id: str, task_id: str = None) -> bool:
    """
    Complete execution pipeline for backing up a user or server.
    Phases:
      1. Compress: snapshots DB and compresses drive data into temporary .zip.bin (0% - 25%)
      2. Hash & Init: computes SHA-256 and registers upload session (25% - 30%)
      3. Upload: streams chunk by chunk with SHA-256 check (30% - 85%)
      4. Verify: verifies remote assembly and checksum (85% - 95%)
      5. Cleanup: deletes local temporary compressed zip (95% - 99%)
      6. Finalized: marks task success and broadcasts completion (100%)
    """
    if not task_id:
        task_id = str(uuid.uuid4())
        db_handler.create_backup_task(task_id, target_type, target_id)

    _register_task(task_id, target_type, target_id, threading.current_thread())
    temp_zip_path = None
    try:
        if is_cancelled(task_id):
            raise BackupCancelledError("Backup operation cancelled before initiation.")

        # Phase 1: Compress
        step_msg = "Creating database snapshot and compressing drive into zip archive..."
        if not is_cancelled(task_id):
            try:
                db_handler.update_backup_task(task_id, progress=5, current_step=step_msg)
                backup_events.broadcast_event({
                    "type": "backup_progress",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "compress",
                    "progress": 5,
                    "step": step_msg
                })
            except Exception:
                pass

        if target_type == 'user':
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

        if is_cancelled(task_id):
            raise BackupCancelledError("Backup operation cancelled during archive creation.")

        step_msg = "Drive data compressed into temporary archive. Computing checksum..."
        if not is_cancelled(task_id):
            try:
                db_handler.update_backup_task(task_id, progress=25, current_step=step_msg)
                backup_events.broadcast_event({
                    "type": "backup_progress",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "compress",
                    "progress": 25,
                    "step": step_msg
                })
            except Exception:
                pass

        # Phase 2, 3, 4: Upload chunks & verify on remote server
        upload_chunked_backup(temp_zip_path, target_type, target_id, file_hash, file_size, metadata, task_id)

        if is_cancelled(task_id):
            raise BackupCancelledError("Backup operation cancelled.")

        # Phase 5: Delete local compressed zip
        step_msg = "Deleting local temporary compressed archive..."
        if not is_cancelled(task_id):
            try:
                db_handler.update_backup_task(task_id, progress=96, current_step=step_msg)
                backup_events.broadcast_event({
                    "type": "backup_progress",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "cleanup",
                    "progress": 96,
                    "step": step_msg
                })
            except Exception:
                pass

        if temp_zip_path and os.path.exists(temp_zip_path):
            try: os.remove(temp_zip_path)
            except OSError: pass

        # Phase 6: Finalized
        step_msg = "Backup verified and finalized successfully."
        if not is_cancelled(task_id):
            try:
                db_handler.update_backup_task(task_id, status="success", progress=100, current_step=step_msg)
                backup_events.broadcast_event({
                    "type": "backup_completed",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "done",
                    "progress": 100,
                    "step": step_msg,
                    "file_hash": file_hash,
                    "size": file_size
                })
            except Exception:
                pass

        return True

    except BackupCancelledError:
        if not _cancel_all_event.is_set():
            try:
                db_handler.update_backup_task(
                    task_id,
                    status="failed",
                    error_message="Backup operation cancelled.",
                    current_step="Cancelled"
                )
                backup_events.broadcast_event({
                    "type": "backup_failed",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "cancelled",
                    "progress": 0,
                    "step": "Backup cancelled",
                    "error": "Backup operation cancelled."
                })
            except Exception:
                pass
        return False

    except Exception as e:
        if is_cancelled(task_id):
            return False
        error_msg = str(e)
        if not _cancel_all_event.is_set():
            try:
                db_handler.update_backup_task(
                    task_id,
                    status="failed",
                    error_message=error_msg,
                    current_step="Failed"
                )
                db_handler.record_backup_result(target_type, target_id, success=False, error=error_msg)
            except Exception:
                pass
            try:
                backup_events.broadcast_event({
                    "type": "backup_failed",
                    "operation": "backup",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "failed",
                    "progress": 0,
                    "step": f"Backup failed: {error_msg}",
                    "error": error_msg
                })
            except Exception:
                pass
        return False

    finally:
        if temp_zip_path and os.path.exists(temp_zip_path):
            try:
                os.remove(temp_zip_path)
            except OSError:
                pass
        _deregister_task(task_id)


def trigger_backup_async(target_type: str, target_id: str) -> str:
    """
    Asynchronously launches a backup job in a background daemon thread.
    Returns the task_id immediately for real-time progress polling.
    Raises RuntimeError if a backup or restore job is already running or system is wiping.
    """
    if _cancel_all_event.is_set() or db_handler.is_server_wiping():
        raise RuntimeError("Cannot start backup: system reset is currently in progress.")

    # 1. Guard against concurrent restore
    active_restore = db_handler.get_active_restore_task(target_type, target_id) or db_handler.get_any_active_restore_task()
    if active_restore:
        raise RuntimeError(f"Cannot start backup: a restore operation ({active_restore['task_id'][:8]}) is currently in progress.")

    # 2. Guard against concurrent backup
    active_backup = db_handler.get_active_backup_task(target_type, target_id)
    if not active_backup and target_type == 'server':
        active_backup = db_handler.get_any_active_backup_task()
    if active_backup:
        raise RuntimeError(f"Backup is already running ({active_backup['task_id'][:8]}).")

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
    success = res.get('success', False)
    if success:
        try:
            reconcile_all_backup_records()
        except Exception:
            pass
    return success


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
    res = _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)
    try:
        reconcile_all_backup_records()
    except Exception:
        pass
    return res


def delete_remote_backups_for_target(target_id: str) -> dict:
    """Deletes all remote backup archives belonging to a specific target (e.g. user_id on wipe)."""
    if not target_id:
        return {"success": True, "deleted_count": 0}
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = json.dumps({"target_id": target_id}).encode('utf-8')
    try:
        res = _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)
        reconcile_all_backup_records()
        return res
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
        res = _send_request(f"{server_url}/api/delete.php", method='POST', headers=headers, body=payload)
        reconcile_all_backup_records()
        return res
    except Exception as e:
        print(f"[BackupManager] Error purging all remote backups during server wipe: {e}")
        return {"success": False, "error": str(e)}


def reconcile_all_backup_records() -> dict:
    """
    Reconciles local SQLite records (user_backup_configs & backup_settings)
    with actual archives present on the remote backup server.
    
    If remote backup server is reachable:
    - For users: verifies if a remote archive exists for their user_id / email.
      If none exists, resets last_backup_at to 0 so the dashboard never shows phantom backups.
      If archives exist, syncs last_backup_at, last_size, last_hash to the newest archive.
    - For server: verifies if a server archive exists on remote.
      If none exists, resets last_server_backup_at to 0.
      If archives exist, syncs last_server_backup_* to the newest archive.
    """
    if db_handler.is_server_wiping():
        return {"reconciled": False, "wiping": True}

    try:
        remote_backups = fetch_remote_backups()
    except Exception as e:
        return {"reconciled": False, "error": str(e)}

    # 1. Server Reconciliation
    server_archives = [b for b in remote_backups if b.get('target_type') == 'server' or b.get('target_id') == 'server']
    if server_archives:
        latest_server = server_archives[0]
        db_handler.record_backup_result(
            'server', 'server',
            success=True,
            size=int(latest_server.get('total_size') or latest_server.get('file_size') or 0),
            file_hash=latest_server.get('file_hash') or '',
            error=''
        )
        created_at = int(latest_server.get('created_at') or 0)
        if created_at > 0:
            db_handler.update_backup_settings({'last_server_backup_at': str(created_at)})
    else:
        db_handler.reset_backup_result('server', 'server')

    # 2. User Reconciliation
    all_users = db_handler.get_all_user_backup_configs()
    for u in all_users:
        u_id = u.get('user_id')
        email = u.get('email')
        user_archives = [
            b for b in remote_backups 
            if b.get('target_type') == 'user' and (b.get('target_id') in (u_id, email))
        ]
        if user_archives:
            latest_user = user_archives[0]
            created_at = int(latest_user.get('created_at') or 0)
            size = int(latest_user.get('total_size') or latest_user.get('file_size') or 0)
            f_hash = latest_user.get('file_hash') or ''
            db_handler.update_user_backup_config(
                email,
                last_backup_at=created_at,
                last_status='success',
                last_size=size,
                last_hash=f_hash,
                last_error=''
            )
        else:
            cfg = db_handler.get_user_backup_config(email)
            if int(cfg.get('last_backup_at') or 0) > 0:
                db_handler.reset_backup_result('user', u_id or email)

    return {"reconciled": True, "remote_count": len(remote_backups)}


def stream_remote_backup(backup_id: str):
    """
    Streams a remote backup archive from the PHP backup server using backend API credentials.
    Returns the requests streaming response.
    """
    settings = db_handler.get_backup_settings()
    server_url = (settings.get('backup_server_url') or 'http://127.0.0.1:8080').rstrip('/')
    api_key = settings.get('backup_server_api_key') or 'zeronode_secret_backup_key_2026'

    download_url = f"{server_url}/api/download.php?backup_id={urllib.parse.quote(backup_id)}"
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        resp = requests.get(download_url, headers=headers, stream=True, timeout=90)
        if not resp.ok:
            raise RuntimeError(f"Remote backup download failed: HTTP {resp.status_code}")
        return resp
    except requests.RequestException as e:
        raise RuntimeError(f"Could not connect to backup server: {e}")


def download_backup_to_temp(backup_id: str, task_id: str = None, target_type: str = None, target_id: str = None) -> str:
    """Downloads a remote backup archive into a local temporary file with progress updates."""
    if is_cancelled(task_id):
        raise BackupCancelledError("Restore operation cancelled before download.")
    remote_resp = stream_remote_backup(backup_id)
    total_bytes = 0
    try:
        total_bytes = int(remote_resp.headers.get('Content-Length') or 0)
    except Exception:
        total_bytes = 0

    temp_fd, temp_path = tempfile.mkstemp(prefix="znode_restore_", suffix=".zip.bin")
    downloaded_bytes = 0
    last_report_bytes = 0
    last_report_time = time.time()

    with os.fdopen(temp_fd, 'wb') as f:
        for chunk in remote_resp.iter_content(chunk_size=65536):
            if is_cancelled(task_id):
                remote_resp.close()
                raise BackupCancelledError("Restore operation cancelled during download.")
            if not chunk:
                continue
            f.write(chunk)
            downloaded_bytes += len(chunk)

            # Report every 256KB or every 0.3s
            now = time.time()
            if (downloaded_bytes - last_report_bytes >= 262144) or (now - last_report_time >= 0.3):
                last_report_bytes = downloaded_bytes
                last_report_time = now
                if total_bytes > 0:
                    ratio = min(1.0, downloaded_bytes / total_bytes)
                    prog = 5 + int(ratio * 35)  # 5% to 40%
                    step_msg = f"Downloading remote archive: {downloaded_bytes / (1024*1024):.2f} MB / {total_bytes / (1024*1024):.2f} MB ({int(ratio * 100)}%)..."
                else:
                    prog = 20
                    step_msg = f"Downloading remote archive: {downloaded_bytes / (1024*1024):.2f} MB..."

                if task_id and not is_cancelled(task_id):
                    try:
                        db_handler.update_restore_task(task_id, progress=prog, current_step=step_msg)
                        backup_events.broadcast_event({
                            "type": "restore_progress",
                            "operation": "restore",
                            "task_id": task_id,
                            "target_type": target_type,
                            "target_id": target_id,
                            "phase": "download",
                            "progress": prog,
                            "step": step_msg,
                            "downloaded_bytes": downloaded_bytes,
                            "total_bytes": total_bytes
                        })
                    except Exception:
                        pass

    remote_resp.close()

    if task_id and not is_cancelled(task_id):
        try:
            step_msg = f"Download complete ({downloaded_bytes / (1024*1024):.2f} MB). Verifying archive..."
            db_handler.update_restore_task(task_id, progress=40, current_step=step_msg)
            backup_events.broadcast_event({
                "type": "restore_progress",
                "operation": "restore",
                "task_id": task_id,
                "target_type": target_type,
                "target_id": target_id,
                "phase": "download",
                "progress": 40,
                "step": step_msg,
                "downloaded_bytes": downloaded_bytes,
                "total_bytes": total_bytes
            })
        except Exception:
            pass

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


def restore_archive(archive_path: str, expected_target_type: str = None, expected_target_id: str = None, task_id: str = None) -> dict:
    """
    Restores user drive or server state from a .zip.bin archive.
    Validates manifest.json, overwrites database and chunk blobs.
    Broadcasts step progress across verify, restore_db, restore_blobs, and cleanup phases.
    """
    if not os.path.exists(archive_path):
        raise FileNotFoundError("Backup archive file does not exist.")
    if is_cancelled(task_id):
        raise BackupCancelledError("Restore operation cancelled before archive inspection.")

    # Phase 2: Verify & Manifest Inspection
    step_msg = "Inspecting backup manifest and validating archive structure..."
    if task_id and not is_cancelled(task_id):
        try:
            db_handler.update_restore_task(task_id, progress=45, current_step=step_msg)
            backup_events.broadcast_event({
                "type": "restore_progress",
                "operation": "restore",
                "task_id": task_id,
                "target_type": expected_target_type,
                "target_id": expected_target_id,
                "phase": "verify",
                "progress": 45,
                "step": step_msg
            })
        except Exception:
            pass

    with zipfile.ZipFile(archive_path, 'r') as zf:
        # 1. Read & Validate Manifest
        try:
            manifest_data = zf.read("manifest.json")
            manifest = json.loads(manifest_data.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid backup archive: missing or corrupt manifest.json ({e})")

        format_type = manifest.get("format")

        # ── Branch A: User Drive Restore ─────────────────────────────────
        if format_type in ("zeronode_user_backup", "zeronode_vault_backup") or manifest.get("type") == "user":
            user_id = manifest.get("user_id")
            if not user_id:
                raise ValueError("Manifest missing user_id.")
            if expected_target_id and expected_target_id != 'server' and expected_target_id != user_id:
                raise PermissionError(f"Archive belongs to user '{user_id}', cannot restore to '{expected_target_id}'.")
            if expected_target_type and expected_target_type not in ('user', 'server'):
                raise ValueError(f"Expected target type '{expected_target_type}' but archive is 'user'.")

            if is_cancelled(task_id):
                raise BackupCancelledError("Restore operation cancelled.")

            from flask import current_app
            try:
                data_root = current_app.config['DATA_DIR']
            except Exception:
                data_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'data')

            user_dir = os.path.normpath(os.path.join(data_root, user_id))
            os.makedirs(user_dir, exist_ok=True)

            # Phase 3: Restore <user_id>.db
            db_arcname = f"{user_id}.db"
            if db_arcname in zf.namelist():
                step_msg = f"Restoring user database ({db_arcname})..."
                if task_id and not is_cancelled(task_id):
                    try:
                        db_handler.update_restore_task(task_id, progress=55, current_step=step_msg)
                        backup_events.broadcast_event({
                            "type": "restore_progress",
                            "operation": "restore",
                            "task_id": task_id,
                            "target_type": "user",
                            "target_id": user_id,
                            "phase": "restore_db",
                            "progress": 55,
                            "step": step_msg
                        })
                    except Exception:
                        pass

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

            if is_cancelled(task_id):
                raise BackupCancelledError("Restore operation cancelled.")

            # Phase 4: Restore Encrypted Blobs
            blob_items = [item for item in zf.namelist() if item.startswith("blobs/") and item.endswith(".bin")]
            total_blobs = len(blob_items)
            step_msg = f"Restoring {total_blobs} encrypted file chunk blobs..."
            if task_id and not is_cancelled(task_id):
                try:
                    db_handler.update_restore_task(task_id, progress=70, current_step=step_msg)
                    backup_events.broadcast_event({
                        "type": "restore_progress",
                        "operation": "restore",
                        "task_id": task_id,
                        "target_type": "user",
                        "target_id": user_id,
                        "phase": "restore_blobs",
                        "progress": 70,
                        "step": step_msg,
                        "blob_count": total_blobs
                    })
                except Exception:
                    pass

            blob_count = 0
            for idx, item in enumerate(blob_items):
                if is_cancelled(task_id):
                    raise BackupCancelledError("Restore operation cancelled during blob extraction.")

                fname = os.path.basename(item)
                if fname:
                    blob_bytes = zf.read(item)
                    dest_path = os.path.join(user_dir, fname)
                    with open(dest_path, 'wb') as f:
                        f.write(blob_bytes)
                    blob_count += 1

                if task_id and not is_cancelled(task_id) and (idx % 10 == 0 or idx == total_blobs - 1):
                    try:
                        prog = 70 + int(((idx + 1) / max(1, total_blobs)) * 20)
                        step_sub = f"Restored {idx + 1}/{total_blobs} chunk blobs..."
                        db_handler.update_restore_task(task_id, progress=prog, current_step=step_sub)
                        backup_events.broadcast_event({
                            "type": "restore_progress",
                            "operation": "restore",
                            "task_id": task_id,
                            "target_type": "user",
                            "target_id": user_id,
                            "phase": "restore_blobs",
                            "progress": prog,
                            "step": step_sub
                        })
                    except Exception:
                        pass

            if is_cancelled(task_id):
                raise BackupCancelledError("Restore operation cancelled.")

            # Phase 5: Cleanup staging
            step_msg = "Finalizing user drive restore..."
            if task_id and not is_cancelled(task_id):
                try:
                    db_handler.update_restore_task(task_id, progress=95, current_step=step_msg)
                    backup_events.broadcast_event({
                        "type": "restore_progress",
                        "operation": "restore",
                        "task_id": task_id,
                        "target_type": "user",
                        "target_id": user_id,
                        "phase": "cleanup",
                        "progress": 95,
                        "step": step_msg
                    })
                except Exception:
                    pass

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

            if is_cancelled(task_id):
                raise BackupCancelledError("Server restore operation cancelled.")

            # Phase 3: Restore server_data.db
            if "server_data.db" in zf.namelist():
                step_msg = "Restoring master server database (server_data.db)..."
                if task_id and not is_cancelled(task_id):
                    try:
                        db_handler.update_restore_task(task_id, progress=60, current_step=step_msg)
                        backup_events.broadcast_event({
                            "type": "restore_progress",
                            "operation": "restore",
                            "task_id": task_id,
                            "target_type": "server",
                            "target_id": "server",
                            "phase": "restore_db",
                            "progress": 60,
                            "step": step_msg
                        })
                    except Exception:
                        pass

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

                # Re-ensure restore task record exists in newly restored DB
                if task_id and not is_cancelled(task_id):
                    try:
                        db_handler.create_restore_task(task_id, "server", "server")
                        db_handler.update_restore_task(task_id, status="running", progress=90, current_step="Master database restored successfully.")
                    except Exception:
                        pass

            if is_cancelled(task_id):
                raise BackupCancelledError("Server restore operation cancelled.")

            # Phase 5: Cleanup
            step_msg = "Finalizing master server restore..."
            if task_id and not is_cancelled(task_id):
                try:
                    db_handler.update_restore_task(task_id, progress=95, current_step=step_msg)
                    backup_events.broadcast_event({
                        "type": "restore_progress",
                        "operation": "restore",
                        "task_id": task_id,
                        "target_type": "server",
                        "target_id": "server",
                        "phase": "cleanup",
                        "progress": 95,
                        "step": step_msg
                    })
                except Exception:
                    pass

            return {
                "success": True,
                "target_type": "server",
                "target_id": "server",
                "restored_at": int(time.time()),
                "manifest": manifest
            }

        else:
            raise ValueError(f"Unsupported backup archive format: {format_type}")


def run_restore(target_type: str, target_id: str, backup_id: str = None, archive_file_path: str = None, task_id: str = None) -> bool:
    """
    Executes an end-to-end restore operation.
    Downloads from remote backup server if backup_id is provided, or uses uploaded archive_file_path.
    Emits granular WebSocket events for download, verify, restore_db, restore_blobs, cleanup, and completion.
    """
    if not task_id:
        task_id = str(uuid.uuid4())
        db_handler.create_restore_task(task_id, target_type, target_id, backup_id=backup_id or '')

    _register_task(task_id, target_type, target_id, threading.current_thread())
    temp_downloaded_path = None
    try:
        if is_cancelled(task_id):
            raise BackupCancelledError("Restore operation cancelled before initiation.")

        if backup_id:
            step_msg = "Connecting to remote backup server..."
            if not is_cancelled(task_id):
                try:
                    db_handler.update_restore_task(task_id, progress=5, current_step=step_msg)
                    backup_events.broadcast_event({
                        "type": "restore_progress",
                        "operation": "restore",
                        "task_id": task_id,
                        "target_type": target_type,
                        "target_id": target_id,
                        "phase": "download",
                        "progress": 5,
                        "step": step_msg
                    })
                except Exception:
                    pass
            temp_downloaded_path = download_backup_to_temp(backup_id, task_id=task_id, target_type=target_type, target_id=target_id)
            archive_to_restore = temp_downloaded_path
        elif archive_file_path:
            archive_to_restore = archive_file_path
        else:
            raise ValueError("Neither backup_id nor archive_file_path was provided for restore.")

        if is_cancelled(task_id):
            raise BackupCancelledError("Restore operation cancelled.")

        res = restore_archive(archive_to_restore, expected_target_type=target_type, expected_target_id=target_id, task_id=task_id)

        actual_type = res.get('target_type') or target_type
        actual_id = res.get('target_id') or target_id

        # Final Phase: Done
        step_msg = f"Restore completed successfully. All data restored for {actual_type}."
        if not is_cancelled(task_id):
            try:
                db_handler.update_restore_task(task_id, target_type=actual_type, target_id=actual_id, status="success", progress=100, current_step=step_msg)
                backup_events.broadcast_event({
                    "type": "restore_completed",
                    "operation": "restore",
                    "task_id": task_id,
                    "target_type": actual_type,
                    "target_id": actual_id,
                    "phase": "done",
                    "progress": 100,
                    "step": step_msg,
                    "details": res
                })
            except Exception:
                pass
        return True

    except BackupCancelledError:
        if not _cancel_all_event.is_set():
            try:
                db_handler.update_restore_task(task_id, status="failed", progress=0, current_step="Restore cancelled.", error_message="Cancelled")
                backup_events.broadcast_event({
                    "type": "restore_failed",
                    "operation": "restore",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "cancelled",
                    "progress": 0,
                    "step": "Restore cancelled",
                    "error": "Restore cancelled."
                })
            except Exception:
                pass
        return False

    except Exception as e:
        if is_cancelled(task_id):
            return False
        err_msg = str(e)
        if not _cancel_all_event.is_set():
            try:
                db_handler.update_restore_task(task_id, status="failed", progress=0, current_step=f"Restore failed: {err_msg}", error_message=err_msg)
            except Exception:
                pass
            try:
                backup_events.broadcast_event({
                    "type": "restore_failed",
                    "operation": "restore",
                    "task_id": task_id,
                    "target_type": target_type,
                    "target_id": target_id,
                    "phase": "failed",
                    "progress": 0,
                    "step": f"Restore failed: {err_msg}",
                    "error": err_msg
                })
            except Exception:
                pass
        return False

    finally:
        if temp_downloaded_path and os.path.exists(temp_downloaded_path):
            try: os.remove(temp_downloaded_path)
            except OSError: pass
        if archive_file_path and os.path.exists(archive_file_path):
            try: os.remove(archive_file_path)
            except OSError: pass
        _deregister_task(task_id)


def trigger_restore_async(target_type: str, target_id: str, backup_id: str = None, archive_file_path: str = None) -> str:
    """
    Asynchronously launches a restore job in a background daemon thread.
    Returns task_id immediately.
    Raises RuntimeError if a restore or backup job is already running or system is wiping.
    """
    if _cancel_all_event.is_set() or db_handler.is_server_wiping():
        raise RuntimeError("Cannot start restore: system reset is currently in progress.")

    # 1. Guard against concurrent restore
    active_restore = db_handler.get_active_restore_task(target_type, target_id) or db_handler.get_any_active_restore_task()
    if active_restore:
        raise RuntimeError(f"Restore is already running ({active_restore['task_id'][:8]}).")

    # 2. Guard against concurrent backup
    active_backup = db_handler.get_active_backup_task(target_type, target_id) or db_handler.get_any_active_backup_task()
    if active_backup:
        raise RuntimeError(f"Cannot start restore: a backup operation ({active_backup['task_id'][:8]}) is currently in progress.")

    task_id = str(uuid.uuid4())
    db_handler.create_restore_task(task_id, target_type, target_id, backup_id=backup_id or '')

    t = threading.Thread(
        target=run_restore,
        args=(target_type, target_id, backup_id, archive_file_path, task_id),
        name=f"RestoreWorker-{task_id[:8]}",
        daemon=True
    )
    t.start()
    return task_id


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

    while not _cancel_all_event.is_set():
        if db_handler.is_server_wiping() or _cancel_all_event.is_set():
            break
        try:
            now = int(time.time())
            settings = db_handler.get_backup_settings()

            # 1. Server Master Backup Check
            server_enabled = settings.get('server_backup_enabled') == '1'
            if server_enabled and not _cancel_all_event.is_set():
                server_interval = settings.get('server_backup_interval', 'daily')
                threshold = 86400 if server_interval == 'daily' else 604800
                last_server_backup = int(settings.get('last_server_backup_at') or 0)

                if (now - last_server_backup) >= threshold:
                    # Check if already running
                    active = db_handler.get_active_backup_task('server', 'server')
                    if not active and not _cancel_all_event.is_set():
                        run_backup('server', 'server')

            # 2. Individual User Backup Check
            if not _cancel_all_event.is_set():
                user_configs = db_handler.get_all_user_backup_configs()
                for u in user_configs:
                    if _cancel_all_event.is_set():
                        break
                    if u.get('enabled') == 1:
                        interval = u.get('interval', 'daily')
                        threshold = 86400 if interval == 'daily' else 604800
                        last_backup = int(u.get('last_backup_at') or 0)

                        if (now - last_backup) >= threshold:
                            active = db_handler.get_active_backup_task('user', u['user_id'])
                            if not active and not _cancel_all_event.is_set():
                                run_backup('user', u['user_id'])
                                time.sleep(2)  # Throttle sequential backups

        except Exception as e:
            if not _cancel_all_event.is_set():
                print(f"[BackupScheduler] Error during scheduled check: {e}")

        # Sleep in short intervals so thread can respond immediately to cancellation
        for _ in range(60):
            if _cancel_all_event.is_set() or db_handler.is_server_wiping():
                break
            time.sleep(1)


def start_backup_scheduler():
    """Initializes the background scheduler thread once."""
    global _scheduler_started
    with _scheduler_lock:
        if not _scheduler_started:
            _scheduler_started = True
            t = threading.Thread(target=_scheduler_loop, name="ZeroNodeBackupScheduler", daemon=True)
            t.start()
