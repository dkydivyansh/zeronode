import os
from flask import Blueprint, redirect, g
from app.routes.auth import get_current_user
from app.dash.loader import load_modules, get_loaded_modules

_dash_dir = os.path.dirname(__file__)

dashboard_bp = Blueprint(
    'dashboard', __name__,
    url_prefix='/app',
    template_folder=_dash_dir   # shell.html + modules/ live here
)


@dashboard_bp.before_request
def enforce_auth():
    """Strict session enforcement for ALL /app/* routes."""
    user = get_current_user()
    if not user:
        return redirect('/auth/logout?next=/login&auto=1')
    g.user = user

@dashboard_bp.context_processor
def inject_modules():
    """Inject loaded modules globally into all dashboard templates."""
    import time
    from app.config import Config
    raw_ver = str(Config.APP_VERSION or '1.2.0')
    app_ver = f"v{raw_ver}" if not raw_ver.startswith("v") else raw_ver
    return dict(
        app_modules=get_loaded_modules(), 
        now_ts=int(time.time()), 
        app_version=app_ver,
        app_name=Config.APP_NAME,
        build_id=Config.BUILD_ID
    )


from flask import send_file, request, jsonify, stream_with_context, Response, current_app
from app.modules.user_data import get_user_manager

# ─── File Download API ────────────────────────────────────────

@dashboard_bp.route('/api/file/<file_uuid>')
def stream_file(file_uuid):
    """
    Highly optimized chunked file streaming API.
    Uses WSGI FileWrapper/sendfile native OS hooks internally.
    Supports HTTP Range headers for partial content / resume.
    """
    manager = get_user_manager()
    try:
        file_package = manager.get_file(file_uuid)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404

    try:
        file_path = file_package['file_path']
        metadata = file_package['metadata']

        resp = send_file(
            file_path,
            as_attachment=False,
            mimetype='application/octet-stream'
        )
        # Force strict isolation to prevent IDM / External capture
        resp.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Download-Options'] = 'noopen'
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return resp
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Chunked Upload API ──────────────────────────────────────

@dashboard_bp.route('/api/file/init', methods=['POST'])
def upload_init():
    """Phase 1: Reserve a UUID and register file metadata.
    Expects JSON: { "file_name": "report.pdf", "aes_key": "encrypted..." }
    Returns JSON: { "uuid": "abcd-1234..." }
    """
    data = request.get_json(silent=True)
    if not data or not data.get('file_name') or not data.get('aes_key'):
        return jsonify({"error": "Missing required fields: file_name, aes_key"}), 400

    manager = get_user_manager()
    try:
        folder_id = data.get('folder_id')
        file_uuid = manager.init_file_upload(data['file_name'], data['aes_key'], folder_id=folder_id)
        return jsonify({"uuid": file_uuid}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/file/<file_uuid>/chunk', methods=['POST'])
def upload_chunk(file_uuid):
    """Phase 2: Write a single encrypted chunk at a specific byte offset.
    Expects Header: X-Chunk-Offset: <integer byte offset>
    Expects Body:   Raw binary chunk bytes (request.data)
    """
    offset_str = request.headers.get('X-Chunk-Offset')
    if offset_str is None:
        return jsonify({"error": "Missing required header: X-Chunk-Offset"}), 400

    try:
        offset = int(offset_str)
    except ValueError:
        return jsonify({"error": "X-Chunk-Offset must be an integer"}), 400

    chunk_bytes = request.data
    if not chunk_bytes:
        return jsonify({"error": "Empty chunk body"}), 400

    manager = get_user_manager()
    try:
        manager.write_file_chunk(file_uuid, chunk_bytes, offset)
        return jsonify({"status": "ok", "offset": offset, "size": len(chunk_bytes)}), 200
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/api/file/<file_uuid>/finalize', methods=['POST'])
def upload_finalize(file_uuid):
    """Phase 3: Commit the upload. Validates the file has content.
    Returns final metadata with file size.
    """
    manager = get_user_manager()
    try:
        result = manager.finalize_file(file_uuid)
        manager.invalidate_stats_cache()
        return jsonify(result), 200
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── File Delete API ──────────────────────────────────────────

@dashboard_bp.route('/api/file/<file_uuid>', methods=['DELETE'])
def delete_file(file_uuid):
    """Permanently delete an encrypted file blob and its metadata.
    Strict ownership enforced by UserDataManager internally.
    """
    manager = get_user_manager()
    success = manager.delete_file(file_uuid)
    if success:
        manager.invalidate_stats_cache()
        return jsonify({"status": "deleted", "uuid": file_uuid}), 200
    else:
        return jsonify({"error": "File not found or access denied"}), 404

@dashboard_bp.route('/api/file/<file_uuid>/content', methods=['PUT'])
def update_file_content(file_uuid):
    """
    Overwrite the binary content of an existing file.
    Expects Raw binary body.
    Optional Header: X-AES-Key (if the key was rotated, else reuses old).
    """
    manager = get_user_manager()
    try:
        new_content = request.data
        aes_key = request.headers.get('X-AES-Key')
        result = manager.update_file_content(file_uuid, new_content, aes_key=aes_key)
        return jsonify(result), 200
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── File Metadata API ───────────────────────────────────────

@dashboard_bp.route('/api/file/<file_uuid>/meta', methods=['GET'])
def get_file_meta(file_uuid):
    """Get metadata for a file without downloading the binary."""
    manager = get_user_manager()
    try:
        file_package = manager.get_file(file_uuid)
        return jsonify(file_package['metadata']), 200
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404

@dashboard_bp.route('/api/file/<file_uuid>/meta', methods=['PATCH'])
def update_file_meta(file_uuid):
    """Update file_name and/or aes_key. Only these fields are mutable.
    Expects JSON: { "file_name": "new_name.pdf" } and/or { "aes_key": "new_key" }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body provided"}), 400

    manager = get_user_manager()
    success = manager.update_file_metadata(
        file_uuid,
        file_name=data.get('file_name'),
        aes_key=data.get('aes_key')
    )
    if success:
        return jsonify({"status": "updated"}), 200
    else:
        return jsonify({"error": "File not found or access denied"}), 404

# ─── Vault Key Management API ─────────────────────────────────

@dashboard_bp.route('/api/key/status', methods=['GET'])
def get_key_status():
    """Check if the user has completed the ECDH Vault setup."""
    manager = get_user_manager()
    has_key = manager.config_get("has_key") == "1"
    
    response = jsonify({"has_key": has_key})
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response, 200

@dashboard_bp.route('/api/key/save', methods=['POST'])
def save_keys():
    """Phase 1: Initial Vault Setup. Stores BOTH password-wrapped and phrase-wrapped keys."""
    data = request.get_json(silent=True)
    required = ("public_key", "encrypted_private_key", "salt", "recovery_encrypted_private_key", "recovery_salt")
    if not data or not all(k in data for k in required):
        return jsonify({"error": "Missing required key fields"}), 400

    manager = get_user_manager()
    if manager.config_get("has_key") == "1":
        return jsonify({"error": "Keys already exist. Use revocation instead."}), 403

    manager.config_set("public_key", data['public_key'])
    manager.config_set("encrypted_private_key", data['encrypted_private_key'])
    manager.config_set("key_salt", data['salt'])
    
    manager.config_set("recovery_encrypted_private_key", data['recovery_encrypted_private_key'])
    manager.config_set("recovery_salt", data['recovery_salt'])
    
    manager.config_set("has_key", "1")
    return jsonify({"status": "keys_saved"}), 201

@dashboard_bp.route('/api/key/load', methods=['GET'])
def load_keys():
    """Phase 2: Vault Unlock. Retrieves all wrapped keys."""
    manager = get_user_manager()
    if manager.config_get("has_key") != "1":
        return jsonify({"error": "Vault keys not set up"}), 404

    return jsonify({
        "public_key": manager.config_get("public_key"),
        "encrypted_private_key": manager.config_get("encrypted_private_key"),
        "salt": manager.config_get("key_salt")
    }), 200

@dashboard_bp.route('/api/key/recovery', methods=['GET'])
def load_recovery_keys():
    """Phase 3: Vault Recovery. Retrieves the backup phrase-wrapped key bundle."""
    manager = get_user_manager()
    if manager.config_get("has_key") != "1":
        return jsonify({"error": "Vault keys not set up"}), 404

    return jsonify({
        "recovery_encrypted_private_key": manager.config_get("recovery_encrypted_private_key"),
        "recovery_salt": manager.config_get("recovery_salt"),
        "public_key": manager.config_get("public_key")
    }), 200

@dashboard_bp.route('/api/key/reset', methods=['POST'])
def reset_keys():
    """Phase 3: Forgot Password. Overwrite the main password and rotate the seed phrase."""
    data = request.get_json(silent=True)
    required = ("encrypted_private_key", "salt", "recovery_encrypted_private_key", "recovery_salt")
    if not data or not all(k in data for k in required):
        return jsonify({"error": "Missing reset fields"}), 400
        
    manager = get_user_manager()
    if manager.config_get("has_key") != "1":
         return jsonify({"error": "No vault to reset."}), 404
         
    manager.config_set("encrypted_private_key", data['encrypted_private_key'])
    manager.config_set("key_salt", data['salt'])
    manager.config_set("recovery_encrypted_private_key", data['recovery_encrypted_private_key'])
    manager.config_set("recovery_salt", data['recovery_salt'])
    
    return jsonify({"status": "keys_reset"}), 200


# ─── File Listing API ────────────────────────────────────────

@dashboard_bp.route('/api/files', methods=['GET'])
def list_files():
    """Paginated file listing.
    Query params: ?limit=100&offset=0
    """
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)

    # Clamp limits to prevent abuse
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    manager = get_user_manager()
    files = manager.list_files(limit=limit, offset=offset)
    return jsonify({"files": files, "limit": limit, "offset": offset, "count": len(files)}), 200

# ─── Drive API (Folders & Hierarchy) ─────────────────────────

@dashboard_bp.route('/api/drive/folder', methods=['POST'])
def api_create_folder():
    """Create a new folder."""
    data = request.get_json(silent=True)
    if not data or 'name' not in data:
        return jsonify({"error": "Folder name required"}), 400
        
    manager = get_user_manager()
    try:
        folder_id = manager.create_folder(data['name'], data.get('parent_id'))
        return jsonify({"status": "created", "id": folder_id}), 201
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403

@dashboard_bp.route('/api/drive/list', methods=['GET'])
@dashboard_bp.route('/api/drive/list/<folder_id>', methods=['GET'])
def api_list_folder(folder_id=None):
    """List contents of a specific folder or root."""
    manager = get_user_manager()
    result = manager.list_folder(folder_id)
    return jsonify(result), 200

@dashboard_bp.route('/api/drive/all_folders', methods=['GET'])
def api_list_all_folders():
    """Flat list of all folders for UI pickers."""
    manager = get_user_manager()
    folders = manager.get_all_folders()
    return jsonify({"folders": folders}), 200

@dashboard_bp.route('/api/drive/folder/<folder_id>', methods=['PATCH'])
def api_update_folder(folder_id):
    """Rename or move a folder."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON payload"}), 400
        
    manager = get_user_manager()
    try:
        if 'name' in data:
            manager.rename_folder(folder_id, data['name'])
        if 'parent_id' in data:
            manager.move_folder(folder_id, data['parent_id'])
        return jsonify({"status": "updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@dashboard_bp.route('/api/drive/file/<file_uuid>/move', methods=['PATCH'])
def api_move_file(file_uuid):
    """Move a file to a new folder (or root if null)."""
    data = request.get_json(silent=True)
    if not data or 'folder_id' not in data:
        return jsonify({"error": "folder_id required (can be null)"}), 400
        
    manager = get_user_manager()
    success = manager.move_file(file_uuid, data['folder_id'])
    if success:
        return jsonify({"status": "moved"}), 200
    return jsonify({"error": "File not found"}), 404

# ─── Drive Deletion API ───────────────────────────────────────

@dashboard_bp.route('/api/drive/delete/folder/<folder_id>', methods=['POST'])
def api_delete_folder(folder_id):
    manager = get_user_manager()
    if manager.delete_item(folder_id, is_folder=True):
        return jsonify({"status": "deleted"}), 200
    return jsonify({"error": "Folder not found"}), 404

@dashboard_bp.route('/api/drive/delete/file/<file_uuid>', methods=['POST'])
def api_delete_file(file_uuid):
    manager = get_user_manager()
    if manager.delete_item(file_uuid, is_folder=False):
        return jsonify({"status": "deleted"}), 200
    return jsonify({"error": "File not found"}), 404

@dashboard_bp.route('/api/drive/bulk/delete', methods=['POST'])
def api_bulk_delete():
    data = request.get_json(silent=True) or {}
    file_ids = data.get('file_ids', [])
    folder_ids = data.get('folder_ids', [])
    if not isinstance(file_ids, list) or not isinstance(folder_ids, list):
        return jsonify({"error": "file_ids and folder_ids must be arrays"}), 400
    if not file_ids and not folder_ids:
        return jsonify({"error": "No items specified for deletion"}), 400

    manager = get_user_manager()
    try:
        res = manager.bulk_delete(file_ids, folder_ids)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@dashboard_bp.route('/api/drive/bulk/move', methods=['POST'])
def api_bulk_move():
    data = request.get_json(silent=True) or {}
    file_ids = data.get('file_ids', [])
    folder_ids = data.get('folder_ids', [])
    target_folder_id = data.get('target_folder_id')

    if not isinstance(file_ids, list) or not isinstance(folder_ids, list):
        return jsonify({"error": "file_ids and folder_ids must be arrays"}), 400
    if not file_ids and not folder_ids:
        return jsonify({"error": "No items specified to move"}), 400

    manager = get_user_manager()
    try:
        res = manager.bulk_move(file_ids, folder_ids, target_folder_id)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ─── Search API ──────────────────────────────────────────────

@dashboard_bp.route('/api/drive/search', methods=['GET'])
def api_search():
    query = request.args.get("q", "")
    if not query:
        return jsonify({"folders": [], "files": []}), 200
        
    limit = max(1, min(request.args.get("limit", 50, type=int), 200))
    manager = get_user_manager()
    results = manager.search(query, limit)
    return jsonify(results), 200

# ─── Security & Account Deletion API ──────────────────────────

@dashboard_bp.route('/api/user/self_wipe', methods=['POST'])
def api_self_wipe():
    """
    Permanently deletes the current user account and stored files.
    """
    data = request.get_json(silent=True)
    expected = "I want to wipe my data"
    
    if not data or data.get('confirmation') != expected:
        return jsonify({"error": "Confirmation phrase did not match. Deletion aborted."}), 400
        
    user_id = g.user['user_id']
    from app.modules import db_handler
    
    success = db_handler.wipe_self(user_id)
    if success:
        return jsonify({"status": "IDENTITY_PURGED", "redirect": "/auth/logout?auto=1"}), 200
    else:
        return jsonify({"error": "Account deletion failed due to an internal error."}), 500

# ─── User Backup Status API ──────────────────────────────────

@dashboard_bp.route('/api/backup/user/status', methods=['GET'])
def api_user_backup_status():
    """Retrieve backup status for the current authenticated user."""
    from app.modules import db_handler, backup_manager
    email = g.user.get('email', '')
    user_id = g.user.get('user_id', '')
    
    try:
        backup_manager.reconcile_all_backup_records()
    except Exception:
        pass

    cfg = db_handler.get_user_backup_config(email)
    active_task = db_handler.get_active_backup_task('user', user_id)
    active_restore = db_handler.get_active_restore_task('user', user_id)
    latest_task = db_handler.get_latest_backup_task('user', user_id)
    if not latest_task:
        latest_task = db_handler.get_latest_backup_task('user', email)
        
    is_admin = db_handler.is_admin(email)
    server_settings = db_handler.get_backup_settings() if is_admin else {}
    global_active = db_handler.get_any_active_backup_task() if is_admin else None
    global_active_restore = db_handler.get_any_active_restore_task() if is_admin else None
    
    return jsonify({
        "user_id": user_id,
        "email": email,
        "enabled": bool(cfg.get('enabled', 0)),
        "interval": cfg.get('interval', 'daily'),
        "last_backup_at": int(cfg.get('last_backup_at') or 0),
        "last_status": cfg.get('last_status', 'never'),
        "last_error": cfg.get('last_error', ''),
        "last_size": int(cfg.get('last_size') or 0),
        "last_hash": cfg.get('last_hash', ''),
        "active_task": active_task,
        "active_restore_task": active_restore,
        "latest_task": latest_task,
        "global_active_task": global_active,
        "global_active_restore_task": global_active_restore,
        "is_admin": is_admin,
        "server_backup_enabled": server_settings.get('server_backup_enabled') == '1' if is_admin else False,
        "server_backup_interval": server_settings.get('server_backup_interval', 'daily') if is_admin else None,
        "last_server_backup_at": int(server_settings.get('last_server_backup_at') or 0) if is_admin else 0,
        "last_server_backup_status": server_settings.get('last_server_backup_status', 'never') if is_admin else None,
    }), 200

@dashboard_bp.route('/api/backup/user/trigger', methods=['POST'])
def api_user_backup_trigger():
    """Trigger an immediate backup for the current user."""
    from app.modules import db_handler, backup_manager
    email = g.user.get('email', '')
    user_id = g.user.get('user_id', '')
    
    cfg = db_handler.get_user_backup_config(email)
    is_admin = db_handler.is_admin(email)
    
    if not cfg.get('enabled') and not is_admin:
        return jsonify({"error": "Backups are not enabled for this account. Contact your administrator."}), 403

    active_restore = db_handler.get_active_restore_task('user', user_id) or db_handler.get_any_active_restore_task()
    if active_restore:
        return jsonify({
            "status": "restore_running",
            "error": "A restore operation is currently in progress. Backup cannot be started.",
            "task_id": active_restore['task_id']
        }), 409

    active = db_handler.get_active_backup_task('user', user_id)
    if active:
        return jsonify({
            "status": "already_running",
            "error": "A backup is already running for your account.",
            "task_id": active['task_id']
        }), 409

    try:
        task_id = backup_manager.trigger_backup_async('user', user_id)
        return jsonify({"status": "started", "task_id": task_id}), 202
    except RuntimeError as re:
        return jsonify({"status": "conflict", "error": str(re)}), 409

@dashboard_bp.route('/api/backup/user/task_status', methods=['GET'])
def api_user_backup_task_status():
    """Retrieve status for a specific user backup task ID."""
    from app.modules import db_handler
    user_id = g.user.get('user_id', '')
    task_id = request.args.get('task_id')
    if not task_id:
        task = db_handler.get_active_backup_task('user', user_id)
    else:
        task = db_handler.get_backup_task(task_id)
    return jsonify({"success": True, "task": task}), 200



