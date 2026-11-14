import os
import time
import tempfile
from flask import render_template, g, request, jsonify, Response
from app.dash.loader import ModuleManifest
from app.modules import db_handler, backup_manager
from app.modules.user_data import get_user_manager

class Manifest(ModuleManifest):
    name        = "Backup"
    description = "Automated offsite backup and restore management."
    admin_only  = False
    routes      = [
        "/",
        "/api/user/status",
        "/api/user/trigger",
        "/api/user/download",
        "/api/user/restore",
        "/api/user/restore_upload",
    ]

    def get_view(self, module_name: str, **kwargs):
        path = request.path.replace(f"/app/{module_name}", "")
        email = g.user.get('email', '')
        user_id = g.user.get('user_id', '')

        # User Backup Status
        if path == "/api/user/status":
            cfg = db_handler.get_user_backup_config(email)
            active_task = db_handler.get_active_backup_task('user', user_id)
            latest_task = db_handler.get_latest_backup_task('user', user_id)
            if not latest_task:
                latest_task = db_handler.get_latest_backup_task('user', email)
            is_admin = db_handler.is_admin(email)
            server_settings = db_handler.get_backup_settings() if is_admin else {}
            global_active = db_handler.get_any_active_backup_task() if is_admin else None

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
                "latest_task": latest_task,
                "global_active_task": global_active,
                "is_admin": is_admin,
                "server_backup_enabled": server_settings.get('server_backup_enabled') == '1' if is_admin else False,
                "server_backup_interval": server_settings.get('server_backup_interval', 'daily') if is_admin else None,
                "last_server_backup_at": int(server_settings.get('last_server_backup_at') or 0) if is_admin else 0,
                "last_server_backup_status": server_settings.get('last_server_backup_status', 'never') if is_admin else None,
            }), 200

        # User Trigger Backup
        if path == "/api/user/trigger":
            cfg = db_handler.get_user_backup_config(email)
            is_admin = db_handler.is_admin(email)
            if not cfg.get('enabled') and not is_admin:
                return jsonify({"error": "Backups are not enabled for this account. Contact your administrator."}), 403
            active = db_handler.get_active_backup_task('user', user_id)
            if active:
                return jsonify({"status": "already_running", "task_id": active['task_id']}), 200
            task_id = backup_manager.trigger_backup_async('user', user_id)
            return jsonify({"status": "started", "task_id": task_id}), 202

        # User Download Latest Backup
        if path == "/api/user/download":
            try:
                user_backups = backup_manager.fetch_remote_backups(target_id=user_id)
                if not user_backups:
                    return jsonify({"error": "No remote backup archive found for your account."}), 404
                latest_backup = user_backups[0]
                remote_resp = backup_manager.stream_remote_backup(latest_backup['id'])
                filename = latest_backup.get('filename') or f"{user_id}_backup.zip.bin"
                
                def generate():
                    try:
                        while True:
                            chunk = remote_resp.read(65536)
                            if not chunk:
                                break
                            yield chunk
                    finally:
                        remote_resp.close()

                headers = {
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": "application/octet-stream",
                }
                if 'Content-Length' in remote_resp.headers:
                    headers["Content-Length"] = remote_resp.headers['Content-Length']
                if 'X-Backup-Hash' in remote_resp.headers:
                    headers["X-Backup-Hash"] = remote_resp.headers['X-Backup-Hash']

                return Response(generate(), headers=headers)
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        # User Restore Drive from Remote Backup
        if path == "/api/user/restore":
            data = request.get_json(silent=True) or {}
            confirmation = data.get('confirmation', '').strip()
            if confirmation != "RESTORE DATA":
                return jsonify({"error": "Confirmation phrase did not match. Please type 'RESTORE DATA' to authorize."}), 400

            backup_id = data.get('backup_id')
            try:
                if not backup_id:
                    user_backups = backup_manager.fetch_remote_backups(target_id=user_id)
                    if not user_backups:
                        return jsonify({"error": "No remote backup archive found for your account."}), 404
                    backup_id = user_backups[0]['id']

                res = backup_manager.restore_from_backup_id(backup_id, expected_target_type='user', expected_target_id=user_id)
                return jsonify({"status": "restored", "result": res}), 200
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        # User Restore Drive from Uploaded Backup File (.zip.bin)
        if path == "/api/user/restore_upload":
            file = request.files.get('archive_file')
            confirmation = request.form.get('confirmation', '').strip()
            if confirmation != "RESTORE DATA":
                return jsonify({"error": "Confirmation phrase did not match. Please type 'RESTORE DATA' to authorize."}), 400
            if not file or not file.filename:
                return jsonify({"error": "No backup archive file selected."}), 400
            
            temp_fd, temp_path = tempfile.mkstemp(prefix="znode_upload_restore_", suffix=".zip.bin")
            os.close(temp_fd)
            try:
                file.save(temp_path)
                res = backup_manager.restore_archive(temp_path, expected_target_type='user', expected_target_id=user_id)
                return jsonify({"status": "restored", "result": res}), 200
            except Exception as e:
                return jsonify({"error": str(e)}), 400
            finally:
                if os.path.exists(temp_path):
                    try: os.remove(temp_path)
                    except OSError: pass

        # Render Main Backup View
        is_admin = db_handler.is_admin(email)
        user_cfg = db_handler.get_user_backup_config(email)

        return render_template(
            f"modules/{module_name}/index.html",
            user=g.user,
            module_name=module_name,
            is_admin=is_admin,
            user_cfg=user_cfg,
            now_ts=int(time.time()),
        )

