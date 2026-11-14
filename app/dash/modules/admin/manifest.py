from flask import render_template, g, current_app, request, jsonify, Response
from app.dash.loader import ModuleManifest
from app.modules.user_data import get_user_manager
from app.modules import db_handler, backup_manager
import time

class Manifest(ModuleManifest):
    name        = "Admin"
    description = "System administration and user management."
    admin_only  = True
    routes      = [
        "/", "/api/stats", "/api/promote", "/api/demote", 
        "/api/whitelist/add", "/api/whitelist/remove", 
        "/api/user/wipe", "/api/server/wipe",
        "/api/backup/status", "/api/backup/settings",
        "/api/backup/user/config", "/api/backup/trigger",
        "/api/backup/test_connection", "/api/backup/remote/list",
        "/api/backup/remote/delete", "/api/backup/remote/delete_bulk", 
        "/api/backup/remote/download", "/api/backup/remote/restore",
        "/api/backup/restore_task_status"
    ]

    def get_view(self, module_name, **kwargs):
        # Dispatch based on sub-path
        path = request.path.replace(f"/app/{module_name}", "")
        
        # 1. Dashboard UI (Home)
        if path == "/" or path == "":
            return self._render_home(module_name)
            
        # 2. Administrative API Cluster
        if path == "/api/stats":
            search = request.args.get('search')
            return jsonify({
                "storage_report": db_handler.get_filtered_storage_report(limit=50, search=search),
                "server_drive": db_handler.get_server_drive_info(),
                "whitelist": db_handler.get_whitelist(),
                "admins": db_handler.get_admins()
            })

        if path == "/api/user/wipe":
            data = request.json
            if not data or 'user_id' not in data:
                return jsonify({"error": "User ID required"}), 400
            
            # Delete user and associated data
            success = db_handler.wipe_user(data['user_id'], g.user['email'])
            
            return jsonify({
                "status": "USER_DELETED" if success else "ACTION_FAILED",
                "identity": data['user_id']
            }), 200 if success else 403

        if path == "/api/whitelist/add":
            data = request.json
            if not data or 'email' not in data:
                return jsonify({"error": "Email required"}), 400
            success = db_handler.add_to_whitelist(data['email'])
            return jsonify({"status": "ok" if success else "exists"}), 200

        if path == "/api/whitelist/remove":
            data = request.json
            if not data or 'email' not in data:
                return jsonify({"error": "Email required"}), 400
            # Prevent self-removal
            if data['email'].lower() == g.user['email'].lower():
                return jsonify({"error": "Cannot remove yourself from whitelist."}), 400
            success = db_handler.remove_from_whitelist(data['email'])
            return jsonify({"status": "ok" if success else "not_found"}), 200

        if path == "/api/promote":
            data = request.json
            if not data or 'email' not in data:
                return jsonify({"error": "Email required"}), 400
            # Promotion requires: email of target + email of requester (current admin)
            success = db_handler.add_admin(data['email'], g.user['email'])
            return jsonify({"status": "ok" if success else "failed"}), 200

        if path == "/api/demote":
            data = request.json
            if not data or 'email' not in data:
                return jsonify({"error": "Email required"}), 400
            # Prevent self-demotion
            if data['email'].lower() == g.user['email'].lower():
                return jsonify({"error": "Cannot demote yourself."}), 400
            success = db_handler.remove_admin(data['email'], g.user['email'])
            return jsonify({"status": "ok" if success else "failed"}), 200

        if path == "/api/server/wipe":
            data = request.json
            expected = "ERASE ALL SERVER DATA"
            if not data or data.get('confirmation') != expected:
                return jsonify({"error": "Confirmation text does not match. System reset aborted."}), 400
            
            # Reset the entire server installation
            success = db_handler.nuclear_wipe_server()
            return jsonify({"status": "SYSTEM_RESET" if success else "RESET_FAILED"}), 200 if success else 500

        # ─── BACKUP MANAGEMENT API CLUSTER ─────────────────────────────
        if path == "/api/backup/status":
            return jsonify({
                "settings": db_handler.get_backup_settings(),
                "user_configs": db_handler.get_all_user_backup_configs(),
                "recent_tasks": db_handler.get_recent_backup_tasks(limit=15),
                "active_backup": db_handler.get_any_active_backup_task(),
                "active_restore": db_handler.get_any_active_restore_task()
            })

        if path == "/api/backup/settings":
            data = request.json or {}
            allowed_keys = ['backup_server_url', 'backup_server_api_key', 'server_backup_enabled', 'server_backup_interval', 'backup_retention']
            updates = {k: str(data[k]) for k in allowed_keys if k in data}
            if updates:
                db_handler.update_backup_settings(updates)
            return jsonify({"status": "updated", "settings": db_handler.get_backup_settings()})

        if path == "/api/backup/user/config":
            data = request.json or {}
            email = data.get('email', '').strip()
            if not email:
                return jsonify({"error": "User email required"}), 400
            enabled = 1 if data.get('enabled') else 0
            interval = data.get('interval', 'daily')
            if interval not in ['daily', 'weekly']:
                interval = 'daily'
            db_handler.set_user_backup_config(email, enabled=enabled, interval=interval)
            return jsonify({"status": "updated", "config": db_handler.get_user_backup_config(email)})

        if path == "/api/backup/trigger":
            data = request.json or {}
            target_type = data.get('target_type', 'server')
            target_id = data.get('target_id', 'server')
            
            # Check if active task already running
            active = db_handler.get_active_backup_task(target_type, target_id)
            if active:
                return jsonify({"status": "already_running", "task_id": active['task_id']}), 200
                
            task_id = backup_manager.trigger_backup_async(target_type, target_id)
            return jsonify({"status": "started", "task_id": task_id}), 202

        if path == "/api/backup/test_connection":
            try:
                res = backup_manager.test_remote_connection()
                return jsonify({"status": "connected", "response": res}), 200
            except Exception as e:
                return jsonify({"status": "connection_failed", "error": str(e)}), 400

        if path == "/api/backup/remote/list":
            target_id = request.args.get('target_id')
            try:
                backups = backup_manager.fetch_remote_backups(target_id)
                return jsonify({"backups": backups}), 200
            except Exception as e:
                return jsonify({"error": str(e), "backups": []}), 400

        if path in ("/api/backup/remote/delete", "/api/backup/remote/delete_bulk"):
            data = request.json or {}
            backup_ids = data.get('backup_ids')
            backup_id = data.get('backup_id')

            if backup_ids and isinstance(backup_ids, list):
                try:
                    res = backup_manager.delete_remote_backups_bulk(backup_ids)
                    return jsonify(res), 200
                except Exception as e:
                    return jsonify({"error": str(e)}), 400
            elif backup_id:
                try:
                    success = backup_manager.delete_remote_backup(backup_id)
                    return jsonify({"status": "deleted" if success else "failed", "backup_id": backup_id}), 200
                except Exception as e:
                    return jsonify({"error": str(e)}), 400
            else:
                return jsonify({"error": "backup_id or backup_ids required"}), 400

        if path == "/api/backup/remote/download":
            backup_id = request.args.get('backup_id')
            if not backup_id:
                return jsonify({"error": "backup_id query parameter required"}), 400
            try:
                remote_resp = backup_manager.stream_remote_backup(backup_id)
                filename = "backup_archive.zip.bin"
                cd = remote_resp.headers.get('Content-Disposition')
                if cd and 'filename=' in cd:
                    filename = cd.split('filename=')[1].strip('"\'')
                
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

        if path == "/api/backup/remote/restore":
            data = request.json or {}
            confirmation = data.get('confirmation', '').strip()
            if confirmation != "RESTORE DATA":
                return jsonify({"error": "Confirmation phrase did not match. Please type 'RESTORE DATA' to authorize."}), 400

            backup_id = data.get('backup_id')
            if not backup_id:
                return jsonify({"error": "backup_id parameter required"}), 400

            target_type = data.get('target_type') or 'server'
            target_id = data.get('target_id')
            if not target_id:
                target_id = 'server' if target_type == 'server' else None
            try:
                task_id = backup_manager.trigger_restore_async(target_type, target_id or 'server', backup_id=backup_id)
                return jsonify({"status": "started", "task_id": task_id}), 202
            except Exception as e:
                return jsonify({"error": str(e)}), 400

        if path == "/api/backup/restore_task_status":
            task_id = request.args.get('task_id')
            if not task_id:
                active = db_handler.get_any_active_restore_task()
                return jsonify({"task": active}), 200
            task = db_handler.get_restore_task(task_id)
            return jsonify({"task": task}), 200

        return jsonify({"error": "Endpoint not found"}), 404

    def _render_home(self, module_name):
        manager = get_user_manager()
        
        # Formal telemetry summary for server-side render
        stats = {
            "security_state": "NOMINAL",
            "server_drive": db_handler.get_server_drive_info(),
            "last_sweep": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return render_template(f"modules/{module_name}/index.html", 
                               user=g.user, 
                               stats=stats,
                               now_ts=int(time.time()))
