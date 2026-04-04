from flask import render_template, g, current_app, request, jsonify
from app.dash.loader import ModuleManifest
from app.modules.user_data import get_user_manager
from app.modules import db_handler
import time

class Manifest(ModuleManifest):
    name        = "Admin"
    description = "System administration and global telemetry."
    admin_only  = True
    routes      = ["/", "/api/stats", "/api/promote", "/api/demote", "/api/whitelist/add", "/api/whitelist/remove", "/api/user/wipe"]

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
                return jsonify({"error": "IDENTITY_ID_REQUIRED"}), 400
            
            # AUTHORIZATION_GATE: Physically de-provision the identity
            success = db_handler.wipe_user(data['user_id'], g.user['email'])
            
            return jsonify({
                "status": "ERASURE_COMMITTED" if success else "AUTHORIZATION_FAILURE",
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

        return jsonify({"error": "Interface node not found"}), 404

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
