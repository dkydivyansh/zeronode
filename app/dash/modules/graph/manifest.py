from flask import render_template, g, request, jsonify, send_file
from app.dash.loader import ModuleManifest
from app.dash.modules.graph.graph_data import get_graph_manager
import time

class Manifest(ModuleManifest):
    name        = "Graph"
    description = "Zero-Knowledge Identity & Relationship Graph."
    admin_only  = False
    routes      = [
        "/", "/view", "/group",
        "/api/subject", "/api/subject/<uuid_str>", "/api/subject/<uuid_str>/revisions",
        "/api/group", "/api/group/<uuid_str>", "/api/group/<uuid_str>/revisions",
        "/api/relation",
        "/api/search/exact", "/api/search/index", "/api/search/deep_fetch",
        "/api/file/init", "/api/file/<file_uuid>/chunk", "/api/file/<file_uuid>/finalize", "/api/file/<file_uuid>", "/api/file/<file_uuid>/meta"
    ]

    def get_view(self, module_name, **kwargs):
        path = request.path.replace(f"/app/{module_name}", "")
        if path == "" or path == "/":
            return self._render_home(module_name)
        elif path == "/view":
            return render_template(f"modules/{module_name}/subject_edit.html", user=g.user)
        elif path == "/group":
            return render_template(f"modules/{module_name}/group_edit.html", user=g.user)
            
        manager = get_graph_manager()

        # ─── SUBJECTS ──────────────────────────────────────────────────
        if path == "/api/subject":
            if request.method == 'POST':
                data = request.get_json(silent=True) or {}
                try:
                    uuid_str = manager.upsert_subject(
                        data.get('uuid'), data.get('encrypted_blob', ''), data.get('encrypted_search_blob', ''),
                        data.get('email_hash'), data.get('phone_hash'), data.get('dob_hash')
                    )
                    return jsonify({"status": "ok", "uuid": uuid_str}), 201
                except Exception as e:
                    return jsonify({"error": str(e)}), 400

        elif path.startswith("/api/subject/"):
            uuid_str = kwargs.get('uuid_str')
            if path.endswith("/revisions") and request.method == 'GET':
                revs = manager.get_subject_revisions(uuid_str)
                return jsonify(revs), 200
            elif request.method == 'GET':
                sub = manager.get_subject(uuid_str)
                return jsonify(sub) if sub else (jsonify({"error": "Not found"}), 404)
            elif request.method == 'PATCH':
                data = request.get_json(silent=True) or {}
                manager.upsert_subject(
                    uuid_str, data.get('encrypted_blob', ''), data.get('encrypted_search_blob', ''),
                    data.get('email_hash'), data.get('phone_hash'), data.get('dob_hash')
                )
                return jsonify({"status": "updated"}), 200
            elif request.method == 'DELETE':
                success = manager.delete_subject(uuid_str)
                return jsonify({"status": "deleted"}) if success else (jsonify({"error": "Not found"}), 404)

        # ─── GROUPS ────────────────────────────────────────────────────
        elif path == "/api/group":
            if request.method == 'POST':
                data = request.get_json(silent=True) or {}
                uuid_str = manager.upsert_group(data.get('uuid'), data.get('encrypted_blob', ''), data.get('encrypted_search_blob', ''))
                return jsonify({"status": "ok", "uuid": uuid_str}), 201
                
        elif path.startswith("/api/group/"):
            uuid_str = kwargs.get('uuid_str')
            if path.endswith("/revisions") and request.method == 'GET':
                revs = manager.get_group_revisions(uuid_str)
                return jsonify(revs), 200
            elif request.method == 'GET':
                grp = manager.get_group(uuid_str)
                return jsonify(grp) if grp else (jsonify({"error": "Not found"}), 404)
            elif request.method == 'PATCH':
                data = request.get_json(silent=True) or {}
                manager.upsert_group(uuid_str, data.get('encrypted_blob', ''), data.get('encrypted_search_blob', ''))
                return jsonify({"status": "updated"}), 200
            elif request.method == 'DELETE':
                success = manager.delete_group(uuid_str)
                return jsonify({"status": "deleted"}) if success else (jsonify({"error": "Not found"}), 404)

        # ─── RELATIONS ─────────────────────────────────────────────────
        elif path == "/api/relation":
            if request.method == 'POST':
                data = request.get_json(silent=True) or {}
                manager.upsert_relation(
                    data.get('source_uuid'), 
                    data.get('target_uuid'), 
                    data.get('encrypted_blob', ''),
                    data.get('source_type', 'subject'),
                    data.get('target_type', 'subject')
                )
                return jsonify({"status": "ok"}), 201
            elif request.method == 'DELETE':
                data = request.get_json(silent=True) or {}
                manager.delete_relation(data.get('source_uuid'), data.get('target_uuid'))
                return jsonify({"status": "deleted"}), 200

        # ─── SEARCH INDICES ────────────────────────────────────────────
        elif path == "/api/search/index" and request.method == 'GET':
            indices = manager.get_search_indices()
            return jsonify(indices), 200
            
        elif path == "/api/search/exact" and request.method == 'POST':
            data = request.get_json(silent=True) or {}
            uuids = manager.exact_search(data.get('email_hash'), data.get('phone_hash'), data.get('dob_hash'))
            return jsonify({"uuids": uuids}), 200

        elif path == "/api/search/deep_fetch" and request.method == 'POST':
            data = request.get_json(silent=True) or {}
            entity_type = data.get('entity_type', 'subject')
            limit = int(data.get('limit', 5000))
            offset = int(data.get('offset', 0))

            with manager._get_conn() as conn:
                if entity_type == 'group':
                    rows = conn.execute("SELECT uuid, encrypted_blob FROM groups LIMIT ? OFFSET ?", (limit, offset)).fetchall()
                else:
                    rows = conn.execute("SELECT uuid, encrypted_blob FROM subjects LIMIT ? OFFSET ?", (limit, offset)).fetchall()
            
            payloads = [{"uuid": r['uuid'], "blob": r['encrypted_blob']} for r in rows if r['encrypted_blob']]
            return jsonify({"payloads": payloads, "has_more": len(payloads) == limit}), 200

        # ─── FILES ─────────────────────────────────────────────────────
        elif path == "/api/file/init" and request.method == 'POST':
            data = request.get_json(silent=True) or {}
            if not data.get('file_name') or not data.get('aes_key') or not data.get('subject_uuid'):
                return jsonify({"error": "Missing fields"}), 400
            entity_type = data.get('entity_type', 'subject')
            file_uuid = manager.init_file_upload(data['subject_uuid'], data['file_name'], data['aes_key'], entity_type)
            return jsonify({"uuid": file_uuid}), 201
            
        elif path.startswith("/api/file/") and "/chunk" in path and request.method == 'POST':
            file_uuid = kwargs.get('file_uuid')
            offset_str = request.headers.get('X-Chunk-Offset')
            if offset_str is None: return jsonify({"error": "Missing offset header"}), 400
            manager.write_file_chunk(file_uuid, request.data, int(offset_str))
            return jsonify({"status": "ok"}), 200
            
        elif path.startswith("/api/file/") and "/finalize" in path and request.method == 'POST':
            file_uuid = kwargs.get('file_uuid')
            return jsonify(manager.finalize_file(file_uuid)), 200
            
        elif path.startswith("/api/file/") and "/meta" in path and request.method == 'GET':
            file_uuid = kwargs.get('file_uuid')
            file_meta = manager.get_file_meta(file_uuid)
            if not file_meta:
                return jsonify({"error": "File not found"}), 404
            return jsonify(file_meta)
            
        elif path.startswith("/api/file/") and not "/chunk" in path and not "/finalize" in path:
            file_uuid = kwargs.get('file_uuid')
            if request.method == 'GET':
                file_package = manager.get_file(file_uuid)
                resp = send_file(file_package['file_path'], as_attachment=False, mimetype='application/octet-stream')
                resp.headers['X-AES-Key'] = file_package['metadata']['aes_key']
                resp.headers['X-File-Name'] = file_package['metadata']['file_name']
                return resp
            elif request.method == 'DELETE':
                manager.delete_file(file_uuid)
                return jsonify({"status": "deleted"}), 200

        return jsonify({"error": "Endpoint not implemented"}), 404

    def _render_home(self, module_name):
        return render_template(f"modules/{module_name}/index.html", user=g.user)
