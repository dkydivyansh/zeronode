from flask import Flask, request
from flask_cors import CORS

def create_app(config_name='dev'):
    """App Factory — strict initialization order."""
    app = Flask(__name__)

    from app.config import config_by_name
    app.config.from_object(config_by_name[config_name])

    CORS(app, resources={r"/*": {"origins": app.config['ALLOWED_ORIGINS']}})

    from flask_sock import Sock
    import json
    from app.modules import backup_events
    from app.modules import db_handler

    # Initialize WebSockets
    sock = Sock(app)

    @app.errorhandler(RuntimeError)
    def handle_socket_runtime_error(e):
        if 'Cannot obtain socket from WSGI environment' in str(e):
            return {"error": "WebSockets not supported by current WSGI server. Polling fallback active.", "websocket": False}, 501
        raise e

    @sock.route('/ws/backup')
    def backup_socket(ws):
        try:
            cookie_name = app.config.get('SESSION_COOKIE_NAME', 'zeronode_session')
            token = request.cookies.get(cookie_name) or request.args.get('token')
            user = db_handler.validate_session(token) if token else None

            if not user:
                try:
                    ws.send(json.dumps({"type": "auth_error", "error": "Unauthorized session"}))
                    ws.close()
                except Exception:
                    pass
                return

            user_id = user['user_id']
            email = user.get('email', '')
            is_admin = db_handler.is_admin(email)

            backup_events.broadcaster.register(ws, user_id, is_admin)
            try:
                active_backup = db_handler.get_active_backup_task('user', user_id)
                active_restore = db_handler.get_active_restore_task('user', user_id)
                global_backup = db_handler.get_any_active_backup_task() if is_admin else None
                global_restore = db_handler.get_any_active_restore_task() if is_admin else None
                recent = backup_events.broadcaster.get_recent_events(user_id, is_admin, limit=5)

                ws.send(json.dumps({
                    "type": "connected",
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "active_backup": active_backup,
                    "active_restore": active_restore,
                    "global_backup": global_backup,
                    "global_restore": global_restore,
                    "recent_events": recent
                }))

                while True:
                    msg = ws.receive()
                    if msg is None:
                        break
                    if msg == "ping":
                        ws.send(json.dumps({"type": "pong"}))
            finally:
                backup_events.broadcaster.deregister(ws)
        except Exception as e:
            try:
                ws.close()
            except Exception:
                pass

    from app.modules.db_handler import init_db
    init_db()

    from app.modules.backup_manager import start_backup_scheduler
    start_backup_scheduler()

    # 1. Import blueprint
    from app.dash import dashboard_bp
    from app.dash.loader import load_modules

    # 2. Load modules onto blueprint BEFORE registration
    report = load_modules(dashboard_bp)

    # 3. Now register all blueprints
    from app.routes.client import client_bp
    from app.routes.auth import auth_bp
    app.register_blueprint(client_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    # Log loaded modules
    for mod in report:
        app.logger.info(f"[LOADER] ✓ {mod['module']} → {mod['routes']}")

    @app.after_request
    def set_secure_headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://sso.sixthminds.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https://sso.sixthminds.com; "
            "font-src 'self'; "
            "media-src 'self' blob:; "
            "connect-src 'self' ws: wss: https://sso.sixthminds.com blob:; "
            "worker-src 'self' blob:; "
            "frame-src 'self' data: blob: https://sso.sixthminds.com; "
            "object-src 'self' blob:;"
        )
        # 2. Strict Cross-Origin Isolation (Stops IDM and 3rd party interference)
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        # We allow cross-origin embedder policy to be none to allow SSO photos
        response.headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
        # 3. Privacy & Feature Lock
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), usb=(), payment=()'
        
        # 4. Strict No-Cache Policy
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response

    return app
