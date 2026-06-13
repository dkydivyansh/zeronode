from flask import Flask
from flask_cors import CORS

def create_app(config_name='dev'):
    """App Factory — strict initialization order."""
    app = Flask(__name__)

    from app.config import config_by_name
    app.config.from_object(config_by_name[config_name])

    CORS(app, resources={r"/*": {"origins": app.config['ALLOWED_ORIGINS']}})

    from app.modules.db_handler import init_db
    init_db()

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
            "script-src 'self' 'unsafe-inline' https://sso.dkydivyansh.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https://sso.dkydivyansh.com; "
            "font-src 'self'; "
            "media-src 'self' blob:; "
            "connect-src 'self' https://sso.dkydivyansh.com blob:; "
            "worker-src 'self' blob:; "
            "frame-src 'self' data: blob: https://sso.dkydivyansh.com; "
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
