import os

# Load .env file manually (project root first, then data/.env fallback)
_root_dir = os.path.dirname(os.path.dirname(__file__))
for _env_path in [os.path.join(_root_dir, '.env'), os.path.join(_root_dir, 'data', '.env')]:
    if os.path.isfile(_env_path):
        with open(_env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, val = line.partition('=')
                    os.environ.setdefault(key.strip(), val.strip())


class Config:
    """Base configuration — all secrets come from environment variables."""
    # ─── Application Metadata & Versioning ──────────────────────────
    APP_NAME          = os.environ.get('APP_NAME', 'ZeroNode')
    APP_VERSION       = os.environ.get('APP_VERSION', '1.2.0')
    BUILD_ID          = os.environ.get('BUILD_ID', '20261114.pwa')

    SECRET_KEY        = os.environ.get('SECRET_KEY', 'change-this-in-production')
    ALLOWED_ORIGINS   = ["http://localhost:5000", "http://127.0.0.1:5000"]
    DATA_DIR          = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data'))

    # ─── SSO Configuration ──────────────────────────────────────────
    SSO_BASE_URL      = os.environ.get('SSO_BASE_URL', 'https://sso.sixthminds.com')
    SSO_CLIENT_ID     = os.environ.get('SSO_CLIENT_ID', '')
    SSO_CLIENT_SECRET = os.environ.get('SSO_CLIENT_SECRET', '')
    SSO_REDIRECT_URI  = os.environ.get('SSO_REDIRECT_URI', 'http://127.0.0.1:5000/auth/callback')
    SSO_SCOPE         = os.environ.get('SSO_SCOPE', 'basic')

    # Administrative Bootstrapping
    ADMIN_EMAIL       = os.environ.get('ADMIN_EMAIL', '')

    # ─── Offsite Backup Server Configuration ────────────────────────
    BACKUP_SERVER_URL      = os.environ.get('BACKUP_SERVER_URL', 'http://127.0.0.1:8080')
    BACKUP_SERVER_API_KEY  = os.environ.get('BACKUP_SERVER_API_KEY', 'zeronode_secret_backup_key_2026')
    BACKUP_RETENTION       = int(os.environ.get('BACKUP_RETENTION', '4'))
    SERVER_BACKUP_ENABLED  = os.environ.get('SERVER_BACKUP_ENABLED', '1')
    SERVER_BACKUP_INTERVAL = os.environ.get('SERVER_BACKUP_INTERVAL', 'daily')

    # Session cookie name
    SESSION_COOKIE_NAME = 'zeronode_session'


class DevelopmentConfig(Config):
    DEBUG   = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG   = False
    TESTING = False

config_by_name = dict(
    dev=DevelopmentConfig,
    prod=ProductionConfig,
    production=ProductionConfig
)
