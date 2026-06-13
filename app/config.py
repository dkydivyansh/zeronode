import os

# Load .env file manually (no external dependency needed)
_env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', '.env')
if os.path.isfile(_env_path):
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, _, val = line.partition('=')
                os.environ.setdefault(key.strip(), val.strip())


class Config:
    """Base configuration — all secrets come from environment variables."""
    SECRET_KEY        = os.environ.get('SECRET_KEY', 'change-this-in-production')
    ALLOWED_ORIGINS   = ["http://localhost:5000", "http://127.0.0.1:5000"]
    DATA_DIR          = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data'))

    # ─── SSO Configuration ──────────────────────────────────────────
    SSO_BASE_URL      = "https://sso.dkydivyansh.com"
    SSO_CLIENT_ID     = os.environ.get('SSO_CLIENT_ID', '')
    SSO_CLIENT_SECRET = os.environ.get('SSO_CLIENT_SECRET', '')
    SSO_REDIRECT_URI  = os.environ.get('SSO_REDIRECT_URI', 'http://127.0.0.1:5000/auth/callback')
    SSO_SCOPE         = os.environ.get('SSO_SCOPE', 'basic')

    # Administrative Bootstrapping
    ADMIN_EMAIL       = os.environ.get('ADMIN_EMAIL', '')

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
