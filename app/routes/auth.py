import secrets
import urllib.request
import urllib.parse
import urllib.error
import json
from functools import wraps
from flask import Blueprint, redirect, request, make_response, current_app, g, abort
from app.modules import db_handler
import socket

# Docker often fails with IPv6 resolution ("Network is unreachable"). Force IPv4 globally for this module.
_old_getaddrinfo = socket.getaddrinfo
def _getaddrinfo_ipv4(*args, **kwargs):
    res = _old_getaddrinfo(*args, **kwargs)
    # Filter out IPv6 (AF_INET6)
    return [r for r in res if r[0] == socket.AF_INET]
socket.getaddrinfo = _getaddrinfo_ipv4

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# ─── Session Middleware ──────────────────────────────────────────────

def get_current_user():
    """Read session cookie → validate → return user dict or None."""
    if hasattr(g, '_current_user'):
        return g._current_user
    cookie_name = current_app.config['SESSION_COOKIE_NAME']
    token = request.cookies.get(cookie_name)
    user = db_handler.validate_session(token) if token else None
    g._current_user = user
    return user


def login_required(f):
    """Decorator: redirect to /auth/logout?next=/login if no valid session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect('/auth/logout?next=/login&auto=1')
        g.user = user
        return f(*args, **kwargs)
    return decorated


# ─── SSO Routes ──────────────────────────────────────────────────────

@auth_bp.route('/login')
def sso_login():
    """Redirect user to Dkydivyansh SSO authorize page."""
    cfg = current_app.config
    current_app.logger.debug(f"SSO login using SSO_BASE_URL={cfg['SSO_BASE_URL']}")
    state = secrets.token_urlsafe(32)

    # Store state in a short-lived cookie for CSRF verification
    params = urllib.parse.urlencode({
        'client_id': cfg['SSO_CLIENT_ID'],
        'scope': cfg['SSO_SCOPE'],
        'state': state
    })
    authorize_url = f"{cfg['SSO_BASE_URL']}/api/authorize?{params}"

    resp = make_response(redirect(authorize_url))
    resp.set_cookie('sso_state', state, max_age=300, httponly=True, samesite='Lax')
    return resp


@auth_bp.route('/callback')
def sso_callback():
    """Handle SSO redirect: exchange code → fetch userinfo → create session."""
    cfg = current_app.config

    # ── Check for OAuth errors ───────────────────────────────────
    error = request.args.get('error')
    if error:
        desc = request.args.get('error_description', 'Authorization failed')
        return redirect(f'/login?error={error}&msg={urllib.parse.quote(desc)}')

    # ── Verify state (CSRF protection) ───────────────────────────
    code = request.args.get('code')
    state = request.args.get('state')
    saved_state = request.cookies.get('sso_state')

    if not code or not state or state != saved_state:
        return redirect('/login?error=invalid_state&msg=CSRF+verification+failed')

    # ── Exchange code for access_token ───────────────────────────
    token_data = _sso_post(f"{cfg['SSO_BASE_URL']}/api/token", {
        'client_id': cfg['SSO_CLIENT_ID'],
        'client_secret': cfg['SSO_CLIENT_SECRET'],
        'code': code
    })

    if not token_data or not token_data.get('success'):
        err = token_data.get('error_description', 'Token exchange failed') if token_data else 'SSO unreachable'
        return redirect(f'/login?error=token_error&msg={urllib.parse.quote(err)}')

    access_token = token_data['access_token']
    scope = token_data.get('scope', 'basic')

    # ── Fetch user info ──────────────────────────────────────────
    userinfo_data = _sso_post(f"{cfg['SSO_BASE_URL']}/api/userinfo", {
        'client_id': cfg['SSO_CLIENT_ID'],
        'client_secret': cfg['SSO_CLIENT_SECRET'],
        'access_token': access_token
    })

    if not userinfo_data or not userinfo_data.get('success'):
        err = userinfo_data.get('error_description', 'Failed to fetch user info') if userinfo_data else 'SSO unreachable'
        return redirect(f'/login?error=userinfo_error&msg={urllib.parse.quote(err)}')

    user_profile = userinfo_data['user']

    # ── Whitelist enforcement ────────────────────────────────────
    email = user_profile.get('email', '').lower()
    if not db_handler.is_whitelisted(email):
        return redirect('/login?error=access_denied&msg=Your+node+is+not+whitelisted')

    # ── Upsert user + create session ─────────────────────────────
    user = db_handler.upsert_user(user_profile, access_token, scope)
    session_token = db_handler.create_session(user['user_id'])

    # ── Set session cookie and redirect ──────────────────────────
    resp = make_response(redirect('/app/home'))
    resp.set_cookie(
        cfg['SESSION_COOKIE_NAME'],
        session_token,
        max_age=24 * 60 * 60,  # 24 hours
        httponly=True,
        samesite='Lax',
        secure=False  # Set True in production with HTTPS
    )
    # Clear the state cookie
    resp.delete_cookie('sso_state')
    return resp


@auth_bp.route('/logout')
def logout():
    """Destroy session and clear cookie, then redirect to wipe page."""
    cfg = current_app.config
    next_path = request.args.get('next', '/login')
    auto = request.args.get('auto', '0')
    terminal = request.args.get('terminal', '0')
    
    token = request.cookies.get(cfg['SESSION_COOKIE_NAME'])
    if token:
        db_handler.destroy_session(token)

    resp = make_response(redirect(f'/auth/exit?next={urllib.parse.quote(next_path)}&auto={auto}&terminal={terminal}'))
    resp.delete_cookie(cfg['SESSION_COOKIE_NAME'])
    return resp


@auth_bp.route('/exit')
def logout_exit():
    """Render the security wipe page."""
    from flask import render_template
    next_url = request.args.get('next', '/login')
    auto_redirect = request.args.get('auto', '0') == '1'
    is_terminal = request.args.get('terminal', '0') == '1'
    
    if is_terminal:
        return render_template('view/deprovisioned.html')
        
    return render_template('view/logout.html', next_url=next_url, auto_redirect=auto_redirect)


# ─── Helper ─────────────────────────────────────────────────────────

def _sso_post(url: str, payload: dict) -> dict | None:
    """Make a POST request to the SSO server. Returns parsed JSON or None."""
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', 'AetherisVault/1.0')
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        current_app.logger.error(f"SSO {e.code} from {url}: {body}")
        try:
            return json.loads(body)
        except Exception:
            return None
    except Exception as e:
        current_app.logger.error(f"SSO request to {url} failed: {e}")
        return None
