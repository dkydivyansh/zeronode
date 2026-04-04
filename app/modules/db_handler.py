import sqlite3
import os
import secrets
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'server_data.db')

def _get_conn():
    """Get a new database connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize database tables. Called once on app startup."""
    conn = _get_conn()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id         TEXT PRIMARY KEY,
            email           TEXT UNIQUE NOT NULL,
            first_name      TEXT NOT NULL DEFAULT '',
            last_name       TEXT NOT NULL DEFAULT '',
            gender          TEXT DEFAULT '',
            date_of_birth   TEXT DEFAULT '',
            phone_number    TEXT DEFAULT '',
            profile_photo   TEXT DEFAULT '',
            access_token    TEXT DEFAULT '',
            scope           TEXT DEFAULT 'basic',
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            email           TEXT PRIMARY KEY,
            added_at        INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_token   TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    """)

    conn.commit()
    conn.close()


# ─── Whitelist Operations ────────────────────────────────────────────

def is_whitelisted(email: str) -> bool:
    """Check if an email is in the whitelist."""
    conn = _get_conn()
    row = conn.execute("SELECT 1 FROM whitelist WHERE email = ?", (email.lower(),)).fetchone()
    conn.close()
    return row is not None


def add_to_whitelist(email: str) -> bool:
    """Add an email to the whitelist. Returns True if added, False if already exists."""
    conn = _get_conn()
    try:
        conn.execute("INSERT INTO whitelist (email, added_at) VALUES (?, ?)",
                      (email.lower(), int(time.time())))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def remove_from_whitelist(email: str) -> bool:
    """Remove an email from the whitelist."""
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM whitelist WHERE email = ?", (email.lower(),))
    conn.commit()
    removed = cursor.rowcount > 0
    conn.close()
    return removed


def get_whitelist() -> list:
    """Get all whitelisted emails."""
    conn = _get_conn()
    rows = conn.execute("SELECT email, added_at FROM whitelist ORDER BY added_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── User Operations ────────────────────────────────────────────────

def upsert_user(user_data: dict, access_token: str, scope: str) -> dict:
    """
    Insert or update a user from SSO userinfo response.
    Returns the user record as a dict.
    """
    now = int(time.time())
    conn = _get_conn()

    # Check if user already exists
    existing = conn.execute("SELECT * FROM users WHERE user_id = ?",
                             (user_data['user_id'],)).fetchone()

    if existing:
        conn.execute("""
            UPDATE users SET
                email = ?, first_name = ?, last_name = ?, gender = ?,
                date_of_birth = ?, phone_number = ?, profile_photo = ?,
                access_token = ?, scope = ?, updated_at = ?
            WHERE user_id = ?
        """, (
            user_data.get('email', ''),
            user_data.get('first_name', ''),
            user_data.get('last_name', ''),
            user_data.get('gender', ''),
            user_data.get('date_of_birth', ''),
            user_data.get('phone_number', ''),
            user_data.get('profile_photo', ''),
            access_token, scope, now,
            user_data['user_id']
        ))
    else:
        conn.execute("""
            INSERT INTO users
                (user_id, email, first_name, last_name, gender,
                 date_of_birth, phone_number, profile_photo,
                 access_token, scope, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_data['user_id'],
            user_data.get('email', ''),
            user_data.get('first_name', ''),
            user_data.get('last_name', ''),
            user_data.get('gender', ''),
            user_data.get('date_of_birth', ''),
            user_data.get('phone_number', ''),
            user_data.get('profile_photo', ''),
            access_token, scope, now, now
        ))

    conn.commit()
    user = conn.execute("SELECT * FROM users WHERE user_id = ?",
                         (user_data['user_id'],)).fetchone()
    conn.close()
    return dict(user)


def get_user(user_id: str) -> dict | None:
    """Get a user by their ID."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    """Get a user by their email."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Session Operations ─────────────────────────────────────────────

SESSION_LIFETIME = 24 * 60 * 60  # 24 hours


def create_session(user_id: str) -> str:
    """Create a new session token for a user. Returns the token."""
    token = secrets.token_urlsafe(48)
    now = int(time.time())
    conn = _get_conn()
    conn.execute(
        "INSERT INTO sessions (session_token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, user_id, now, now + SESSION_LIFETIME)
    )
    conn.commit()
    conn.close()
    return token


def validate_session(token: str) -> dict | None:
    """
    Validate a session token. Returns the user dict if valid, None otherwise.
    Automatically purges expired sessions.
    """
    if not token:
        return None

    conn = _get_conn()
    now = int(time.time())

    # Purge expired sessions (background cleanup)
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    conn.commit()

    row = conn.execute("""
        SELECT s.user_id, s.expires_at
        FROM sessions s
        WHERE s.session_token = ? AND s.expires_at > ?
    """, (token, now)).fetchone()

    if not row:
        conn.close()
        return None

    user = conn.execute("SELECT * FROM users WHERE user_id = ?", (row['user_id'],)).fetchone()
    conn.close()
    if user:
        user_dict = dict(user)
        user_dict['session_expires_at'] = row['expires_at']
        return user_dict
    return None


def destroy_session(token: str) -> bool:
    """Destroy a specific session."""
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
    conn.commit()
    destroyed = cursor.rowcount > 0
    conn.close()
    return destroyed


def destroy_user_sessions(user_id: str) -> int:
    """Destroy all sessions for a user. Returns count of destroyed sessions."""
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    count = cursor.rowcount
    conn.close()
    return count
