import sqlite3
import os
import secrets
import time
import shutil

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'server_data.db')

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

        CREATE TABLE IF NOT EXISTS admins (
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

    # --- ADMINISTRATIVE BOOTSTRAP ---
    admin_email = os.environ.get('ADMIN_EMAIL')
    if admin_email:
        # Root Whitelisting & Promotion Protocol
        conn.execute("INSERT OR IGNORE INTO whitelist (email, added_at) VALUES (?, ?)", 
                     (admin_email.lower(), int(time.time())))
        conn.execute("INSERT OR IGNORE INTO admins (email, added_at) VALUES (?, ?)", 
                     (admin_email.lower(), int(time.time())))
        conn.commit()

    conn.close()


# ─── Administrative Operations ────────────────────────────────────────────

def is_admin(email: str) -> bool:
    """Check if an email is in the admin ledger."""
    if not email: return False
    conn = _get_conn()
    row = conn.execute("SELECT 1 FROM admins WHERE email = ?", (email.lower(),)).fetchone()
    conn.close()
    return row is not None

def add_admin(email: str, requester_email: str) -> bool:
    """
    Elevate a whitelisted user to Admin status.
    REQUIRES: requester_email MUST ALREADY BE AN ADMIN.
    """
    # 1. Requester Audit Gate: Only admins can promote others
    if not is_admin(requester_email):
        return False
        
    # 2. Security Gate: Target must be whitelisted first
    if not is_whitelisted(email):
        return False
        
    conn = _get_conn()
    try:
        conn.execute("INSERT INTO admins (email, added_at) VALUES (?, ?)",
                      (email.lower(), int(time.time())))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def remove_admin(email: str, requester_email: str) -> bool:
    """
    Revoke Admin status from a user.
    REQUIRES: requester_email MUST ALREADY BE AN ADMIN.
    """
    if not is_admin(requester_email):
        return False
        
    conn = _get_conn()
    # 1. Purge administrative privileges
    cursor = conn.execute("DELETE FROM admins WHERE email = ?", (email.lower(),))
    
    # 2. Authoritatively terminate all active sessions for this user ID
    conn.execute("DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM users WHERE email = ?)", (email.lower(),))
    
    conn.commit()
    removed = cursor.rowcount > 0
    conn.close()
    return removed

def get_admins() -> list:
    """Get all registered administrators."""
    conn = _get_conn()
    rows = conn.execute("SELECT email, added_at FROM admins ORDER BY added_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

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
    # 1. Purge whitelist access
    cursor = conn.execute("DELETE FROM whitelist WHERE email = ?", (email.lower(),))
    
    # 2. Authoritatively terminate all active sessions for this user ID
    conn.execute("DELETE FROM sessions WHERE user_id IN (SELECT user_id FROM users WHERE email = ?)", (email.lower(),))
    
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
        
        # Privilege Injection: Check if user is an admin
        user_dict['is_admin'] = is_admin(user_dict['email'])
        if user_dict['is_admin']:
            user_dict['scope'] = 'ADMIN'
            
        return user_dict
    return None


def destroy_session(token: str) -> bool:
    """Destroy a specific session."""
    conn = None
    try:
        conn = _get_conn()
        cursor = conn.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.OperationalError:
        # DB or table already purged (Expected during liquidation)
        return False
    finally:
        if conn: conn.close()


def destroy_user_sessions(user_id: str) -> int:
    """Destroy all sessions for a user. Returns count of destroyed sessions."""
    conn = _get_conn()
    cursor = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    count = cursor.rowcount
    conn.close()
    return count

def get_server_drive_info() -> dict:
    """Get OS-level disk stats for the vault DATA_DIR."""
    # current_app might not be available if called outside request, 
    # but we know DATA_DIR is relative to this file
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data')
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
        
    usage = shutil.disk_usage(data_dir)
    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "percent": round((usage.used / usage.total) * 100, 2)
    }

def get_user_storage_report() -> list:
    """
    Detailed storage consumption report per user.
    Scans the data/ directory and joins with user emails.
    """
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data')
    if not os.path.exists(data_dir):
        return []

    report = []
    conn = _get_conn()
    
    # 1. Get all users to map directory names to emails
    users = {u['user_id']: dict(u) for u in conn.execute("SELECT user_id, email, first_name, last_name FROM users").fetchall()}
    conn.close()

    # 2. Scan directories
    for entry in os.scandir(data_dir):
        if entry.is_dir():
            user_id = entry.name
            user_info = users.get(user_id, {"email": "Unknown / Orphaned", "first_name": "N/A", "last_name": ""})
            
            # Calculate total size of user directory
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(entry.path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    try:
                        total_size += os.path.getsize(fp)
                    except OSError:
                        pass
            
            report.append({
                "user_id": user_id,
                "email": user_info['email'],
                "name": f"{user_info['first_name']} {user_info['last_name']}".strip(),
                "size_bytes": total_size
            })

    # Sort by size descending
    return sorted(report, key=lambda x: x['size_bytes'], reverse=True)

def _atomic_erasure_internal(user_id: str, email: str) -> bool:
    """
    INTERNAL_ERASURE_ENGINE: Performs the absolute physical and database purge of an identity.
    Uses robust retry logic and authoritative error handlers for Windows file-lock recovery.
    """
    conn = _get_conn()
    try:
        # 1. Atomic Database Purge
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM admins WHERE email = ?", (email,))
        conn.execute("DELETE FROM whitelist WHERE email = ?", (email,))
        conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
    except Exception as e:
        print(f"CRITICAL: Identity de-provisioning DB failure for {user_id}: {e}")
    finally:
        conn.close()

    # 2. Physical Volume Erasure (Robust Walker)
    data_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', user_id))
    
    def force_remove_readonly(func, path, excinfo):
        """Authoritative error handler to break file locks/readonly attributes."""
        import stat
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except:
            pass

    if os.path.exists(data_dir):
        import shutil
        import time
        # Try up to 5 times to bypass transient locks (common on Windows with SQLite WAL)
        for attempt in range(5):
            try:
                shutil.rmtree(data_dir, onerror=force_remove_readonly)
                if not os.path.exists(data_dir):
                    return True # ERASURE_SUCCESSFUL
            except Exception as e:
                if attempt == 4:
                    print(f"CRITICAL: Physical volume erasure final failure for {user_id}: {e}")
            time.sleep(0.5) # Wait for transient locks/GC to release
            
    return not os.path.exists(data_dir) # True if gone, False if still exists


def wipe_self(user_id: str) -> bool:
    """
    SELF_IDENTITY_ERASURE: Authoritatively de-provisions the current identity and purges its data.
    """
    conn = _get_conn()
    user = conn.execute("SELECT email FROM users WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    
    if not user:
        return False # IDENTITY_RESOLUTION_FAILURE
        
    return _atomic_erasure_internal(user_id, user['email'].lower())

def wipe_user(user_id: str, requester_email: str) -> bool:
    """
    ADMIN_ERASURE_PROTOCOL: Physically de-provisions an identity and purges its data volume.
    """
    conn = _get_conn()
    try:
        # 1. Self-Erasure Prevention Gate (for ADMIN only)
        requester = conn.execute("SELECT user_id FROM users WHERE email = ?", (requester_email.lower(),)).fetchone()
        if requester and requester['user_id'] == user_id:
            return False # AUTHORIZATION_DENIED: Admin cannot wipe themselves via this protocol.

        # 2. Identify Target Identity
        target = conn.execute("SELECT email FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not target:
            return False # IDENTITY_RESOLUTION_FAILURE: Remote identity not found.

        target_email = target['email'].lower()
        conn.close() # Close to allow internal atomic erasure

        # 3. Perform Absolute Purge
        return _atomic_erasure_internal(user_id, target_email)
    except Exception as e:
        print(f"CRITICAL: De-provisioning failure gate for {user_id}: {e}")
        return False
    finally:
        # Check if already closed
        try: conn.close()
        except: pass

def nuclear_wipe_server() -> bool:
    """
    NUCLEAR_SYSTEM_LIQUIDATION: Physically de-provisions the entire server infrastructure.
    Purges .env, master database, and the entire data/ root.
    Harnessed with robust Windows file-lock retry logic.
    """
    root_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
    env_path = os.path.normpath(os.path.join(root_dir, '.env'))
    data_dir = os.path.normpath(os.path.join(root_dir, 'data'))
    db_path = os.path.normpath(DB_PATH)
    
    def force_remove_readonly(func, path, excinfo):
        """Authoritative error handler to break file locks/readonly attributes."""
        import stat
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except:
            pass

    try:
        # 1. Purge Configuration (Authoritative)
        if os.path.exists(env_path):
            try: os.remove(env_path)
            except Exception as e: print(f"DEBUG: ENV purge failure: {e}")
            
        # 2. Purge User Data Volumes (Robust Walker)
        if os.path.exists(data_dir):
            for _ in range(3): # Authoritative Retry Loop
                try:
                    shutil.rmtree(data_dir, onerror=force_remove_readonly)
                    if not os.path.exists(data_dir): break
                except:
                    time.sleep(0.5) # Wait for transient locks to release
            
        # 3. Purge Master Database (Force)
        if os.path.exists(db_path):
            try: os.remove(db_path)
            except: pass
            
        # 4. Authoritative Shutdown Sequence
        # We exit the process to prevent any further DB operations or ghost-requests.
        # Process termination will release any final locks on remaining files.
        print("SYSTEM_LIQUIDATION_PROTOCOL_COMMITTED // SHUTTING DOWN")
        import threading
        def delayed_shutdown():
            time.sleep(1.5) # Grant enough time for the final API response to reach the client
            os._exit(0)
            
        threading.Thread(target=delayed_shutdown, daemon=True).start()
            
        return True
    except Exception as e:
        print(f"CRITICAL: System liquidation failure node: {e}")
        # Even if data_dir fails, we've likely purged .env/db, marking the system as de-provisioned.
        return True 

def get_filtered_storage_report(limit: int = 10, search: str = None) -> list:
    """
    FORENSIC_USER_AUDIT: Retrieves storage telemetry for specific identities with filtering and limits.
    """
    conn = _get_conn()
    query = "SELECT user_id, email, first_name, last_name, profile_photo FROM users"
    params = []
    if search:
        query += " WHERE user_id LIKE ? OR email LIKE ? OR (first_name || ' ' || last_name) LIKE ?"
        s = f"%{search}%"
        params.extend([s, s, s])
    
    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    report = []
    data_dir_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data')

    for row in rows:
        user_id = row['user_id']
        total_size = 0
        user_path = os.path.join(data_dir_root, user_id)
        if os.path.exists(user_path):
            for dirpath, dirnames, filenames in os.walk(user_path):
                for f in filenames:
                    try: total_size += os.path.getsize(os.path.join(dirpath, f))
                    except: pass
        
        report.append({
            "user_id": user_id,
            "email": row['email'],
            "name": f"{row['first_name']} {row['last_name']}".strip() or "Identity Unresolved",
            "profile_photo": row['profile_photo'],
            "size_bytes": total_size
        })
    return report
