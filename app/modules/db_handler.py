import sqlite3
import os
import secrets
import time
import shutil

DATA_DIR = os.environ.get('DATA_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data'))
DB_PATH = os.path.join(DATA_DIR, 'server_data.db')

def _get_conn():
    """Get a new database connection with row_factory for dict-like access."""
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
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

        -- Backup System Tables
        CREATE TABLE IF NOT EXISTS backup_settings (
            key             TEXT PRIMARY KEY,
            value           TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_backup_configs (
            email           TEXT PRIMARY KEY,
            enabled         INTEGER NOT NULL DEFAULT 0,
            interval        TEXT NOT NULL DEFAULT 'daily',
            last_backup_at  INTEGER DEFAULT 0,
            last_status     TEXT DEFAULT 'never',
            last_error      TEXT DEFAULT '',
            last_size       INTEGER DEFAULT 0,
            last_hash       TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS backup_tasks (
            task_id         TEXT PRIMARY KEY,
            target_type     TEXT NOT NULL,
            target_id       TEXT NOT NULL,
            status          TEXT NOT NULL,
            progress        INTEGER DEFAULT 0,
            current_step    TEXT DEFAULT '',
            started_at      INTEGER NOT NULL,
            updated_at      INTEGER DEFAULT 0,
            completed_at    INTEGER DEFAULT 0,
            error_message   TEXT DEFAULT '',
            backup_filename TEXT DEFAULT '',
            backup_hash     TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_backup_tasks_target ON backup_tasks(target_id, started_at DESC);

        CREATE TABLE IF NOT EXISTS restore_tasks (
            task_id         TEXT PRIMARY KEY,
            target_type     TEXT NOT NULL,
            target_id       TEXT NOT NULL,
            backup_id       TEXT DEFAULT '',
            status          TEXT NOT NULL,
            progress        INTEGER DEFAULT 0,
            current_step    TEXT DEFAULT '',
            started_at      INTEGER NOT NULL,
            updated_at      INTEGER DEFAULT 0,
            completed_at    INTEGER DEFAULT 0,
            error_message   TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_restore_tasks_target ON restore_tasks(target_id, started_at DESC);
    """)

    # Migration: Ensure updated_at column exists in existing tables
    b_cols = [c[1] for c in conn.execute("PRAGMA table_info(backup_tasks)").fetchall()]
    if 'updated_at' not in b_cols:
        conn.execute("ALTER TABLE backup_tasks ADD COLUMN updated_at INTEGER DEFAULT 0")

    r_cols = [c[1] for c in conn.execute("PRAGMA table_info(restore_tasks)").fetchall()]
    if 'updated_at' not in r_cols:
        conn.execute("ALTER TABLE restore_tasks ADD COLUMN updated_at INTEGER DEFAULT 0")

    conn.commit()

    # --- BACKUP SYSTEM BOOTSTRAP ---
    default_backup_settings = {
        'backup_server_url': os.environ.get('BACKUP_SERVER_URL', 'http://127.0.0.1:8080'),
        'backup_server_api_key': os.environ.get('BACKUP_SERVER_API_KEY', 'zeronode_secret_backup_key_2026'),
        'server_backup_enabled': '1',
        'server_backup_interval': 'daily',
        'backup_retention': '4',
        'last_server_backup_at': '0',
        'last_server_backup_status': 'never',
        'last_server_backup_error': '',
        'last_server_backup_size': '0',
        'last_server_backup_hash': ''
    }
    for k, v in default_backup_settings.items():
        conn.execute("INSERT OR IGNORE INTO backup_settings (key, value) VALUES (?, ?)", (k, str(v)))

    # --- ADMINISTRATIVE BOOTSTRAP ---
    admin_email = os.environ.get('ADMIN_EMAIL')
    if admin_email:
        # Root Whitelisting & Promotion Protocol
        conn.execute("INSERT OR IGNORE INTO whitelist (email, added_at) VALUES (?, ?)", 
                     (admin_email.lower(), int(time.time())))
        conn.execute("INSERT OR IGNORE INTO admins (email, added_at) VALUES (?, ?)", 
                     (admin_email.lower(), int(time.time())))
        # Admin backup is enabled by default with daily interval
        conn.execute("""
            INSERT OR IGNORE INTO user_backup_configs (email, enabled, interval)
            VALUES (?, 1, 'daily')
        """, (admin_email.lower(),))
        conn.commit()

    # Clean up any interrupted running tasks upon boot
    now = int(time.time())
    conn.execute("""
        UPDATE backup_tasks
        SET status = 'failed',
            error_message = 'Task interrupted by server restart',
            completed_at = ?
        WHERE status = 'running'
    """, (now,))
    conn.execute("""
        UPDATE restore_tasks
        SET status = 'failed',
            error_message = 'Restore task interrupted by server restart',
            completed_at = ?
        WHERE status = 'running'
    """, (now,))
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
        # Admin backup is enabled by default with daily interval
        conn.execute("""
            INSERT INTO user_backup_configs (email, enabled, interval)
            VALUES (?, 1, 'daily')
            ON CONFLICT(email) DO UPDATE SET enabled = 1
        """, (email.lower(),))
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
    data_dir = DATA_DIR
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
    data_dir = DATA_DIR
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
        conn.execute("DELETE FROM user_backup_configs WHERE email = ?", (email,))
        conn.execute("DELETE FROM backup_tasks WHERE (target_type = 'user' AND target_id = ?) OR target_id = ?", (user_id, email))
        conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        conn.commit()
    except Exception as e:
        print(f"CRITICAL: Identity de-provisioning DB failure for {user_id}: {e}")
    finally:
        conn.close()

    # 1b. Remote Backup Purge: Delete all remote backups for this user
    try:
        from app.modules import backup_manager
        backup_manager.delete_remote_backups_for_target(user_id)
        if email and email.lower() != user_id.lower():
            backup_manager.delete_remote_backups_for_target(email)
    except Exception as e:
        print(f"WARN: Remote backup purge failed during erasure of {user_id}: {e}")

    # 2. Physical Volume Erasure (Robust Walker)
    data_dir = os.path.normpath(os.path.join(DATA_DIR, user_id))
    
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
    data_dir = os.path.normpath(DATA_DIR)
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
        # 0. Remote Backup Server Purge: Delete all remote backups on server wipe
        try:
            from app.modules import backup_manager
            backup_manager.delete_all_remote_backups()
        except Exception as e:
            print(f"WARN: Remote backup server wipe failed: {e}")

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
    data_dir_root = DATA_DIR

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


# ─── Automated Backup & Disaster Recovery Database Cluster ────────────

def get_backup_settings() -> dict:
    """Retrieve all global backup settings as key-value dictionary."""
    conn = _get_conn()
    rows = conn.execute("SELECT key, value FROM backup_settings").fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}

def update_backup_settings(settings: dict) -> bool:
    """Upsert one or more global backup settings."""
    conn = _get_conn()
    for k, v in settings.items():
        conn.execute("""
            INSERT INTO backup_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?
        """, (k, str(v), str(v)))
    conn.commit()
    conn.close()
    return True

def get_user_backup_config(email: str) -> dict:
    """Retrieve backup policy configuration for a specific user email."""
    if not email:
        return {"email": "", "enabled": 0, "interval": "daily", "last_backup_at": 0, "last_status": "never", "last_error": "", "last_size": 0, "last_hash": ""}
    conn = _get_conn()
    row = conn.execute("SELECT * FROM user_backup_configs WHERE email = ?", (email.lower().strip(),)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        "email": email,
        "enabled": 0,
        "interval": "daily",
        "last_backup_at": 0,
        "last_status": "never",
        "last_error": "",
        "last_size": 0,
        "last_hash": ""
    }

def set_user_backup_config(email: str, enabled: int = 1, interval: str = 'daily') -> bool:
    """Configure or update backup policy for a user."""
    conn = _get_conn()
    conn.execute("""
        INSERT INTO user_backup_configs (email, enabled, interval)
        VALUES (?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET enabled = ?, interval = ?
    """, (email.lower().strip(), enabled, interval, enabled, interval))
    conn.commit()
    conn.close()
    return True

def get_all_user_backup_configs() -> list:
    """Retrieve backup status for all registered users, joined with user profile info."""
    conn = _get_conn()
    sql = """
        SELECT 
            u.user_id, u.email, u.first_name, u.last_name, u.profile_photo,
            COALESCE(b.enabled, 0) as enabled,
            COALESCE(b.interval, 'daily') as interval,
            COALESCE(b.last_backup_at, 0) as last_backup_at,
            COALESCE(b.last_status, 'never') as last_status,
            COALESCE(b.last_error, '') as last_error,
            COALESCE(b.last_size, 0) as last_size,
            COALESCE(b.last_hash, '') as last_hash,
            CASE WHEN a.email IS NOT NULL THEN 1 ELSE 0 END as is_admin
        FROM users u
        LEFT JOIN user_backup_configs b ON LOWER(u.email) = LOWER(b.email)
        LEFT JOIN admins a ON LOWER(u.email) = LOWER(a.email)
        ORDER BY u.created_at ASC
    """
    rows = conn.execute(sql).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def create_backup_task(task_id: str, target_type: str, target_id: str) -> bool:
    """Create a new backup task record."""
    conn = _get_conn()
    now = int(time.time())
    conn.execute("""
        INSERT OR REPLACE INTO backup_tasks (task_id, target_type, target_id, status, progress, current_step, started_at, updated_at)
        VALUES (?, ?, ?, 'running', 0, 'Initiating backup...', ?, ?)
    """, (task_id, target_type, target_id, now, now))
    conn.commit()
    conn.close()
    return True

def update_backup_task(task_id: str, **kwargs) -> bool:
    """Update progress, status, or details of an active backup task."""
    conn = _get_conn()
    allowed = ['status', 'progress', 'current_step', 'completed_at', 'error_message', 'backup_filename', 'backup_hash', 'updated_at']
    updates = []
    params = []
    for k, v in kwargs.items():
        if k in allowed:
            updates.append(f"{k} = ?")
            params.append(v)
            
    now = int(time.time())
    if 'updated_at' not in kwargs:
        updates.append("updated_at = ?")
        params.append(now)

    if kwargs.get('status') in ['success', 'failed'] and 'completed_at' not in kwargs:
        updates.append("completed_at = ?")
        params.append(now)
        
    if not updates:
        conn.close()
        return True
        
    params.append(task_id)
    query = f"UPDATE backup_tasks SET {', '.join(updates)} WHERE task_id = ?"
    conn.execute(query, params)
    conn.commit()
    conn.close()
    return True

def record_backup_result(target_type: str, target_id: str, success: bool, size: int = 0, file_hash: str = '', error: str = '') -> bool:
    """Record the final outcome of a backup run onto user or server settings."""
    now = int(time.time())
    status_str = 'success' if success else 'failed'
    conn = _get_conn()
    
    if target_type == 'server':
        settings_to_update = {
            'last_server_backup_at': str(now),
            'last_server_backup_status': status_str,
            'last_server_backup_error': error or '',
            'last_server_backup_size': str(size),
            'last_server_backup_hash': file_hash or ''
        }
        for k, v in settings_to_update.items():
            conn.execute("""
                INSERT INTO backup_settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = ?
            """, (k, v, v))
            
    elif target_type == 'user':
        email = None
        if '@' in target_id:
            email = target_id.lower().strip()
        else:
            u = conn.execute("SELECT email FROM users WHERE user_id = ?", (target_id,)).fetchone()
            if u:
                email = u['email'].lower()
                
        if email:
            conn.execute("""
                INSERT INTO user_backup_configs (email, last_backup_at, last_status, last_error, last_size, last_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    last_backup_at = ?,
                    last_status = ?,
                    last_error = ?,
                    last_size = ?,
                    last_hash = ?
            """, (email, now, status_str, error, size, file_hash, now, status_str, error, size, file_hash))
            
    conn.commit()
    conn.close()
    return True

def cleanup_stale_backup_tasks(timeout_seconds: int = 900) -> int:
    """
    STALE TASK HEALING: Automatically marks tasks in 'running' state as failed
    if their last heartbeat (updated_at) has had no activity for the timeout threshold (default: 15 minutes).
    Prevents active multi-gigabyte uploads (e.g. 34 GB) from being prematurely terminated.
    """
    now = int(time.time())
    stale_threshold = now - timeout_seconds
    conn = _get_conn()
    cursor = conn.execute("""
        UPDATE backup_tasks
        SET status = 'failed',
            error_message = 'Task timed out due to inactivity.',
            completed_at = ?
        WHERE status = 'running' 
          AND (CASE WHEN updated_at > 0 THEN updated_at ELSE started_at END) < ?
    """, (now, stale_threshold))
    conn.commit()
    count = cursor.rowcount
    conn.close()
    return count

def get_backup_task(task_id: str) -> dict | None:
    """Retrieve details for a specific backup task ID."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM backup_tasks WHERE task_id = ?", (task_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_latest_backup_task(target_type: str, target_id: str) -> dict | None:
    """Retrieve the most recent task for a given target."""
    cleanup_stale_backup_tasks()
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM backup_tasks
        WHERE target_type = ? AND target_id = ?
        ORDER BY started_at DESC LIMIT 1
    """, (target_type, target_id)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_active_backup_task(target_type: str, target_id: str) -> dict | None:
    """Retrieve currently running task if any."""
    cleanup_stale_backup_tasks()
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM backup_tasks
        WHERE target_type = ? AND target_id = ? AND status = 'running'
        ORDER BY started_at DESC LIMIT 1
    """, (target_type, target_id)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_any_active_backup_task() -> dict | None:
    """Retrieve any currently running backup task across the system."""
    cleanup_stale_backup_tasks()
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM backup_tasks
        WHERE status = 'running'
        ORDER BY started_at DESC LIMIT 1
    """, ()).fetchone()
    conn.close()
    return dict(row) if row else None

def get_recent_backup_tasks(limit: int = 20) -> list:
    """Retrieve the latest backup tasks across all targets."""
    cleanup_stale_backup_tasks()
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM backup_tasks ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ─── Restore Task Management ──────────────────────────────────────────

def create_restore_task(task_id: str, target_type: str, target_id: str, backup_id: str = '') -> bool:
    """Create a new restore task record."""
    conn = _get_conn()
    now = int(time.time())
    conn.execute("""
        INSERT OR REPLACE INTO restore_tasks (task_id, target_type, target_id, backup_id, status, progress, current_step, started_at, updated_at)
        VALUES (?, ?, ?, ?, 'running', 0, 'Initiating restore...', ?, ?)
    """, (task_id, target_type, target_id, backup_id, now, now))
    conn.commit()
    conn.close()
    return True

def update_restore_task(task_id: str, **kwargs) -> bool:
    """Update progress, status, or details of an active restore task."""
    conn = _get_conn()
    allowed = ['status', 'progress', 'current_step', 'completed_at', 'error_message', 'updated_at']
    updates = []
    params = []
    for k, v in kwargs.items():
        if k in allowed:
            updates.append(f"{k} = ?")
            params.append(v)

    now = int(time.time())
    if 'updated_at' not in kwargs:
        updates.append("updated_at = ?")
        params.append(now)

    if kwargs.get('status') in ['success', 'failed'] and 'completed_at' not in kwargs:
        updates.append("completed_at = ?")
        params.append(now)
        
    if not updates:
        conn.close()
        return True
        
    params.append(task_id)
    query = f"UPDATE restore_tasks SET {', '.join(updates)} WHERE task_id = ?"
    conn.execute(query, params)
    conn.commit()
    conn.close()
    return True

def cleanup_stale_restore_tasks(timeout_seconds: int = 900) -> int:
    """Marks any restore tasks in 'running' state without recent progress as failed."""
    now = int(time.time())
    stale_threshold = now - timeout_seconds
    conn = _get_conn()
    cursor = conn.execute("""
        UPDATE restore_tasks
        SET status = 'failed',
            error_message = 'Restore task timed out due to inactivity.',
            completed_at = ?
        WHERE status = 'running' 
          AND (CASE WHEN updated_at > 0 THEN updated_at ELSE started_at END) < ?
    """, (now, stale_threshold))
    conn.commit()
    count = cursor.rowcount
    conn.close()
    return count

def get_restore_task(task_id: str) -> dict | None:
    """Retrieve details for a specific restore task ID."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM restore_tasks WHERE task_id = ?", (task_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_active_restore_task(target_type: str, target_id: str) -> dict | None:
    """Retrieve currently running restore task if any."""
    cleanup_stale_restore_tasks()
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM restore_tasks
        WHERE target_type = ? AND target_id = ? AND status = 'running'
        ORDER BY started_at DESC LIMIT 1
    """, (target_type, target_id)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_any_active_restore_task() -> dict | None:
    """Retrieve any currently running restore task across the system."""
    cleanup_stale_restore_tasks()
    conn = _get_conn()
    row = conn.execute("""
        SELECT * FROM restore_tasks
        WHERE status = 'running'
        ORDER BY started_at DESC LIMIT 1
    """, ()).fetchone()
    conn.close()
    return dict(row) if row else None

