import os
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from flask import current_app, g

class UserDataManager:
    def __init__(self, user_id: str):
        if not user_id:
            raise ValueError("user_id cannot be empty")
        
        self.user_id = user_id
        
        # Calculate localized paths
        _data_root = current_app.config['DATA_DIR']
        self.user_dir = os.path.join(_data_root, self.user_id)
        self.db_path = os.path.join(self.user_dir, f"{self.user_id}.db")
        
        # Ensure base structure exists
        self._ensure_structure()

    def _ensure_structure(self):
        """Creates the user directory if missing, and initializes schema."""
        if not os.path.exists(self.user_dir):
            os.makedirs(self.user_dir, exist_ok=True)
            
        with sqlite3.connect(self.db_path) as conn:
            # Enable WAL mode for performance/concurrent read access
            conn.execute('PRAGMA journal_mode=WAL')
            # Critical: Enable foreign key constraint checking per connection
            conn.execute('PRAGMA foreign_keys=ON')
            
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS files (
                    uuid TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    last_modified TIMESTAMP NOT NULL,
                    owner TEXT NOT NULL,
                    aes_key TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS folders (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    parent_id TEXT DEFAULT NULL,
                    owner TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    last_modified TIMESTAMP NOT NULL,
                    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);

                CREATE TABLE IF NOT EXISTS trash (
                    id TEXT PRIMARY KEY,
                    original_type TEXT NOT NULL,
                    original_id TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    original_parent_id TEXT,
                    metadata TEXT,
                    deleted_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    owner TEXT NOT NULL
                );
            """)

            # Lazy migration: Add missing columns to existing 'files' table
            try:
                conn.execute("ALTER TABLE files ADD COLUMN folder_id TEXT DEFAULT NULL REFERENCES folders(id) ON DELETE CASCADE")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id)")
            except sqlite3.OperationalError:
                pass  # Columns/index likely already exist
                
            try:
                conn.execute("ALTER TABLE files ADD COLUMN file_size INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass

            conn.commit()

    def _get_conn(self):
        """Provide a contextual DB connection with ENFORCED foreign keys."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ─── File Operations ──────────────────────────────────────────

    def store_file(self, file_name: str, file_data: bytes, aes_key: str, folder_id: str = None) -> str:
        """Stores encrypted payload and registers UUID metadata mapping. Returns UUID."""
        # Enforce Quota
        stats = self.get_vault_stats()
        if (stats['total_bytes'] + len(file_data)) > (10 * 1024 * 1024 * 1024):
            raise Exception("Storage limit of 10GB exceeded. Please delete files to free space.")

        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        now_ts = datetime.now(timezone.utc).isoformat()

        # Write to disk
        with open(file_path, 'wb') as f:
            f.write(file_data)
            
        # Write metadata
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO files (uuid, file_name, last_modified, owner, aes_key, folder_id, file_size) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (file_uuid, file_name, now_ts, self.user_id, aes_key, folder_id, len(file_data))
            )
            conn.commit()
            
        return file_uuid

    # ─── Chunked Upload Operations ────────────────────────────────

    def init_file_upload(self, file_name: str, aes_key: str, folder_id: str = None) -> str:
        """Phase 1 of chunked upload: register metadata and reserve a UUID on disk.
        Returns the file UUID for subsequent chunk writes."""
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        now_ts = datetime.now(timezone.utc).isoformat()

        # Touch an empty .bin file to reserve the path
        with open(file_path, 'wb') as f:
            pass  # 0-byte file, will be filled by write_file_chunk

        # Register metadata
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO files (uuid, file_name, last_modified, owner, aes_key, folder_id) VALUES (?, ?, ?, ?, ?, ?)",
                (file_uuid, file_name, now_ts, self.user_id, aes_key, folder_id)
            )
            conn.commit()

        return file_uuid

    def write_file_chunk(self, file_uuid: str, chunk_bytes: bytes, offset: int) -> bool:
        """Phase 2 of chunked upload: write bytes at a specific offset.
        Uses OS-level seek() so multiple chunks can be written in parallel safely.
        Strictly validates ownership before touching the file."""
        # 1. Ownership check
        with self._get_conn() as conn:
            row = conn.execute("SELECT uuid FROM files WHERE uuid = ? AND owner = ?",
                               (file_uuid, self.user_id)).fetchone()
        if not row:
            raise PermissionError(f"File {file_uuid} not found or access denied.")

        # 2. Seek-write to the exact offset on disk
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        with open(file_path, 'r+b') as f:
            f.seek(offset)
            f.write(chunk_bytes)
            # Force flush to disk for integrity (essential for Windows seek-writes)
            f.flush()
            os.fsync(f.fileno())

        # 3. Bump last_modified timestamp
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("UPDATE files SET last_modified = ? WHERE uuid = ?", (now_ts, file_uuid))
            conn.commit()

        print(f"DEBUG: Chunk written to {file_uuid}. New disk size: {os.path.getsize(file_path)}")
        return True

    def finalize_file(self, file_uuid: str) -> dict:
        """Phase 3 of chunked upload: mark upload complete and return final metadata.
        Validates the .bin file actually has content."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ? AND owner = ?",
                               (file_uuid, self.user_id)).fetchone()
        if not row:
            raise PermissionError(f"File {file_uuid} not found or access denied.")

        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        file_size = os.path.getsize(file_path)
        # print(f"DEBUG: Finalizing {file_uuid}. Actual disk size: {file_size}")
        if file_size == 0:
            raise RuntimeError(f"File {file_uuid} has 0 bytes — no chunks were written.")

        # Final size and timestamp commit
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("UPDATE files SET last_modified = ?, file_size = ? WHERE uuid = ?", 
                         (now_ts, file_size, file_uuid))
            conn.commit()

        return {
            "uuid": file_uuid,
            "file_name": row['file_name'],
            "size": file_size,
            "last_modified": now_ts
        }


    def get_file(self, file_uuid: str) -> dict:
        """Fetch the metadata dictionary and physical file path for chunked streaming."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ? AND owner = ?", (file_uuid, self.user_id)).fetchone()
            
        if not row:
            raise FileNotFoundError(f"File {file_uuid} not found or access denied.")
            
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        if not os.path.exists(file_path):
             raise FileNotFoundError(f"Database consistency error: physical payload missing for {file_uuid}. The entry exists but the binary is gone.")
             
        return {
            "metadata": dict(row),
            "file_path": file_path
        }
        
    def update_file_metadata(self, file_uuid: str, file_name: str = None, aes_key: str = None) -> bool:
        """Strict metadata modifier protecting specific columns, ensuring ownership."""
        update_fields = []
        params = []
        
        if file_name is not None:
            update_fields.append("file_name = ?")
            params.append(file_name)
        if aes_key is not None:
            update_fields.append("aes_key = ?")
            params.append(aes_key)
            
        if not update_fields:
            return True # Nothing to update
            
        update_fields.append("last_modified = ?")
        params.append(datetime.now(timezone.utc).isoformat())
        
        params.extend([file_uuid, self.user_id])
        
        query = f"UPDATE files SET {', '.join(update_fields)} WHERE uuid = ? AND owner = ?"
        with self._get_conn() as conn:
            cursor = conn.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

    def list_files(self, limit: int = 100, offset: int = 0) -> list:
        """Return paginated list of file metadata to prevent memory overflow."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM files WHERE owner = ? ORDER BY last_modified DESC LIMIT ? OFFSET ?", (self.user_id, limit, offset)).fetchall()
            return [dict(r) for r in rows]

    def delete_file(self, file_uuid: str) -> bool:
        """Delete payload bin and DB row."""
        # Verify ownership / existence
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ? AND owner = ?", (file_uuid, self.user_id)).fetchone()
            if not row:
                 return False
            
            # Wipe DB payload references
            conn.execute("DELETE FROM files WHERE uuid = ?", (file_uuid,))
            conn.commit()
            
        # Wipe FS
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        if os.path.exists(file_path):
            os.remove(file_path)
            
        return True

    # ─── Config Operations ──────────────────────────────────────────

    def config_set(self, key: str, value: str):
        """Create or update a config override locally for user ID target."""
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value)
            )
            conn.commit()

    def config_get(self, key: str) -> str | None:
        """Retrieve local override."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
            return row['value'] if row else None
            
    def config_delete(self, key: str) -> bool:
        """Hard delete a user configuration key."""
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM config WHERE key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0

    # ─── Drive Folder Operations ────────────────────────────────────

    def create_folder(self, name: str, parent_id: str = None) -> str:
        folder_id = str(uuid.uuid4())
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            # If parent_id is provided, verify it exists and is owned by the user
            if parent_id:
                row = conn.execute("SELECT id FROM folders WHERE id = ? AND owner = ?", (parent_id, self.user_id)).fetchone()
                if not row:
                    raise PermissionError("Parent folder not found")
            conn.execute(
                "INSERT INTO folders (id, name, parent_id, owner, created_at, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                (folder_id, name, parent_id, self.user_id, now_ts, now_ts)
            )
            conn.commit()
        return folder_id

    def list_folder(self, folder_id: str = None) -> dict:
        """Returns all folders and files inside a specific folder_id (or root if None)."""
        with self._get_conn() as conn:
            # Query folders with an item_count subquery (files + subfolders)
            folder_sql = """
                SELECT f.*, 
                    (SELECT COUNT(*) FROM files WHERE folder_id = f.id) + 
                    (SELECT COUNT(*) FROM folders WHERE parent_id = f.id) as item_count
                FROM folders f 
                WHERE f.parent_id {target_expr} AND f.owner = ? 
                ORDER BY f.name ASC
            """
            
            if folder_id is None:
                folders = conn.execute(folder_sql.format(target_expr="IS NULL"), (self.user_id,)).fetchall()
                files = conn.execute("SELECT * FROM files WHERE folder_id IS NULL AND owner = ? ORDER BY file_name ASC", (self.user_id,)).fetchall()
            else:
                folders = conn.execute(folder_sql.format(target_expr="= ?"), (folder_id, self.user_id)).fetchall()
                files = conn.execute("SELECT * FROM files WHERE folder_id = ? AND owner = ? ORDER BY file_name ASC", (folder_id, self.user_id)).fetchall()
                
            # Fetch breadcrumb path
            path = []
            curr_id = folder_id
            while curr_id:
                row = conn.execute("SELECT id, name, parent_id FROM folders WHERE id = ? AND owner = ?", (curr_id, self.user_id)).fetchone()
                if not row:
                    break
                path.insert(0, {"id": row['id'], "name": row['name']})
                curr_id = row['parent_id']

        return {
            "folders": [dict(f) for f in folders],
            "files": [dict(f) for f in files],
            "path": path
        }

    def rename_folder(self, folder_id: str, new_name: str) -> bool:
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute("UPDATE folders SET name = ?, last_modified = ? WHERE id = ? AND owner = ?", 
                                  (new_name, now_ts, folder_id, self.user_id))
            conn.commit()
            return cursor.rowcount > 0

    def move_folder(self, folder_id: str, new_parent_id: str = None) -> bool:
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            if new_parent_id:
                # Prevent moving into itself
                if folder_id == new_parent_id:
                    raise ValueError("Cannot move folder into itself")
            cursor = conn.execute("UPDATE folders SET parent_id = ?, last_modified = ? WHERE id = ? AND owner = ?", 
                                  (new_parent_id, now_ts, folder_id, self.user_id))
            conn.commit()
            return cursor.rowcount > 0

    def move_file(self, file_uuid: str, folder_id: str = None) -> bool:
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute("UPDATE files SET folder_id = ?, last_modified = ? WHERE uuid = ? AND owner = ?", 
                                  (folder_id, now_ts, file_uuid, self.user_id))
            conn.commit()
            return cursor.rowcount > 0

    def search(self, query: str, limit: int = 50) -> dict:
        """Search across folder and file names using LIKE."""
        like_q = f"%{query}%"
        with self._get_conn() as conn:
            folder_sql = """
                SELECT f.*,
                    (SELECT COUNT(*) FROM files WHERE folder_id = f.id) + 
                    (SELECT COUNT(*) FROM folders WHERE parent_id = f.id) as item_count
                FROM folders f 
                WHERE f.owner = ? AND f.name LIKE ? LIMIT ?
            """
            folders = conn.execute(folder_sql, (self.user_id, like_q, limit)).fetchall()
            files = conn.execute("SELECT uuid, file_name as name, folder_id, file_size, last_modified FROM files WHERE owner = ? AND file_name LIKE ? LIMIT ?", (self.user_id, like_q, limit)).fetchall()
            return {
                "folders": [dict(f) for f in folders],
                "files": [dict(f) for f in files]
            }

    def get_all_folders(self) -> list:
        """Returns a flat list of all folders for selection in UI pickers."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT id, name, parent_id FROM folders WHERE owner = ? ORDER BY name ASC", (self.user_id,)).fetchall()
            return [dict(r) for r in rows]

    def move_file(self, file_uuid: str, new_folder_id: str = None) -> bool:
        """Relocates a file to a new target folder."""
        with self._get_conn() as conn:
            # Verify folder exists first if not root
            if new_folder_id:
                f = conn.execute("SELECT id FROM folders WHERE id = ? AND owner = ?", (new_folder_id, self.user_id)).fetchone()
                if not f: raise ValueError("Target folder not found.")
            
            res = conn.execute("UPDATE files SET folder_id = ? WHERE uuid = ? AND owner = ?", (new_folder_id, file_uuid, self.user_id))
            conn.commit()
            return res.rowcount > 0

    def move_folder(self, folder_id: str, new_parent_id: str = None) -> bool:
        """Relocates a folder to a new parent, with strict hierarchy loop prevention."""
        if folder_id == new_parent_id:
            raise ValueError("Target destination cannot be the item itself.")
        
        with self._get_conn() as conn:
            # 1. Loop Prevention: check if new_parent_id is a descendant of folder_id
            if new_parent_id:
                descendants = conn.execute("""
                    WITH RECURSIVE tree AS (
                        SELECT id FROM folders WHERE id = ?
                        UNION ALL
                        SELECT f.id FROM folders f INNER JOIN tree t ON f.parent_id = t.id
                    ) SELECT id FROM tree
                """, (folder_id,)).fetchall()
                desc_ids = [r['id'] for r in descendants]
                if new_parent_id in desc_ids:
                    raise ValueError("Target destination is a subfolder of the current item. Recursion blocked.")

                # Verify target exists
                f = conn.execute("SELECT id FROM folders WHERE id = ? AND owner = ?", (new_parent_id, self.user_id)).fetchone()
                if not f: raise ValueError("Target folder not found.")

            res = conn.execute("UPDATE folders SET parent_id = ?, last_modified = ? WHERE id = ? AND owner = ?", 
                               (new_parent_id, datetime.now(timezone.utc).isoformat(), folder_id, self.user_id))
            conn.commit()
            return res.rowcount > 0

    # ─── Drive Trash Operations ─────────────────────────────────────
    
    def delete_item(self, item_id: str, is_folder: bool) -> bool:
        """Permanently deletes an item from the disk and database."""
        with self._get_conn() as conn:
            if is_folder:
                # 1. Fetch all descending folders using a recursive CTE to find all files inside
                folder_rows = conn.execute("""
                    WITH RECURSIVE
                        folder_tree AS (
                            SELECT id FROM folders WHERE id = ? AND owner = ?
                            UNION ALL
                            SELECT f.id FROM folders f
                            INNER JOIN folder_tree t ON f.parent_id = t.id
                        )
                    SELECT id FROM folder_tree;
                """, (item_id, self.user_id)).fetchall()
                
                if not folder_rows:
                    return False
                    
                folder_ids = [r['id'] for r in folder_rows]
                
                # 2. Fetch all files inside any of these folders to delete binaries
                placeholders = ','.join('?' for _ in folder_ids)
                file_rows = conn.execute(f"SELECT uuid FROM files WHERE folder_id IN ({placeholders}) AND owner = ?", 
                                         (*folder_ids, self.user_id)).fetchall()
                
                for f in file_rows:
                    file_path = os.path.join(self.user_dir, f"{f['uuid']}.bin")
                    if os.path.exists(file_path):
                        try: os.remove(file_path)
                        except OSError: pass

                # 3. Delete root folder (Cascade handles the rest of DB cleanup)
                conn.execute("DELETE FROM folders WHERE id = ? AND owner = ?", (item_id, self.user_id))
            else:
                # Delete single file binary and DB row
                row = conn.execute("SELECT uuid FROM files WHERE uuid = ? AND owner = ?", (item_id, self.user_id)).fetchone()
                if not row:
                    return False
                file_path = os.path.join(self.user_dir, f"{item_id}.bin")
                if os.path.exists(file_path):
                    try: os.remove(file_path)
                    except OSError: pass
                conn.execute("DELETE FROM files WHERE uuid = ? AND owner = ?", (item_id, self.user_id))
                
            conn.commit()
            
        self.invalidate_stats_cache()
        return True

    # ─── Raw Data Engine (Custom Module Tables) ─────────────────────
    
    def execute_query(self, sql: str, params: tuple = ()) -> int:
        """Executes a RAW sql query securely inside the localized user DB."""
        with self._get_conn() as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.rowcount
            
    def fetch_all(self, sql: str, params: tuple = ()) -> list:
        """Fetch multiple rows from a raw sql query natively."""
        with self._get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    # ─── Vault Stats (cached) ──────────────────────────────────────────
    _stats_cache = {}  # class-level: { user_id: (timestamp, stats_dict) }
    _STATS_TTL = 60    # seconds

    def get_vault_stats(self) -> dict:
        """Calculate total disk usage and file count for the dashboard.
        Results are cached for 60 seconds to avoid redundant filesystem scans."""
        import time as _time
        now = _time.time()

        # Check cache
        cached = UserDataManager._stats_cache.get(self.user_id)
        if cached and (now - cached[0]) < self._STATS_TTL:
            return cached[1]

        # File count from DB
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM files WHERE owner = ?", (self.user_id,)).fetchone()
            file_count = row['cnt'] if row else 0

        # Disk usage: recursively walk the ENTIRE user directory
        total_bytes = 0
        if os.path.isdir(self.user_dir):
            for dirpath, dirnames, filenames in os.walk(self.user_dir):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        total_bytes += os.path.getsize(fpath)
                    except OSError:
                        pass

        stats = {
            "file_count": file_count,
            "total_bytes": total_bytes,
        }

        # Store in cache
        UserDataManager._stats_cache[self.user_id] = (now, stats)
        return stats

    def invalidate_stats_cache(self):
        """Call after uploads/deletes to force a fresh recalculation."""
        UserDataManager._stats_cache.pop(self.user_id, None)

def get_user_manager() -> UserDataManager:
    """Helper generator. Must be called inside a valid active Request Context with existing session g_user."""
    if not hasattr(g, 'user') or not g.user:
        raise RuntimeError("Cannot initialize user data manager: Unauthenticated context.")
    
    # Retrieve pre-authenticated global token details populated previously at entry routing phase
    user_id = g.user.get('user_id')
    if not user_id:
         raise RuntimeError("Corrupt user session: Missing user_id payload.")
         
    return UserDataManager(user_id)
