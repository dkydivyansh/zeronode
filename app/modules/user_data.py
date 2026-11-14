import os
import sqlite3
import uuid
import time
from datetime import datetime, timezone, timedelta
from flask import current_app, g
from contextlib import contextmanager

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
            
        with self._get_conn() as conn:
            # Enable WAL mode for performance/concurrent read access (persistent setting)
            conn.execute('PRAGMA journal_mode=WAL')
            self._initialize_schema(conn)


    def _initialize_schema(self, conn):
        """Internal runner for the schema bootstrap."""
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


    @contextmanager
    def _get_conn(self):
        """Provide a contextual DB connection that ENFORCES closure and foreign keys."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
            # with statement on connection handles commit/rollback for the yield block
        finally:
            conn.close()

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
        """Phase 1 of chunked upload: register metadata and reserve a UUID on disk."""
        
        # 0. Automatic cleanup of stalled/failed uploads (timeout = 300s)
        self._cleanup_stale_uploads()

        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        now_ts = datetime.now(timezone.utc).isoformat()

        # Touch an empty .bin file to reserve the path
        with open(file_path, 'wb') as f:
            pass  # 0-byte file, will be filled by write_file_chunk

        # Register metadata with file_size = -1 (indicates INCOMPLETE/UPLOADING)
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO files (uuid, file_name, last_modified, owner, aes_key, folder_id, file_size) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (file_uuid, file_name, now_ts, self.user_id, aes_key, folder_id, -1)
            )
            conn.commit()

        return file_uuid

    def _cleanup_stale_uploads(self):
        """INTERNAL: Purge files stuck in 'uploading' state (-1 size) for > 5 mins."""
        threshold = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        
        with self._get_conn() as conn:
            # 1. Discover targets
            stale_files = conn.execute(
                "SELECT uuid FROM files WHERE owner = ? AND file_size = -1 AND last_modified <= ?",
                (self.user_id, threshold)
            ).fetchall()
            
            if not stale_files:
                return

            for row in stale_files:
                f_uuid = row['uuid']
                f_path = os.path.join(self.user_dir, f"{f_uuid}.bin")
                
                # Check OS level mtime to ensure we don't delete an actively uploading file
                if os.path.exists(f_path):
                    if time.time() - os.path.getmtime(f_path) < 300:
                        continue  # File was written to recently, skip cleanup
                    try: os.remove(f_path)
                    except OSError: pass
                
                # 3. Metadata Delete
                conn.execute("DELETE FROM files WHERE uuid = ?", (f_uuid,))
            
            conn.commit()

    def write_file_chunk(self, file_uuid: str, chunk_bytes: bytes, offset: int) -> bool:
        """Phase 2 of chunked upload: write bytes at a specific offset."""
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

        return True

    def finalize_file(self, file_uuid: str) -> dict:
        """Phase 3 of chunked upload: mark upload complete and return final metadata."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ? AND owner = ?",
                               (file_uuid, self.user_id)).fetchone()
        if not row:
            raise PermissionError(f"File {file_uuid} not found or access denied.")

        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        file_size = os.path.getsize(file_path)
        
        # Exception: Allow 0-byte files for Markdown notes as requested
        is_md = row['file_name'].lower().endswith('.md')
        if file_size == 0 and not is_md:
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

    def update_file_content(self, file_uuid: str, file_data: bytes, aes_key: str = None) -> dict:
        """Atomically overwrite file content and update metadata."""
        stats = self.get_vault_stats()
        if (stats['total_bytes'] + len(file_data)) > (10 * 1024 * 1024 * 1024):
            raise Exception("Storage limit of 10GB exceeded. Please delete files to free space.")

        with self._get_conn() as conn:
            row = conn.execute("SELECT uuid FROM files WHERE uuid = ? AND owner = ?",
                               (file_uuid, self.user_id)).fetchone()
        if not row:
            raise PermissionError(f"File {file_uuid} not found or access denied.")

        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        with open(file_path, 'wb') as f:
            f.write(file_data)
            f.flush()
            os.fsync(f.fileno())

        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            if aes_key:
                conn.execute(
                    "UPDATE files SET last_modified = ?, file_size = ?, aes_key = ? WHERE uuid = ?",
                    (now_ts, len(file_data), aes_key, file_uuid)
                )
            else:
                conn.execute(
                    "UPDATE files SET last_modified = ?, file_size = ? WHERE uuid = ?",
                    (now_ts, len(file_data), file_uuid)
                )
            conn.commit()

        self.invalidate_stats_cache()
        return {
            "uuid": file_uuid,
            "size": len(file_data),
            "last_modified": now_ts
        }

    def get_file(self, file_uuid: str) -> dict:
        """Fetch the metadata dictionary and physical file path."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ? AND owner = ?", (file_uuid, self.user_id)).fetchone()
            
        if not row:
            raise FileNotFoundError(f"File {file_uuid} not found or access denied.")
            
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        if not os.path.exists(file_path):
             raise FileNotFoundError(f"Database consistency error: physical payload missing for {file_uuid}.")
             
        return {
            "metadata": dict(row),
            "file_path": file_path
        }
        
    def update_file_metadata(self, file_uuid: str, file_name: str = None, aes_key: str = None) -> bool:
        """Strict metadata modifier."""
        update_fields = []
        params = []
        
        if file_name is not None:
            update_fields.append("file_name = ?")
            params.append(file_name)
        if aes_key is not None:
            update_fields.append("aes_key = ?")
            params.append(aes_key)
            
        if not update_fields:
            return True
            
        update_fields.append("last_modified = ?")
        params.append(datetime.now(timezone.utc).isoformat())
        params.extend([file_uuid, self.user_id])
        
        query = f"UPDATE files SET {', '.join(update_fields)} WHERE uuid = ? AND owner = ?"
        with self._get_conn() as conn:
            cursor = conn.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

    def list_files(self, limit: int = 100, offset: int = 0) -> list:
        """Return paginated list of file metadata. Excludes incomplete uploads."""
        self._cleanup_stale_uploads()
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM files WHERE owner = ? AND file_size >= 0 ORDER BY last_modified DESC LIMIT ? OFFSET ?", (self.user_id, limit, offset)).fetchall()
            return [dict(r) for r in rows]

    def delete_file(self, file_uuid: str) -> bool:
        """Delete payload bin and DB row."""
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ? AND owner = ?", (file_uuid, self.user_id)).fetchone()
            if not row: return False
            conn.execute("DELETE FROM files WHERE uuid = ?", (file_uuid,))
            conn.commit()
            
        file_path = os.path.join(self.user_dir, f"{file_uuid}.bin")
        if os.path.exists(file_path): os.remove(file_path)
        return True

    # ─── Config Operations ──────────────────────────────────────────

    def config_set(self, key: str, value: str):
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value)
            )
            conn.commit()

    def config_get(self, key: str) -> str | None:
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
            return row['value'] if row else None
            
    def config_delete(self, key: str) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM config WHERE key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0

    # ─── Drive Folder Operations ────────────────────────────────────

    def create_folder(self, name: str, parent_id: str = None) -> str:
        folder_id = str(uuid.uuid4())
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            if parent_id:
                row = conn.execute("SELECT id FROM folders WHERE id = ? AND owner = ?", (parent_id, self.user_id)).fetchone()
                if not row: raise PermissionError("Parent folder not found")
            conn.execute(
                "INSERT INTO folders (id, name, parent_id, owner, created_at, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                (folder_id, name, parent_id, self.user_id, now_ts, now_ts)
            )
            conn.commit()
        return folder_id

    def list_folder(self, folder_id: str = None) -> dict:
        """Returns all folders and files inside a specific folder_id."""
        self._cleanup_stale_uploads()
        with self._get_conn() as conn:
            folder_sql = """
                SELECT f.*, 
                    (SELECT COUNT(*) FROM files WHERE folder_id = f.id AND file_size >= 0) + 
                    (SELECT COUNT(*) FROM folders WHERE parent_id = f.id) as item_count
                FROM folders f 
                WHERE f.parent_id {target_expr} AND f.owner = ? 
                ORDER BY f.name ASC
            """
            
            if folder_id is None:
                folders = conn.execute(folder_sql.format(target_expr="IS NULL"), (self.user_id,)).fetchall()
                files = conn.execute("SELECT * FROM files WHERE folder_id IS NULL AND owner = ? AND file_size >= 0 ORDER BY file_name ASC", (self.user_id,)).fetchall()
            else:
                folders = conn.execute(folder_sql.format(target_expr="= ?"), (folder_id, self.user_id)).fetchall()
                files = conn.execute("SELECT * FROM files WHERE folder_id = ? AND owner = ? AND file_size >= 0 ORDER BY file_name ASC", (folder_id, self.user_id)).fetchall()
                
            path = []
            curr_id = folder_id
            while curr_id:
                row = conn.execute("SELECT id, name, parent_id FROM folders WHERE id = ? AND owner = ?", (curr_id, self.user_id)).fetchone()
                if not row: break
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

    def search(self, query: str, limit: int = 50) -> dict:
        """Search across folder and file names. Filters incomplete uploads."""
        like_q = f"%{query}%"
        self._cleanup_stale_uploads()
        with self._get_conn() as conn:
            folder_sql = """
                SELECT f.*,
                    (SELECT COUNT(*) FROM files WHERE folder_id = f.id AND file_size >= 0) + 
                    (SELECT COUNT(*) FROM folders WHERE parent_id = f.id) as item_count
                FROM folders f 
                WHERE f.owner = ? AND f.name LIKE ? LIMIT ?
            """
            folders = conn.execute(folder_sql, (self.user_id, like_q, limit)).fetchall()
            files = conn.execute("SELECT uuid, file_name as name, folder_id, file_size, last_modified FROM files WHERE owner = ? AND file_size >= 0 AND file_name LIKE ? LIMIT ?", (self.user_id, like_q, limit)).fetchall()
            return {
                "folders": [dict(f) for f in folders],
                "files": [dict(f) for f in files]
            }

    def get_all_folders(self) -> list:
        """Returns a flat list of all folders for Selection UI."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT id, name, parent_id FROM folders WHERE owner = ? ORDER BY name ASC", (self.user_id,)).fetchall()
            return [dict(r) for r in rows]

    def move_file(self, file_uuid: str, new_folder_id: str = None) -> bool:
        """Relocates a file to a new target folder."""
        with self._get_conn() as conn:
            if new_folder_id:
                f = conn.execute("SELECT id FROM folders WHERE id = ? AND owner = ?", (new_folder_id, self.user_id)).fetchone()
                if not f: raise ValueError("Target folder not found.")
            res = conn.execute("UPDATE files SET folder_id = ?, last_modified = ? WHERE uuid = ? AND owner = ?", 
                               (new_folder_id, datetime.now(timezone.utc).isoformat(), file_uuid, self.user_id))
            conn.commit()
            return res.rowcount > 0

    def move_folder(self, folder_id: str, new_parent_id: str = None) -> bool:
        """Relocates a folder with loop prevention."""
        if folder_id == new_parent_id: raise ValueError("Target destination cannot be the folder itself.")
        with self._get_conn() as conn:
            if new_parent_id:
                descendants = conn.execute("""
                    WITH RECURSIVE tree AS (
                        SELECT id FROM folders WHERE id = ?
                        UNION ALL
                        SELECT f.id FROM folders f INNER JOIN tree t ON f.parent_id = t.id
                    ) SELECT id FROM tree
                """, (folder_id,)).fetchall()
                if new_parent_id in [r['id'] for r in descendants]:
                    raise ValueError("Recursive movement blocked.")
                f = conn.execute("SELECT id FROM folders WHERE id = ? AND owner = ?", (new_parent_id, self.user_id)).fetchone()
                if not f: raise ValueError("Target folder not found.")
            res = conn.execute("UPDATE folders SET parent_id = ?, last_modified = ? WHERE id = ? AND owner = ?", 
                               (new_parent_id, datetime.now(timezone.utc).isoformat(), folder_id, self.user_id))
            conn.commit()
            return res.rowcount > 0

    def delete_item(self, item_id: str, is_folder: bool) -> bool:
        """Permanently deletes an item from disk and DB (recursively for folders)."""
        if is_folder:
            res = self.bulk_delete(file_ids=[], folder_ids=[item_id])
            return res.get("deleted_folders", 0) > 0
        else:
            res = self.bulk_delete(file_ids=[item_id], folder_ids=[])
            return res.get("deleted_files", 0) > 0

    def bulk_delete(self, file_ids: list, folder_ids: list) -> dict:
        """Permanently deletes multiple files and folders recursively."""
        clean_file_ids = list(set(str(f).strip() for f in file_ids if f and str(f).strip()))
        clean_folder_ids = list(set(str(f).strip() for f in folder_ids if f and str(f).strip()))

        all_file_uuids = set()
        all_folder_ids = set()

        with self._get_conn() as conn:
            # 1. Resolve all folders recursively
            if clean_folder_ids:
                p = ','.join('?' for _ in clean_folder_ids)
                folder_rows = conn.execute(f"""
                    WITH RECURSIVE
                        folder_tree AS (
                            SELECT id FROM folders WHERE id IN ({p}) AND owner = ?
                            UNION ALL
                            SELECT f.id FROM folders f
                            INNER JOIN folder_tree t ON f.parent_id = t.id
                        )
                    SELECT id FROM folder_tree;
                """, (*clean_folder_ids, self.user_id)).fetchall()

                all_folder_ids = {r['id'] for r in folder_rows}

                # Find all files inside any of these folders
                if all_folder_ids:
                    f_list = list(all_folder_ids)
                    chunk_size = 500
                    for i in range(0, len(f_list), chunk_size):
                        chunk = f_list[i:i + chunk_size]
                        fp = ','.join('?' for _ in chunk)
                        f_rows = conn.execute(
                            f"SELECT uuid FROM files WHERE folder_id IN ({fp}) AND owner = ?",
                            (*chunk, self.user_id)
                        ).fetchall()
                        for r in f_rows:
                            all_file_uuids.add(r['uuid'])

            # 2. Resolve explicit file_ids belonging to this user
            if clean_file_ids:
                chunk_size = 500
                for i in range(0, len(clean_file_ids), chunk_size):
                    chunk = clean_file_ids[i:i + chunk_size]
                    p = ','.join('?' for _ in chunk)
                    f_rows = conn.execute(
                        f"SELECT uuid FROM files WHERE uuid IN ({p}) AND owner = ?",
                        (*chunk, self.user_id)
                    ).fetchall()
                    for r in f_rows:
                        all_file_uuids.add(r['uuid'])

            # 3. Physically delete all resolved .bin chunk files
            for f_uuid in all_file_uuids:
                f_path = os.path.join(self.user_dir, f"{f_uuid}.bin")
                if os.path.exists(f_path):
                    try:
                        os.remove(f_path)
                    except OSError:
                        pass

            # 4. Remove rows from files table
            if all_file_uuids:
                uuid_list = list(all_file_uuids)
                chunk_size = 500
                for i in range(0, len(uuid_list), chunk_size):
                    chunk = uuid_list[i:i + chunk_size]
                    p = ','.join('?' for _ in chunk)
                    conn.execute(
                        f"DELETE FROM files WHERE uuid IN ({p}) AND owner = ?",
                        (*chunk, self.user_id)
                    )

            # 5. Remove rows from folders table
            if all_folder_ids:
                f_list = list(all_folder_ids)
                chunk_size = 500
                for i in range(0, len(f_list), chunk_size):
                    chunk = f_list[i:i + chunk_size]
                    p = ','.join('?' for _ in chunk)
                    conn.execute(
                        f"DELETE FROM folders WHERE id IN ({p}) AND owner = ?",
                        (*chunk, self.user_id)
                    )

            conn.commit()

        self.invalidate_stats_cache()
        return {
            "status": "deleted",
            "deleted_files": len(all_file_uuids),
            "deleted_folders": len(all_folder_ids)
        }

    def bulk_move(self, file_ids: list, folder_ids: list, target_folder_id: str = None) -> dict:
        """Relocates multiple files and folders to a target folder (or root if None)."""
        clean_file_ids = list(set(str(f).strip() for f in file_ids if f and str(f).strip()))
        clean_folder_ids = list(set(str(f).strip() for f in folder_ids if f and str(f).strip()))

        if target_folder_id:
            target_folder_id = str(target_folder_id).strip()
            if not target_folder_id or target_folder_id.lower() in ("null", "none", "root"):
                target_folder_id = None

        with self._get_conn() as conn:
            if target_folder_id:
                # Target must exist and belong to user
                target = conn.execute(
                    "SELECT id FROM folders WHERE id = ? AND owner = ?",
                    (target_folder_id, self.user_id)
                ).fetchone()
                if not target:
                    raise ValueError("Target folder not found.")

                # Cannot move folder into itself
                if target_folder_id in clean_folder_ids:
                    raise ValueError("Cannot move a folder into itself.")

                # Cannot move folder into one of its descendants
                if clean_folder_ids:
                    p = ','.join('?' for _ in clean_folder_ids)
                    descendants = conn.execute(f"""
                        WITH RECURSIVE tree AS (
                            SELECT id FROM folders WHERE id IN ({p}) AND owner = ?
                            UNION ALL
                            SELECT f.id FROM folders f INNER JOIN tree t ON f.parent_id = t.id
                        ) SELECT id FROM tree;
                    """, (*clean_folder_ids, self.user_id)).fetchall()

                    descendant_ids = {r['id'] for r in descendants}
                    if target_folder_id in descendant_ids:
                        raise ValueError("Cannot move a folder into one of its subfolders.")

            now_ts = datetime.now(timezone.utc).isoformat()
            moved_files = 0
            moved_folders = 0

            # Move files
            if clean_file_ids:
                chunk_size = 500
                for i in range(0, len(clean_file_ids), chunk_size):
                    chunk = clean_file_ids[i:i + chunk_size]
                    p = ','.join('?' for _ in chunk)
                    cur = conn.execute(
                        f"UPDATE files SET folder_id = ?, last_modified = ? WHERE uuid IN ({p}) AND owner = ?",
                        (target_folder_id, now_ts, *chunk, self.user_id)
                    )
                    moved_files += cur.rowcount

            # Move folders
            if clean_folder_ids:
                chunk_size = 500
                for i in range(0, len(clean_folder_ids), chunk_size):
                    chunk = clean_folder_ids[i:i + chunk_size]
                    p = ','.join('?' for _ in chunk)
                    cur = conn.execute(
                        f"UPDATE folders SET parent_id = ?, last_modified = ? WHERE id IN ({p}) AND owner = ?",
                        (target_folder_id, now_ts, *chunk, self.user_id)
                    )
                    moved_folders += cur.rowcount

            conn.commit()

        return {
            "status": "moved",
            "moved_files": moved_files,
            "moved_folders": moved_folders,
            "target_folder_id": target_folder_id
        }

    # ─── Raw Data Engine ──────────────────────────────────────────
    
    def execute_query(self, sql: str, params: tuple = ()) -> int:
        with self._get_conn() as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.rowcount
            
    def fetch_all(self, sql: str, params: tuple = ()) -> list:
        with self._get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    # ─── Vault Stats (cached) ──────────────────────────────────────────
    _stats_cache = {}  # { user_id: (timestamp, stats_dict) }
    _STATS_TTL = 60

    def get_vault_stats(self) -> dict:
        import time as _time
        now = _time.time()
        cached = UserDataManager._stats_cache.get(self.user_id)
        if cached and (now - cached[0]) < self._STATS_TTL: return cached[1]
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM files WHERE owner = ? AND file_size >= 0", (self.user_id,)).fetchone()
            file_count = row['cnt'] if row else 0
        total_bytes = 0
        if os.path.isdir(self.user_dir):
            for dirpath, _, filenames in os.walk(self.user_dir):
                for fname in filenames:
                    try: total_bytes += os.path.getsize(os.path.join(dirpath, fname))
                    except OSError: pass
        stats = {"file_count": file_count, "total_bytes": total_bytes}
        UserDataManager._stats_cache[self.user_id] = (now, stats)
        return stats

    def invalidate_stats_cache(self):
        UserDataManager._stats_cache.pop(self.user_id, None)

def get_user_manager() -> UserDataManager:
    if not hasattr(g, 'user') or not g.user: raise RuntimeError("Unauthenticated context.")
    user_id = g.user.get('user_id')
    if not user_id: raise RuntimeError("Missing user_id.")
    return UserDataManager(user_id)
