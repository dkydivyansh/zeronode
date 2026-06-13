import os
import sqlite3
import uuid
from datetime import datetime, timezone
from flask import current_app, g
from contextlib import contextmanager

class GraphDataManager:
    def __init__(self, user_id: str):
        if not user_id:
            raise ValueError("user_id cannot be empty")
        
        self.user_id = user_id
        
        # Calculate localized paths
        _data_root = current_app.config['DATA_DIR']
        self.user_dir = os.path.join(_data_root, self.user_id)
        self.graph_db_path = os.path.join(self.user_dir, f"graph_{self.user_id}.db")
        self.graph_files_dir = os.path.join(self.user_dir, "graph")
        
        # Ensure base structure exists
        self._ensure_structure()

    def _ensure_structure(self):
        if not os.path.exists(self.user_dir):
            os.makedirs(self.user_dir, exist_ok=True)
        if not os.path.exists(self.graph_files_dir):
            os.makedirs(self.graph_files_dir, exist_ok=True)
            
        with self._get_conn() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            self._initialize_schema(conn)

    def _initialize_schema(self, conn):
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS subjects (
                uuid TEXT PRIMARY KEY,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                email_hash TEXT,
                phone_hash TEXT,
                dob_hash TEXT,
                encrypted_search_blob TEXT, 
                encrypted_blob TEXT 
            );

            CREATE TABLE IF NOT EXISTS groups (
                uuid TEXT PRIMARY KEY,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                encrypted_search_blob TEXT,
                encrypted_blob TEXT
            );

            CREATE TABLE IF NOT EXISTS relations (
                source_uuid TEXT,
                target_uuid TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                encrypted_blob TEXT,
                PRIMARY KEY (source_uuid, target_uuid)
            );

            CREATE TABLE IF NOT EXISTS subject_files (
                subject_uuid TEXT,
                file_uuid TEXT PRIMARY KEY,
                attached_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS group_files (
                group_uuid TEXT,
                file_uuid TEXT PRIMARY KEY,
                attached_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Same file chunking tables as vault, but isolated to graph folder
            CREATE TABLE IF NOT EXISTS files (
                uuid TEXT PRIMARY KEY,
                file_name TEXT NOT NULL,
                last_modified TIMESTAMP NOT NULL,
                owner TEXT NOT NULL,
                aes_key TEXT NOT NULL,
                file_size INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS subjects_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_uuid TEXT,
                action_type TEXT,
                old_encrypted_blob TEXT,
                action_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                purge_date DATETIME
            );

            CREATE TABLE IF NOT EXISTS groups_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_uuid TEXT,
                action_type TEXT,
                old_encrypted_blob TEXT,
                action_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                purge_date DATETIME
            );
        """)
        
        # Safely attempt to add columns to relations table if they don't exist
        try:
            conn.execute("ALTER TABLE relations ADD COLUMN source_type TEXT DEFAULT 'subject'")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE relations ADD COLUMN target_type TEXT DEFAULT 'subject'")
        except Exception:
            pass

        # Create Triggers safely (IF NOT EXISTS is not standard for triggers in all SQLite versions, so drop then create)
        conn.executescript("""
            DROP TRIGGER IF EXISTS snapshot_subject_update;
            CREATE TRIGGER snapshot_subject_update
            BEFORE UPDATE ON subjects
            FOR EACH ROW
            BEGIN
                INSERT INTO subjects_history (subject_uuid, action_type, old_encrypted_blob, purge_date)
                VALUES (OLD.uuid, 'UPDATE', OLD.encrypted_blob, datetime('now', '+60 days'));
                
                DELETE FROM subjects_history
                WHERE subject_uuid = OLD.uuid AND action_type = 'UPDATE'
                AND history_id NOT IN (
                    SELECT history_id FROM subjects_history
                    WHERE subject_uuid = OLD.uuid AND action_type = 'UPDATE'
                    ORDER BY history_id DESC
                    LIMIT 20
                );
            END;

            DROP TRIGGER IF EXISTS snapshot_subject_delete;
            CREATE TRIGGER snapshot_subject_delete
            BEFORE DELETE ON subjects
            FOR EACH ROW
            BEGIN
                INSERT INTO subjects_history (subject_uuid, action_type, old_encrypted_blob, purge_date)
                VALUES (OLD.uuid, 'DELETE', OLD.encrypted_blob, datetime('now', '+60 days'));
            END;

            DROP TRIGGER IF EXISTS snapshot_group_update;
            CREATE TRIGGER snapshot_group_update
            BEFORE UPDATE ON groups
            FOR EACH ROW
            BEGIN
                INSERT INTO groups_history (group_uuid, action_type, old_encrypted_blob, purge_date)
                VALUES (OLD.uuid, 'UPDATE', OLD.encrypted_blob, datetime('now', '+60 days'));
                
                DELETE FROM groups_history
                WHERE group_uuid = OLD.uuid AND action_type = 'UPDATE'
                AND history_id NOT IN (
                    SELECT history_id FROM groups_history
                    WHERE group_uuid = OLD.uuid AND action_type = 'UPDATE'
                    ORDER BY history_id DESC
                    LIMIT 20
                );
            END;

            DROP TRIGGER IF EXISTS snapshot_group_delete;
            CREATE TRIGGER snapshot_group_delete
            BEFORE DELETE ON groups
            FOR EACH ROW
            BEGIN
                INSERT INTO groups_history (group_uuid, action_type, old_encrypted_blob, purge_date)
                VALUES (OLD.uuid, 'DELETE', OLD.encrypted_blob, datetime('now', '+60 days'));
            END;
        """)
        conn.commit()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.graph_db_path)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    # ─── Subjects ──────────────────────────────────────────────────

    def upsert_subject(self, uuid_str: str, encrypted_blob: str, encrypted_search_blob: str, email_hash: str = None, phone_hash: str = None, dob_hash: str = None):
        if not uuid_str:
            uuid_str = str(uuid.uuid4())
        
        with self._get_conn() as conn:
            existing = conn.execute("SELECT uuid, encrypted_blob FROM subjects WHERE uuid = ?", (uuid_str,)).fetchone()
            if existing:
                if existing['encrypted_blob']:
                    conn.execute("""
                        INSERT INTO subjects_history (subject_uuid, action_type, old_encrypted_blob)
                        VALUES (?, 'UPDATE', ?)
                    """, (uuid_str, existing['encrypted_blob']))
                    
                conn.execute("""
                    UPDATE subjects SET
                        updated_at = CURRENT_TIMESTAMP,
                        email_hash = ?, phone_hash = ?, dob_hash = ?,
                        encrypted_search_blob = ?, encrypted_blob = ?
                    WHERE uuid = ?
                """, (email_hash, phone_hash, dob_hash, encrypted_search_blob, encrypted_blob, uuid_str))
            else:
                conn.execute("""
                    INSERT INTO subjects (uuid, email_hash, phone_hash, dob_hash, encrypted_search_blob, encrypted_blob)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (uuid_str, email_hash, phone_hash, dob_hash, encrypted_search_blob, encrypted_blob))
            conn.commit()
        return uuid_str

    def get_subject(self, uuid_str: str) -> dict:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM subjects WHERE uuid = ?", (uuid_str,)).fetchone()
            if not row: return None
            
            # Get relations
            rels = conn.execute("SELECT * FROM relations WHERE source_uuid = ? OR target_uuid = ?", (uuid_str, uuid_str)).fetchall()
            
            # Get files
            files = conn.execute("""
                SELECT f.uuid, f.file_name, f.file_size, f.last_modified, f.aes_key 
                FROM subject_files sf
                JOIN files f ON sf.file_uuid = f.uuid
                WHERE sf.subject_uuid = ?
            """, (uuid_str,)).fetchall()

            return {
                "profile": dict(row),
                "relations": [dict(r) for r in rels],
                "files": [dict(f) for f in files]
            }

    def delete_subject(self, uuid_str: str):
        with self._get_conn() as conn:
            # Delete associated files physically
            files = conn.execute("SELECT file_uuid FROM subject_files WHERE subject_uuid = ?", (uuid_str,)).fetchall()
            for f in files:
                self.delete_file(f['file_uuid'])
                
            conn.execute("DELETE FROM relations WHERE source_uuid = ? OR target_uuid = ?", (uuid_str, uuid_str))
            cursor = conn.execute("DELETE FROM subjects WHERE uuid = ?", (uuid_str,))
            conn.execute("DELETE FROM subjects_history WHERE subject_uuid = ?", (uuid_str,))
            conn.commit()
            return cursor.rowcount > 0

    def get_subject_revisions(self, uuid_str: str) -> list:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT history_id, action_type, old_encrypted_blob, action_date FROM subjects_history WHERE subject_uuid = ? ORDER BY action_date DESC", (uuid_str,)).fetchall()
            return [dict(r) for r in rows]

    # ─── Groups ────────────────────────────────────────────────────

    def upsert_group(self, uuid_str: str, encrypted_blob: str, encrypted_search_blob: str):
        if not uuid_str:
            uuid_str = str(uuid.uuid4())
        
        with self._get_conn() as conn:
            existing = conn.execute("SELECT uuid, encrypted_blob FROM groups WHERE uuid = ?", (uuid_str,)).fetchone()
            if existing:
                if existing['encrypted_blob']:
                    conn.execute("""
                        INSERT INTO groups_history (group_uuid, action_type, old_encrypted_blob)
                        VALUES (?, 'UPDATE', ?)
                    """, (uuid_str, existing['encrypted_blob']))
                    
                conn.execute("""
                    UPDATE groups SET
                        updated_at = CURRENT_TIMESTAMP,
                        encrypted_search_blob = ?, encrypted_blob = ?
                    WHERE uuid = ?
                """, (encrypted_search_blob, encrypted_blob, uuid_str))
            else:
                conn.execute("""
                    INSERT INTO groups (uuid, encrypted_search_blob, encrypted_blob)
                    VALUES (?, ?, ?)
                """, (uuid_str, encrypted_search_blob, encrypted_blob))
            conn.commit()
        return uuid_str

    def get_group(self, uuid_str: str) -> dict:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM groups WHERE uuid = ?", (uuid_str,)).fetchone()
            if not row: return None
            
            rels = conn.execute("SELECT * FROM relations WHERE source_uuid = ? OR target_uuid = ?", (uuid_str, uuid_str)).fetchall()
            
            files = conn.execute("""
                SELECT f.uuid, f.file_name, f.file_size, f.last_modified, f.aes_key 
                FROM group_files gf
                JOIN files f ON gf.file_uuid = f.uuid
                WHERE gf.group_uuid = ?
            """, (uuid_str,)).fetchall()

            return {
                "profile": dict(row),
                "relations": [dict(r) for r in rels],
                "files": [dict(f) for f in files]
            }

    def delete_group(self, uuid_str: str):
        with self._get_conn() as conn:
            # Delete associated files physically
            files = conn.execute("SELECT file_uuid FROM group_files WHERE group_uuid = ?", (uuid_str,)).fetchall()
            for f in files:
                self.delete_file(f['file_uuid'])
                
            conn.execute("DELETE FROM relations WHERE source_uuid = ? OR target_uuid = ?", (uuid_str, uuid_str))
            cursor = conn.execute("DELETE FROM groups WHERE uuid = ?", (uuid_str,))
            conn.execute("DELETE FROM groups_history WHERE group_uuid = ?", (uuid_str,))
            conn.commit()
            return cursor.rowcount > 0

    def get_group_revisions(self, uuid_str: str) -> list:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT history_id, action_type, old_encrypted_blob, action_date FROM groups_history WHERE group_uuid = ? ORDER BY action_date DESC", (uuid_str,)).fetchall()
            return [dict(r) for r in rows]

    # ─── Relations ─────────────────────────────────────────────────

    def upsert_relation(self, source_uuid: str, target_uuid: str, encrypted_blob: str, source_type: str = 'subject', target_type: str = 'subject'):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO relations (source_uuid, target_uuid, encrypted_blob, source_type, target_type)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_uuid, target_uuid) DO UPDATE SET 
                    encrypted_blob = excluded.encrypted_blob,
                    source_type = excluded.source_type,
                    target_type = excluded.target_type
            """, (source_uuid, target_uuid, encrypted_blob, source_type, target_type))
            conn.commit()

    def delete_relation(self, source_uuid: str, target_uuid: str):
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM relations WHERE source_uuid = ? AND target_uuid = ?", (source_uuid, target_uuid))
            conn.commit()
            return cursor.rowcount > 0

    # ─── Search Indices ────────────────────────────────────────────

    def get_search_indices(self) -> dict:
        """Returns ALL lightweight search blobs for the frontend to decrypt locally."""
        with self._get_conn() as conn:
            subjects = conn.execute("SELECT uuid, encrypted_search_blob FROM subjects").fetchall()
            groups = conn.execute("SELECT uuid, encrypted_search_blob FROM groups").fetchall()
            return {
                "subjects": [{"uuid": r['uuid'], "search_blob": r['encrypted_search_blob']} for r in subjects],
                "groups": [{"uuid": r['uuid'], "search_blob": r['encrypted_search_blob']} for r in groups]
            }

    def exact_search(self, email_hash: str = None, phone_hash: str = None, dob_hash: str = None) -> list:
        """Server-side blind index exact match."""
        query = "SELECT uuid FROM subjects WHERE 1=1"
        params = []
        if email_hash:
            query += " AND email_hash = ?"
            params.append(email_hash)
        if phone_hash:
            query += " AND phone_hash = ?"
            params.append(phone_hash)
        if dob_hash:
            query += " AND dob_hash = ?"
            params.append(dob_hash)
            
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [r['uuid'] for r in rows]

    # ─── File Operations (Graph Specific) ──────────────────────────

    def init_file_upload(self, subject_uuid: str, file_name: str, aes_key: str, entity_type: str = 'subject') -> str:
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(self.graph_files_dir, f"{file_uuid}.bin")
        now_ts = datetime.now(timezone.utc).isoformat()

        # Enforce 2GB quota for graph attachments once on init
        total_bytes = 0
        for fname in os.listdir(self.graph_files_dir):
            try: total_bytes += os.path.getsize(os.path.join(self.graph_files_dir, fname))
            except OSError: pass
            
        if total_bytes > (2 * 1024 * 1024 * 1024):
            raise Exception("Graph attachment limit of 2GB exceeded.")

        with open(file_path, 'wb') as f:
            pass  # 0-byte

        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO files (uuid, file_name, last_modified, owner, aes_key, file_size) VALUES (?, ?, ?, ?, ?, ?)",
                (file_uuid, file_name, now_ts, self.user_id, aes_key, -1)
            )
            if entity_type == 'group':
                conn.execute(
                    "INSERT INTO group_files (group_uuid, file_uuid) VALUES (?, ?)",
                    (subject_uuid, file_uuid)
                )
            else:
                conn.execute(
                    "INSERT INTO subject_files (subject_uuid, file_uuid) VALUES (?, ?)",
                    (subject_uuid, file_uuid)
                )
            conn.commit()
        return file_uuid

    def write_file_chunk(self, file_uuid: str, chunk_bytes: bytes, offset: int) -> bool:
        with self._get_conn() as conn:
            row = conn.execute("SELECT uuid FROM files WHERE uuid = ?", (file_uuid,)).fetchone()
        if not row:
            raise PermissionError(f"File {file_uuid} not found in graph.")

        file_path = os.path.join(self.graph_files_dir, f"{file_uuid}.bin")

        with open(file_path, 'r+b') as f:
            f.seek(offset)
            f.write(chunk_bytes)

        return True

    def finalize_file(self, file_uuid: str) -> dict:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ?", (file_uuid,)).fetchone()
        if not row:
            raise PermissionError(f"File {file_uuid} not found.")

        file_path = os.path.join(self.graph_files_dir, f"{file_uuid}.bin")
        file_size = os.path.getsize(file_path)

        now_ts = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute("UPDATE files SET last_modified = ?, file_size = ? WHERE uuid = ?", 
                         (now_ts, file_size, file_uuid))
            conn.commit()

        return {"uuid": file_uuid, "file_name": row['file_name'], "size": file_size, "last_modified": now_ts}

    def get_file_meta(self, file_uuid: str) -> dict:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ?", (file_uuid,)).fetchone()
        if not row:
            return None
        return dict(row)

    def get_all_graph_files(self) -> list:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT uuid, file_name as name, file_size, last_modified FROM files WHERE file_size >= 0 ORDER BY file_name ASC").fetchall()
            return [dict(r) for r in rows]

    def get_file(self, file_uuid: str) -> dict:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM files WHERE uuid = ?", (file_uuid,)).fetchone()
        if not row:
            raise FileNotFoundError(f"File {file_uuid} not found.")
            
        file_path = os.path.join(self.graph_files_dir, f"{file_uuid}.bin")
        return {"metadata": dict(row), "file_path": file_path}

    def delete_file(self, file_uuid: str) -> bool:
        with self._get_conn() as conn:
            conn.execute("DELETE FROM subject_files WHERE file_uuid = ?", (file_uuid,))
            conn.execute("DELETE FROM group_files WHERE file_uuid = ?", (file_uuid,))
            conn.execute("DELETE FROM files WHERE uuid = ?", (file_uuid,))
            conn.commit()
            
        file_path = os.path.join(self.graph_files_dir, f"{file_uuid}.bin")
        if os.path.exists(file_path):
            os.remove(file_path)
        return True

def get_graph_manager() -> GraphDataManager:
    if not hasattr(g, 'user') or not g.user: raise RuntimeError("Unauthenticated context.")
    user_id = g.user.get('user_id')
    return GraphDataManager(user_id)
