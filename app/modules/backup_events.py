import json
import time
import threading
from typing import Set, Tuple, Any

class BackupEventBroadcaster:
    """
    Thread-safe WebSocket broadcaster for real-time backup and restore progress updates.
    Supports granular target filtering so non-admins only see their own account events.
    """
    def __init__(self):
        # Set of tuples: (ws, user_id, is_admin)
        self._clients: Set[Tuple[Any, str, bool]] = set()
        self._lock = threading.Lock()
        self._recent_events = []
        self._max_recent = 50

    def register(self, ws, user_id: str, is_admin: bool):
        """Register a connected WebSocket client."""
        with self._lock:
            self._clients.add((ws, user_id, is_admin))

    def deregister(self, ws):
        """Remove a disconnected WebSocket client."""
        with self._lock:
            self._clients = {c for c in self._clients if c[0] != ws}

    def broadcast(self, event: dict):
        """
        Broadcast a real-time event to all authorized connected clients.
        Event schema:
        {
            "type": "backup_progress" | "restore_progress" | "backup_completed" | "restore_completed" | "failed",
            "operation": "backup" | "restore",
            "task_id": str,
            "target_type": "user" | "server",
            "target_id": str,
            "phase": "compress" | "upload" | "verify" | "download" | "restore_db" | "restore_blobs" | "cleanup" | "done",
            "progress": int (0 - 100),
            "step": str,
            "details": dict,
            "timestamp": int
        }
        """
        if "timestamp" not in event:
            event["timestamp"] = int(time.time())

        payload = json.dumps(event)
        target_type = event.get("target_type")
        target_id = event.get("target_id")

        with self._lock:
            # Store in recent cache for fast fallback retrieval
            self._recent_events.append(event)
            if len(self._recent_events) > self._max_recent:
                self._recent_events.pop(0)

            dead = set()
            for client_tuple in self._clients:
                ws, uid, is_admin = client_tuple
                
                # Scope check: Admins see everything; users see only their own events
                allowed = is_admin or (target_type == "user" and target_id == uid)
                if not allowed:
                    continue

                try:
                    ws.send(payload)
                except Exception:
                    dead.add(client_tuple)

            if dead:
                self._clients.difference_update(dead)

    def get_recent_events(self, user_id: str, is_admin: bool, limit: int = 10) -> list:
        """Retrieve recent events filtered for the given user."""
        with self._lock:
            filtered = []
            for ev in reversed(self._recent_events):
                if is_admin or (ev.get("target_type") == "user" and ev.get("target_id") == user_id):
                    filtered.append(ev)
                if len(filtered) >= limit:
                    break
            return list(reversed(filtered))

# Global singleton broadcaster instance
broadcaster = BackupEventBroadcaster()

def broadcast_event(event: dict):
    """Convenience helper to broadcast backup and restore events."""
    broadcaster.broadcast(event)

