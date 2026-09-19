"""Message history. Only encrypted envelopes are stored; decryption happens on read."""
import sqlite3
import threading
from typing import List



class MessageDb:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, room TEXT NOT NULL, "
            "sender TEXT NOT NULL, ts INTEGER NOT NULL, envelope TEXT NOT NULL)")
        self._db.commit()

    def insert(self, m: dict) -> bool:
        """Returns False for duplicates (same id): this also blunts simple replays."""
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?)",
                (m["id"], m["room"], m["sender"], m["ts"], m["envelope"]))
            self._db.commit()
            return cur.rowcount == 1

    def all(self, room: str) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, room, sender, ts, envelope FROM messages WHERE room=? ORDER BY ts", (room,)).fetchall()
        return [dict(id=r[0], room=r[1], sender=r[2], ts=r[3], envelope=r[4]) for r in rows]

    def clear(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM messages")
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
