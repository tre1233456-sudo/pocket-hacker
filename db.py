"""
Pocket Flipper - SQLite Database
Stores conversations and notes.
"""

import sqlite3
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, path: str = "pocket_hacker.db"):
        self.path = path
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_id);
                CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def save_message(self, user_id: int, role: str, content: str):
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO conversations (user_id, role, content) VALUES (?, ?, ?)",
                (user_id, role, content)
            )
            conn.commit()
        finally:
            conn.close()

    def get_conversation(self, user_id: int, limit: int = 20) -> List[Dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT role, content FROM conversations WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                (user_id, limit)
            ).fetchall()
            return [dict(r) for r in reversed(rows)]
        finally:
            conn.close()

    def clear_conversation(self, user_id: int):
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM conversations WHERE user_id = ?", (user_id,))
            conn.commit()
        finally:
            conn.close()

    def save_note(self, user_id: int, title: str, content: str) -> int:
        conn = self._get_conn()
        try:
            cur = conn.execute(
                "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
                (user_id, title, content)
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_notes(self, user_id: int) -> List[Dict]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY id DESC",
                (user_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def delete_note(self, user_id: int, note_id: int) -> bool:
        conn = self._get_conn()
        try:
            cur = conn.execute(
                "DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
