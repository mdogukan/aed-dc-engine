import sqlite3
import json
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger("AED-DC.Database")

class IncidentDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, "database", "incidents.db")
        else:
            self.db_path = db_path

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    service_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    forensics TEXT
                )
            """)
            conn.commit()

    def add_incident(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, service_type: str, action: str, forensics: dict):
        timestamp = datetime.now(timezone.utc).isoformat()
        forensics_json = json.dumps(forensics)
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO incidents (timestamp, src_ip, src_port, dst_ip, dst_port, service_type, action, forensics)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, src_port, dst_ip, dst_port, service_type, action, forensics_json))
            conn.commit()

    def get_all_incidents(self, limit: int = 100) -> list[dict]:
        """Kayıtları her zaman en yeniden en eskiye doğru (DESC) getirir."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            
            result = []
            for r in rows:
                item = dict(r)
                if item.get("forensics"):
                    try:
                        item["forensics"] = json.loads(item["forensics"])
                    except Exception:
                        pass
                result.append(item)
            return result
