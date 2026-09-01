import sqlite3
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class IncidentDatabase:
    def __init__(self, db_path="database/incidents.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Veritabanı tablosunu ve indeksleri hazırlar."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    service_type TEXT NOT NULL,
                    action TEXT NOT NULL,
                    forensics_json TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON incidents(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp)")
            conn.commit()

    def add_incident(self, src_ip, src_port, dst_ip, dst_port, service_type, action, forensics=None):
        """Yeni bir saldırı ve tecrit olayını veritabanına ekler."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO incidents (timestamp, src_ip, src_port, dst_ip, dst_port, service_type, action, forensics_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now(timezone.utc).isoformat(),
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    service_type,
                    action,
                    json.dumps(forensics or {})
                ))
                conn.commit()
        except Exception as e:
            logging.error(f"Veritabanı kayıt hatası: {e}")

    def get_all_incidents(self, limit=50):
        """Son gerçekleşen olayları listeler."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_statistics(self):
        """Güvenlik istatistiklerini hesaplar."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM incidents")
            total_events = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(DISTINCT src_ip) as unique_attackers FROM incidents")
            unique_attackers = cursor.fetchone()["unique_attackers"]

            cursor.execute("SELECT dst_port, COUNT(*) as count FROM incidents GROUP BY dst_port ORDER BY count DESC LIMIT 5")
            top_ports = [dict(row) for row in cursor.fetchall()]

            return {
                "total_incidents": total_events,
                "unique_attackers": unique_attackers,
                "top_targeted_ports": top_ports
            }

if __name__ == "__main__":
    db = IncidentDatabase()
