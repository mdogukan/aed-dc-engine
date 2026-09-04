import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("AED-DC.Database")

class IncidentDatabase:
    def __init__(self, db_path="/home/black-bird/aed-dc-engine/database/incidents.db"):
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _ensure_schema(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT DEFAULT '192.168.159.240',
                    service_type TEXT DEFAULT 'TCP',
                    src_port INTEGER DEFAULT 0,
                    dst_port INTEGER DEFAULT 0,
                    protocol TEXT DEFAULT 'TCP',
                    action TEXT DEFAULT 'LOG',
                    forensics TEXT DEFAULT '{}'
                )
            """)
            conn.commit()

            cursor.execute("PRAGMA table_info(incidents)")
            existing_cols = [row[1] for row in cursor.fetchall()]

            needed_cols = {
                "dst_ip": "TEXT DEFAULT '192.168.159.240'",
                "service_type": "TEXT DEFAULT 'TCP'",
                "src_port": "INTEGER DEFAULT 0",
                "dst_port": "INTEGER DEFAULT 0",
                "protocol": "TEXT DEFAULT 'TCP'",
                "action": "TEXT DEFAULT 'LOG'",
                "forensics": "TEXT DEFAULT '{}'"
            }
            for col, col_def in needed_cols.items():
                if col not in existing_cols:
                    try:
                        cursor.execute(f"ALTER TABLE incidents ADD COLUMN {col} {col_def}")
                    except Exception:
                        pass
            conn.commit()
        finally:
            conn.close()

    def log_incident(self, *args, **kwargs):
        src_ip = kwargs.get("src_ip", args[0] if len(args) > 0 else "0.0.0.0")
        dst_ip = kwargs.get("dst_ip", kwargs.get("target_ip", "192.168.159.240"))
        dst_port = kwargs.get("dst_port", args[1] if len(args) > 1 else kwargs.get("port", 0))
        
        # protocol ve service_type belirleme
        raw_proto = kwargs.get("protocol", args[2] if len(args) > 2 else kwargs.get("proto", kwargs.get("service_type", "TCP")))
        action = kwargs.get("action", args[3] if len(args) > 3 else kwargs.get("event", "LOG"))
        forensics = kwargs.get("forensics", args[4] if len(args) > 4 else {})
        src_port = kwargs.get("src_port", kwargs.get("sport", 0))

        port_num = int(dst_port or 0)
        if port_num == 0 or "RECON" in str(action):
            proto_val = "ICMP"
        elif port_num in (80, 8080):
            proto_val = "HTTP"
        elif port_num in (22, 2222):
            proto_val = "SSH"
        else:
            proto_val = str(raw_proto or "TCP")

        service_type_val = kwargs.get("service_type", proto_val)

        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        forensics_str = json.dumps(forensics or {}, ensure_ascii=False)

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(incidents)")
            cols_in_db = [row[1] for row in cursor.fetchall()]

            # service_type ve protocol aynı anda doldurulur
            data = {
                "timestamp": ts,
                "src_ip": str(src_ip),
                "dst_ip": str(dst_ip),
                "service_type": str(service_type_val or proto_val),
                "src_port": int(src_port or 0),
                "dst_port": int(dst_port or 0),
                "protocol": str(proto_val),
                "action": str(action or "LOG"),
                "forensics": forensics_str
            }

            active_cols = [c for c in data if c in cols_in_db]
            placeholders = ", ".join(["?"] * len(active_cols))
            col_names = ", ".join(active_cols)
            values = [data[c] for c in active_cols]

            cursor.execute(f"INSERT INTO incidents ({col_names}) VALUES ({placeholders})", values)
            conn.commit()
            return cursor.lastrowid
        except Exception as e:
            logger.error(f"Veritabanı yazma hatası: {e}")
            return None
        finally:
            conn.close()

    def get_incidents(self, limit: int = 50):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                item = dict(row)
                try:
                    item["forensics"] = json.loads(item["forensics"]) if item.get("forensics") else {}
                except Exception:
                    item["forensics"] = {}
                result.append(item)
            return result
        except Exception as e:
            logger.error(f"Veritabanı okuma hatası: {e}")
            return []
        finally:
            conn.close()

    get_all_incidents = lambda self: self.get_incidents(limit=1000)
    get_recent_incidents = get_incidents
    get_all = get_incidents
    fetch_incidents = get_incidents
    add_incident = log_incident
    record_incident = log_incident

db = IncidentDatabase()
Database = IncidentDatabase
