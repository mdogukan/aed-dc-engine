import asyncio
import threading
import logging
import json
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from containment.blocker import NftablesContainment
from database.db import db
from api.ws_manager import ws_manager

logger = logging.getLogger("AED-DC.Traps")

FAKE_ENV_RESPONSE = """# Production Environment Secrets
APP_NAME=Enterprise-Core-API
APP_ENV=production
APP_KEY=base64:dGVzdGtleWZvcmF1dG9ub21vdXNjeWJlcmRlY2VwdGlvbg==
APP_DEBUG=false
DB_CONNECTION=pgsql
DB_HOST=10.0.80.12
DB_PORT=5432
DB_DATABASE=corp_vault
DB_USERNAME=pg_admin_sec
DB_PASSWORD=V4ult#Master@2026!Key
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
JWT_SECRET=super_secret_signing_token_9921_xae
"""

class DecoyHTTPHandler(BaseHTTPRequestHandler):
    blocker = NftablesContainment()

    def log_message(self, format, *args):
        pass  # Standart konsol log kirliliğini önle

    def do_GET(self):
        self._handle_attack()

    def do_POST(self):
        self._handle_attack()

    def do_HEAD(self):
        self._handle_attack()

    def _handle_attack(self):
        client_ip = self.client_address[0]
        req_path = self.path
        user_agent = self.headers.get("User-Agent", "Unknown")
        headers_dump = dict(self.headers)
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        logger.warning(f"[YEM SERVİSİ ETKİLEŞİMİ] Saldırgan IP: {client_ip} | İstek: {req_path}")

        forensics = {
            "requested_path": req_path,
            "method": self.command,
            "user_agent": user_agent,
            "headers": headers_dump,
            "trigger": "HIGH_INTERACTION_DECOY_ENV_TRAP",
            "honey_token": "AWS_ACCESS_KEY_ID & DB_PASSWORD"
        }

        # 1. SQLite Adli Kayıt
        try:
            db.log_incident(
                src_ip=client_ip,
                dst_port=80,
                protocol="HTTP",
                action="INTERACTED_AND_ISOLATED",
                forensics=forensics
            )
        except Exception as e:
            logger.error(f"Veritabanı yazma hatası: {e}")

        # 2. Çekirdek Seviyesinde Tecrit (1 Saat)
        try:
            self.blocker.isolate_ip(client_ip, timeout_seconds=3600)
        except Exception as e:
            logger.error(f"Tecrit motoru hatası: {e}")

        # 3. Sol Tabloya Anında Canlı WebSocket Yayını Fırlat
        payload = {
            "timestamp": now_str,
            "src_ip": client_ip,
            "ip": client_ip,
            "dst_port": 80,
            "port": 80,
            "protocol": "HTTP",
            "action": "INTERACTED_AND_ISOLATED",
            "event": "INTERACTED_AND_ISOLATED",
            "forensics": forensics
        }
        try:
            ws_manager.broadcast_threadsafe(payload)
        except Exception as e:
            logger.error(f"WebSocket yayın hatası: {e}")

        # 4. Saldırgana Sahte İçeriği Dön
        try:
            body = FAKE_ENV_RESPONSE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "nginx/1.18.0 (Ubuntu)")
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True

class AsyncDecoyServer:
    def __init__(self, *args, **kwargs):
        host = "0.0.0.0"
        port = 80
        if args:
            if isinstance(args[0], str):
                host = args[0]
                if len(args) > 1:
                    port = args[1]
            elif isinstance(args[0], dict):
                host = args[0].get("host", host)
                port = args[0].get("port", port)
            elif hasattr(args[0], "host"):
                host = getattr(args[0], "host", host)
                port = getattr(args[0], "port", port)
        if "host" in kwargs:
            host = kwargs["host"]
        if "port" in kwargs:
            port = kwargs["port"]
        self.host = str(host)
        self.port = int(port)
        self.server = None
        self.thread = None

    def _run_server(self):
        try:
            self.server = ReusableHTTPServer((self.host, self.port), DecoyHTTPHandler)
            logger.info(f"[*] Dinamik Sahte Servisler Başlatıldı | Dinleme: {self.host}:{self.port} (HTTP)")
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"HTTP Dinleme Hatası ({self.host}:{self.port}): {e}")

    async def start(self):
        """main.py içerisindeki asyncio.gather() ile tam uyumlu asenkron coroutine."""
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._run_server, daemon=True)
            self.thread.start()
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.stop()

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass

start_http_trap = lambda host="0.0.0.0", port=80: AsyncDecoyServer(host, port)
