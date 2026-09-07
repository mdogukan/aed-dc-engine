from core.attck_engine import attck_engine
import sys
import os
import time
import socket
import asyncio
import threading
import logging
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

import paramiko

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.ws_manager import ws_manager
from containment.blocker import NftablesContainment
from database.db import db

logger = logging.getLogger("AED-DC.SSHDecoy")
logging.getLogger("paramiko").setLevel(logging.WARNING)

CANARY_SSH_USERS = {"vault_admin", "pg_admin_sec", "canary_user", "admin_backup"}
CANARY_SSH_PASSWORDS = {"V4ult#Master@2026!Key", "super_secret_signing_token_9921_xae"}


class HoneySSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, auth_callback):
        self.client_ip = client_ip
        self.auth_callback = auth_callback

    def check_auth_password(self, username, password):
        self.auth_callback(username, password)
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        self.auth_callback(username, "")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


class AsyncSSHDecoyServer:
    def __init__(self, bind_ip="192.168.159.240", port=22, log_file="logs/detections.json"):
        self.bind_ip = bind_ip
        self.port = int(port)
        self.log_file = log_file
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        self.blocker = NftablesContainment()
        self.db = db
        self.server_socket = None
        self.thread = None
        self.running = False
        # Sahte SSH sunucusu için dinamik anahtar üretimi
        self.host_key = paramiko.RSAKey.generate(2048)

    def _calculate_dynamic_ttl(self, client_ip: str) -> tuple[int, str]:
        try:
            incidents = self.db.get_incidents(limit=500)
            recent_strikes = sum(1 for inc in incidents if inc.get("src_ip") == client_ip)
            strike_count = max(1, recent_strikes)
        except Exception:
            strike_count = 1

        if strike_count <= 1:
            return 3600, "1 Saat (1. İhlal)"
        elif strike_count == 2:
            return 21600, "6 Saat (2. İhlal)"
        else:
            return 172800, "48 Saat (3+ İhlal)"

    def _record_incident(self, client_ip: str, client_port: int, username: str, password: str, client_version: str):
        is_canary = (
            username.lower() in CANARY_SSH_USERS
            or password in CANARY_SSH_PASSWORDS
            or "CANARY" in username.upper()
        )

        now_utc = datetime.now(timezone.utc).isoformat()
        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        if is_canary:
            action_event = "CANARY_TOKEN_TRIGGERED"
            ttl_seconds = 7200
            ttl_label = "2 Saat (Kritik Canary İhlali)"
            trigger_reason = "CANARY_SSH_CREDENTIAL_MISUSE"
            logger.critical(f"[CANARY SSH ALARMI] Çalınan SSH Kimliği Kullanıldı! IP: {client_ip} | Kullanıcı: {username}")
        else:
            action_event = "INTERACTED_AND_ISOLATED"
            ttl_seconds, ttl_label = self._calculate_dynamic_ttl(client_ip)
            trigger_reason = "SSH_BRUTE_FORCE_PROBE" if username else "SSH_LOW_INTERACTION_BANNER_TRAP"
            logger.warning(f"[SSH ETKİLEŞİMİ] Saldırgan IP: {client_ip} | Kullanıcı: {username or 'Yok'}")

        forensics = {
            "attempted_user": username or "Bilinmiyor",
            "attempted_pass": password if password else "[Girilmedi]",
            "client_banner": client_version,
            "strike_penalty": ttl_label,
            "trigger": trigger_reason,
            "threat_level": "CRITICAL" if is_canary else "HIGH"
        }

        forensic_entry = {
            "timestamp": now_utc,
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": self.bind_ip,
            "dst_port": self.port,
            "protocol": "SSH",
            "forensics": forensics,
            "action": action_event
        }

        # 1. JSON Log Kaydı
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(forensic_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.error(f"SSH JSON log hatası: {e}")

        # 2. SQLite Adli Kayıt (SHA-256 zinciriyle mühürlenir)
        try:
            self.db.log_incident(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=self.bind_ip,
                dst_port=self.port,
                protocol="SSH",
                action=action_event,
                forensics=forensics
            )
        except Exception as e:
            logger.error(f"SSH SQLite log hatası: {e}")

        # 3. Çekirdekte Tecrit (nftables)
        try:
            self.blocker.isolate_ip(client_ip, timeout_seconds=ttl_seconds)
        except Exception as e:
            logger.error(f"SSH tecrit hatası: {e}")

        # 4. Web Paneline Canlı WebSocket Gönderimi
        _, mitre_id, mitre_desc = attck_engine.resolve_mitre_ttp(self.port, "SSH", action_event, forensics)
        payload_data = {
            "timestamp": now_str,
            "mitre_id": mitre_id,
            "mitre_technique": mitre_desc,
            "src_ip": client_ip,
            "ip": client_ip,
            "dst_port": self.port,
            "port": self.port,
            "protocol": "SSH",
            "action": action_event,
            "event": action_event,
            "forensics": forensics
        }
        try:
            ws_manager.broadcast_threadsafe(payload_data)
        except Exception as e:
            logger.error(f"SSH WebSocket yayın hatası: {e}")

    def _handle_client_thread(self, client_sock, client_addr):
        client_ip = client_addr[0]
        client_port = client_addr[1]
        auth_data = {"user": None, "pass": None}

        def on_auth(u, p):
            auth_data["user"] = u
            auth_data["pass"] = p

        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            transport.add_server_key(self.host_key)

            server = HoneySSHServer(client_ip, on_auth)
            transport.start_server(server=server)

            # Kimlik doğrulama veya tarama için 12 saniye bekle
            channel = transport.accept(12)
            if channel is not None:
                channel.close()
        except Exception:
            pass
        finally:
            client_version = transport.remote_version if transport and hasattr(transport, "remote_version") else "Bilinmeyen İstemci"
            self._record_incident(
                client_ip=client_ip,
                client_port=client_port,
                username=auth_data["user"] or "",
                password=auth_data["pass"] or "",
                client_version=client_version
            )
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass

    def _run_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.bind_ip, self.port))
            self.server_socket.listen(50)
            logger.info(f"[*] Dinamik Sahte SSH Servisi Başlatıldı | Dinleme: {self.bind_ip}:{self.port} (SSH)")
            self.running = True

            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    t = threading.Thread(
                        target=self._handle_client_thread,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    t.start()
                except Exception:
                    break
        except Exception as e:
            logger.error(f"SSH dinleme hatası: {e}")

    async def start(self):
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(target=self._run_server, daemon=True)
            self.thread.start()
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.stop()

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass


start_ssh_trap = lambda host="192.168.159.240", port=22: AsyncSSHDecoyServer(host, port)
