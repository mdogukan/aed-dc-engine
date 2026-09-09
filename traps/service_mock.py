from core.attck_engine import attck_engine
import asyncio
import threading
import logging
import json
import secrets
import string
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from containment.blocker import NftablesContainment
from database.db import db
from api.ws_manager import ws_manager

logger = logging.getLogger("AED-DC.Traps")

BASE_CANARY_ENDPOINT = "/api/v1/vault-auth"

# 1. AWS Kimlik Bilgisi Oturum Önbelleği
_AWS_CACHE_LOCK = threading.Lock()
_AWS_CREDS_CACHE = {}

# 2. Out-of-Band Deanonymizer Jeton Havuzu (Thread-safe)
# Yapı: { token_id: {"origin_ip": str, "created_at": datetime, "hit_count": int} }
_DEANON_LOCK = threading.Lock()
_DEANON_REGISTRY = {}

def register_deanon_token(origin_ip: str) -> tuple:
    """
    Saldırgan IP'sine özel dinamik bir Canary takip jetonu üretir ve kaydeder.
    """
    token_suffix = secrets.token_hex(6).upper()
    token_key = f"CANARY_KEY_VAULT_{token_suffix}"
    tracking_url = f"http://192.168.159.240{BASE_CANARY_ENDPOINT}?token={token_key}"
    
    with _DEANON_LOCK:
        _DEANON_REGISTRY[token_key] = {
            "origin_ip": origin_ip,
            "created_at": datetime.utcnow(),
            "hit_count": 0
        }
    return token_key, tracking_url

def check_deanon_token(token_key: str, current_ip: str):
    """
    Gelen jetonu doğrular. Eğer jetonu çeken ilk IP ile şu an kullanan IP farklıysa
    VPN/Proxy arkasından çıkan saldırganı deşifre eder (Deanonymization).
    """
    with _DEANON_LOCK:
        if token_key in _DEANON_REGISTRY:
            data = _DEANON_REGISTRY[token_key]
            data["hit_count"] += 1
            origin_ip = data["origin_ip"]
            is_deanonymized = (origin_ip != current_ip)
            return True, is_deanonymized, origin_ip
    return False, False, None

def generate_custom_env(client_ip: str) -> str:
    """
    Saldırgan IP'sine özel üretilmiş takip jetonunu içeren dinamik .env içeriği oluşturur.
    """
    token_key, tracking_url = register_deanon_token(client_ip)
    
    return f"""# Production Environment Secrets
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
CANARY_AUTH_TOKEN={token_key}
CANARY_VERIFY_URL={tracking_url}
"""

def get_or_create_aws_creds(client_ip: str, req_path: str) -> dict:
    now = datetime.utcnow()
    with _AWS_CACHE_LOCK:
        if client_ip in _AWS_CREDS_CACHE:
            cached_data, expires_at = _AWS_CREDS_CACHE[client_ip]
            if now < expires_at:
                return cached_data

        chars = string.ascii_uppercase + string.digits
        rand_access_key = "AKIA" + "".join(secrets.choice(chars) for _ in range(16))
        secret_chars = string.ascii_letters + string.digits + "+/="
        rand_secret_key = "".join(secrets.choice(secret_chars) for _ in range(40))
        rand_session_token = "FQoGZXIvYXdzE" + secrets.token_urlsafe(48)

        last_updated = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        expiration = (now + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")

        role_name = req_path.rstrip("/").split("/")[-1]
        if not role_name or role_name in ("security-credentials", "meta-data", "latest"):
            role_name = "corp-ec2-cluster-admin"

        creds = {
            "Code": "Success",
            "LastUpdated": last_updated,
            "Type": "AWS-HMAC",
            "RoleArn": f"arn:aws:iam::849201948201:role/{role_name}",
            "AccessKeyId": rand_access_key,
            "SecretAccessKey": rand_secret_key,
            "Token": rand_session_token,
            "Expiration": expiration
        }

        _AWS_CREDS_CACHE[client_ip] = (creds, now + timedelta(hours=1))
        return creds

class DecoyHTTPHandler(BaseHTTPRequestHandler):
    blocker = NftablesContainment()

    def log_message(self, format, *args):
        pass

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

        parsed_url = urlparse(req_path)
        query_params = parse_qs(parsed_url.query)

        # Gelen istekte jeton arama (URL parametresi, Path veya Header'lar)
        incoming_token = None
        if "token" in query_params:
            incoming_token = query_params["token"][0]
        elif "CANARY_KEY_VAULT_" in req_path:
            for part in req_path.split("/"):
                if "CANARY_KEY_VAULT_" in part:
                    incoming_token = part
                    break
        else:
            for val in headers_dump.values():
                if "CANARY_KEY_VAULT_" in str(val):
                    incoming_token = str(val).strip()
                    break

        token_valid, is_deanonymized, origin_ip = (False, False, None)
        if incoming_token:
            token_valid, is_deanonymized, origin_ip = check_deanon_token(incoming_token, client_ip)

        # 1. SENARYO: OUT-OF-BAND DEANONYMIZATION (VPN / Proxy Maskesi Düştü!)
        if token_valid and is_deanonymized:
            action_event = "ATTACKER_DEANONYMIZED"
            logger.critical(
                f"[DEANONYMIZER ALARMI] Saldırgan Maskesi Düştü! "
                f"VPN/Proxy İlk IP: {origin_ip} -> Gerçek/İkincil IP: {client_ip} | Token: {incoming_token}"
            )
            forensics = {
                "requested_path": req_path,
                "method": self.command,
                "user_agent": user_agent,
                "headers": headers_dump,
                "trigger": "OUT_OF_BAND_DEANONYMIZATION_SUCCESS",
                "compromised_token": incoming_token,
                "origin_vpn_proxy_ip": origin_ip,
                "deanonymized_real_ip": client_ip,
                "attribution_note": "Saldırgan çaldığı kimlik bilgisini farklı bir ağdan tetikledi, fail tespiti doğrulandı.",
                "threat_level": "MAXIMUM_ATTRIBUTION"
            }
            response_body = json.dumps({
                "status": "error",
                "code": 403,
                "message": "Access Denied: Node authentication failed."
            }).encode("utf-8")
            content_type = "application/json"

        # 2. SENARYO: Standart Canary Token Tetiklendi (Aynı IP)
        elif token_valid or BASE_CANARY_ENDPOINT in req_path:
            action_event = "CANARY_TOKEN_TRIGGERED"
            logger.critical(f"[CANARY ALARMI] Çalınan Zehirli Yem Kullanıldı! IP: {client_ip} | İstek: {req_path}")
            forensics = {
                "requested_path": req_path,
                "method": self.command,
                "user_agent": user_agent,
                "headers": headers_dump,
                "trigger": "CANARY_HONEYTOKEN_MISUSE",
                "canary_token": incoming_token or "STATIC_VAULT_PROBE",
                "threat_level": "CRITICAL"
            }
            response_body = json.dumps({
                "status": "error",
                "code": 401,
                "message": "Invalid token session or unauthorized access."
            }).encode("utf-8")
            content_type = "application/json"

        # 3. SENARYO: Bulut Meta-Veri (AWS IMDS) Keşfi
        elif "meta-data" in req_path.lower():
            action_event = "CLOUD_METADATA_HARVESTING"
            logger.warning(f"[AWS YEM TUZAĞI] Bulut Meta-Veri Keşfi Tespit Edildi! IP: {client_ip} | İstek: {req_path}")

            aws_fake_creds = get_or_create_aws_creds(client_ip, req_path)

            forensics = {
                "requested_path": req_path,
                "method": self.command,
                "user_agent": user_agent,
                "headers": headers_dump,
                "trigger": "CLOUD_METADATA_API_PROBE",
                "generated_access_key": aws_fake_creds["AccessKeyId"],
                "honey_token": "AWS_IAM_CREDENTIALS_LEAK",
                "threat_level": "HIGH"
            }
            response_body = json.dumps(aws_fake_creds, indent=2).encode("utf-8")
            content_type = "application/json"

        # 4. SENARYO: Genel İstek (.env sızdırma yemi)
        else:
            action_event = "INTERACTED_AND_ISOLATED"
            logger.warning(f"[YEM SERVİSİ ETKİLEŞİMİ] Saldırgan IP: {client_ip} | İstek: {req_path}")

            # Her saldırgana özel dinamik Canary Token içeren .env üret
            custom_env = generate_custom_env(client_ip)

            forensics = {
                "requested_path": req_path,
                "method": self.command,
                "user_agent": user_agent,
                "headers": headers_dump,
                "trigger": "HIGH_INTERACTION_DECOY_ENV_TRAP",
                "honey_token": "DYNAMIC_DEANON_TOKEN_INJECTED"
            }
            response_body = custom_env.encode("utf-8")
            content_type = "text/plain; charset=utf-8"

        # 1. SQLite Adli Kayıt (SHA-256 zinciriyle mühürlenir)
        try:
            db.log_incident(
                src_ip=client_ip,
                dst_port=80,
                protocol="HTTP",
                action=action_event,
                forensics=forensics
            )
        except Exception as e:
            logger.error(f"Veritabanı yazma hatası: {e}")

        # 2. Çekirdek Seviyesinde Tecrit (Deanonymize ve Canary için 2 Saat, diğerleri için 1 Saat)
        isolation_time = 7200 if (token_valid or is_deanonymized) else 3600
        try:
            self.blocker.isolate_ip(client_ip, timeout_seconds=isolation_time)
        except Exception as e:
            logger.error(f"Tecrit motoru hatası: {e}")

        # 3. Canlı WebSocket Yayını
        _, mitre_id, mitre_desc = attck_engine.resolve_mitre_ttp(80, "HTTP", action_event, forensics)
        payload = {
            "timestamp": now_str,
            "mitre_id": mitre_id,
            "mitre_technique": mitre_desc,
            "src_ip": client_ip,
            "ip": client_ip,
            "dst_port": 80,
            "port": 80,
            "protocol": "HTTP",
            "action": action_event,
            "event": action_event,
            "forensics": forensics
        }
        try:
            ws_manager.broadcast_threadsafe(payload)
        except Exception as e:
            logger.error(f"WebSocket yayın hatası: {e}")

        # 4. Yanıtı İstemciye İlet
        try:
            status_code = 403 if is_deanonymized else (401 if token_valid else 200)
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(response_body)))
            server_header = "EC2ws" if ("meta-data" in req_path.lower()) else "nginx/1.18.0 (Ubuntu)"
            self.send_header("Server", server_header)
            self.end_headers()
            self.wfile.write(response_body)
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
