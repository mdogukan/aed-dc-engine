import subprocess
import logging
import threading
import time
import re
from containment.l2_isolator import l2_isolator

logger = logging.getLogger("AED-DC.Blocker")

class NftablesContainment:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(NftablesContainment, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, table: str = "inet aed_filter", chain: str = "aed_isolation", set_name: str = "isolated_ips", *args, **kwargs):
        if self._initialized:
            return
        self.nft_table = "inet aed_filter"
        self.nft_chain = chain
        self.nft_set = set_name
        self.active_blocks = {}
        self._lock = threading.Lock()
        self._init_nftables()
        self._initialized = True

    def _init_nftables(self):
        """Çekirdekte tablo ve küme yoksa otomatik oluşturur."""
        try:
            subprocess.run(["nft", "add", "table", "inet", "aed_filter"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nft", "add", "chain", "inet", "aed_filter", "aed_isolation", "{ type filter hook input priority -100; policy accept; }"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nft", "add", "set", "inet", "aed_filter", "isolated_ips", "{ type ipv4_addr; }"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nft", "add", "rule", "inet", "aed_filter", "aed_isolation", "ip", "saddr", "@isolated_ips", "drop"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.error(f"nftables otomatik kurulum hatası: {e}")

    def isolate_ip(self, ip_address: str, timeout_seconds: int = 3600):
        """IP adresini hem belleğe hem nftables'a hem de L2 karantinasına yazar."""
        with self._lock:
            self.active_blocks[ip_address] = time.time() + timeout_seconds

        try:
            cmd = ["nft", "add", "element", "inet", "aed_filter", "isolated_ips", "{", ip_address, "}"]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.warning(f"[ÇEKİRDEK TECRİT] {ip_address} adresi {timeout_seconds}s süreyle kilitlendi.")
        except Exception as e:
            logger.error(f"nftables kural hatası: {e}")

        try:
            l2_isolator.isolate_l2(ip_address, timeout_seconds)
        except Exception as e:
            logger.error(f"L2 tecrit hatası: {e}")

    def release_ip(self, ip_address: str):
        """IP engelini kaldırır."""
        with self._lock:
            if ip_address in self.active_blocks:
                del self.active_blocks[ip_address]

        try:
            cmd = ["nft", "delete", "element", "inet", "aed_filter", "isolated_ips", "{", ip_address, "}"]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"[ÇEKİRDEK ENGEL KALKTI] {ip_address} serbest bırakıldı.")
        except Exception as e:
            logger.error(f"nftables silme hatası: {e}")

        try:
            l2_isolator.release_isolation(ip_address)
        except Exception as e:
            logger.error(f"L2 serbest bırakma hatası: {e}")

        return True

    def unblock_ip(self, ip_address: str) -> bool:
        return self.release_ip(ip_address)

    def flush_all(self) -> bool:
        with self._lock:
            self.active_blocks.clear()

        try:
            subprocess.run(["nft", "flush", "set", "inet", "aed_filter", "isolated_ips"], check=True)
            logger.info("[TÜM ENGELLER KALDIRILDI] Çekirdek tecrit listesi temizlendi.")
        except Exception as e:
            logger.error(f"Flush hatası: {e}")

        with l2_isolator._lock:
            active_ips = list(l2_isolator.active_isolations.keys())
        for ip in active_ips:
            l2_isolator.release_isolation(ip)

        return True

    def get_blocked_details(self):
        now = time.time()
        details = []
        with self._lock:
            expired = [ip for ip, exp in self.active_blocks.items() if exp <= now]
            for ip in expired:
                del self.active_blocks[ip]

            for ip, exp in self.active_blocks.items():
                rem = int(exp - now)
                details.append({
                    "ip": ip,
                    "expires": f"{rem}s" if rem > 0 else "0s"
                })
        return details

containment_blocker = NftablesContainment()
