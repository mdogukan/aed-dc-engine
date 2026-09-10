import subprocess
import logging
import threading
from containment.l2_isolator import l2_isolator

logger = logging.getLogger("AED-DC.Blocker")

class NftablesContainment:
    def __init__(self, table: str = "inet aed_filter", chain: str = "aed_input", set_name: str = "isolated_ips", *args, **kwargs):
        self.nft_table = "inet aed_filter"
        self.nft_chain = chain
        self.nft_set = set_name

    def isolate_ip(self, ip_address: str, timeout_seconds: int = 3600):
        """IP adresini hem nftables çekirdek filtresine ekler hem de L2 seviyesinde izole eder."""
        try:
            cmd = ["nft", "add", "element", "inet", "aed_filter", "isolated_ips", "{", ip_address, "}"]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.warning(f"[ÇEKİRDEK TECRİT] {ip_address} adresi {timeout_seconds}s süreyle kilitlendi.")
        except Exception as e:
            logger.error(f"nftables kural hatası: {e}")

        try:
            l2_isolator.isolate_l2(ip_address, timeout_seconds)
        except Exception as e:
            logger.error(f"L2 tecrit hatası: {e}")

    def release_ip(self, ip_address: str):
        """IP adresinin hem nftables hem de L2 karantinasını kaldırır."""
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

    def flush_all(self):
        """Tüm engelleri ve L2 izolasyonlarını temizler."""
        try:
            subprocess.run(["nft", "flush", "set", "inet", "aed_filter", "isolated_ips"], check=True)
            logger.info("[TÜM ENGELLER KALDIRILDI] Çekirdek tecrit listesi temizlendi.")
        except Exception as e:
            logger.error(f"Flush hatası: {e}")

        with l2_isolator._lock:
            active_ips = list(l2_isolator.active_isolations.keys())
        for ip in active_ips:
            l2_isolator.release_isolation(ip)

containment_blocker = NftablesContainment()
