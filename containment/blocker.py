import subprocess
import logging
import re

logger = logging.getLogger("AED-DC.Containment")

class NftablesContainment:
    def __init__(self, table="aed_filter", chain="aed_isolation", set_name="isolated_ips"):
        self.table = table
        self.chain = chain
        self.set_name = set_name
        self.target_ip = "192.168.159.240"
        self._initialize_subsystem()

    def _run_cmd(self, cmd_args):
        try:
            res = subprocess.run(cmd_args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"nftables hatası: {' '.join(cmd_args)} | Hata: {e.stderr.strip()}")
            return None

    def _initialize_subsystem(self):
        # 1. Temel Filtre Tablosu ve Tecrit Zinciri (Orijinal Yapı)
        subprocess.run(["nft", "add", "table", "inet", self.table], stderr=subprocess.DEVNULL)
        subprocess.run(["nft", "add", "set", "inet", self.table, self.set_name, "{", "type", "ipv4_addr;", "flags", "timeout;", "}"], stderr=subprocess.DEVNULL)
        subprocess.run(["nft", "add", "chain", "inet", self.table, self.chain, "{", "type", "filter", "hook", "prerouting", "priority", "-150;", "policy", "accept;", "}"], stderr=subprocess.DEVNULL)
        
        check_rule = subprocess.run(["nft", "list", "chain", "inet", self.table, self.chain], stdout=subprocess.PIPE, text=True)
        if f"@{self.set_name} drop" not in check_rule.stdout:
            self._run_cmd(["nft", "add", "rule", "inet", self.table, self.chain, "ip", "saddr", f"@{self.set_name}", "drop"])
            logger.info(f"[*] Çekirdek İzolasyon Kuralı Aktif: inet {self.table} -> @{self.set_name} drop")

        # 2. Port Tarama Bataklığı (NAT Yönlendirmesi)
        subprocess.run(["nft", "add", "chain", "inet", self.table, "nat_prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "dstnat;", "policy", "accept;", "}"], stderr=subprocess.DEVNULL)
        
        check_nat = subprocess.run(f"nft list chain inet {self.table} nat_prerouting 2>/dev/null | grep 'redirect to :8888'", shell=True, stdout=subprocess.PIPE, text=True)
        if "redirect to :8888" not in check_nat.stdout:
            nat_cmd = f"nft add rule inet {self.table} nat_prerouting ip daddr {self.target_ip} tcp dport != {{ 22, 80, 8000, 8888 }} redirect to :8888"
            subprocess.run(nat_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            logger.info("[*] Çekirdek NAT Bataklığı Aktif: Hedef Portlar -> :8888 Tarpit")

    def isolate_ip(self, ip: str, timeout_seconds: int = 3600) -> bool:
        cmd = ["nft", "add", "element", "inet", self.table, self.set_name, "{", ip, "timeout", f"{timeout_seconds}s", "}"]
        result = self._run_cmd(cmd)
        if result is not None:
            logger.warning(f"[ÇEKİRDEK TECRİT] {ip} adresi {timeout_seconds}s süreyle kilitlendi.")
            return True
        return False

    def unblock_ip(self, ip: str) -> bool:
        cmd = ["nft", "delete", "element", "inet", self.table, self.set_name, "{", ip, "}"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            logger.info(f"[ÇEKİRDEK ENGEL KALKTI] {ip} serbest bırakıldı.")
            return True
        
        cmd_shell = f"nft delete element inet {self.table} {self.set_name} '{{ {ip} }}'"
        res2 = subprocess.run(cmd_shell, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res2.returncode == 0 or ip not in self.get_blocked_ips():
            logger.info(f"[ÇEKİRDEK ENGEL KALKTI] {ip} serbest bırakıldı.")
            return True

        return False

    def flush_all(self) -> bool:
        cmd = ["nft", "flush", "set", "inet", self.table, self.set_name]
        result = self._run_cmd(cmd)
        if result is not None:
            logger.info(f"[TÜM ENGELLER KALKTI] @{self.set_name} sıfırlandı.")
            return True
        return False

    def get_blocked_details(self) -> list[dict]:
        cmd = ["nft", "list", "set", "inet", self.table, self.set_name]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True)
            elements_match = re.search(r'elements\s*=\s*\{([^}]+)\}', res.stdout, re.DOTALL)
            if not elements_match:
                return []
            
            raw_content = elements_match.group(1)
            pattern = re.compile(r'(\b\d{1,3}(?:\.\d{1,3}){3}\b)(?:\s+timeout\s+([^\s,]+))?(?:\s+expires\s+([^\s,}]+))?')
            details = []
            for match in pattern.finditer(raw_content):
                ip = match.group(1)
                timeout = match.group(2) or "1h"
                expires = match.group(3) or "-"
                if not ip.startswith("0.") and not ip.startswith("127."):
                    details.append({
                        "ip": ip,
                        "rule": "DROP",
                        "timeout": timeout,
                        "expires": expires
                    })
            return details
        except Exception:
            return []

    def get_blocked_ips(self) -> list[str]:
        return [d["ip"] for d in self.get_blocked_details()]

    # Uyumluluk aliasları (tüm modüllerle tam uyum için)
    block_ip = isolate_ip
    remove_ip = unblock_ip
    unblock_all = flush_all
    get_blocked_ips_detailed = get_blocked_details

# Singleton nesneler
nft_blocker = NftablesContainment()
blocker = nft_blocker
