import subprocess
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class NftablesContainment:
    def __init__(self, table_name="aed_filter", chain_name="aed_isolation"):
        self.table_name = table_name
        self.chain_name = chain_name
        self._init_firewall()

    def _run_cmd(self, cmd):
        try:
            res = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"nftables komut hatası: {e.stderr.strip()}")
            return None

    def _init_firewall(self):
        """İzolasyon için özel nftables tablosunu ve filtre zincirini oluşturur."""
        self._run_cmd(f"nft add table inet {self.table_name}")
        self._run_cmd(f"nft 'add chain inet {self.table_name} {self.chain_name} {{ type filter hook input priority -100; policy accept; }}'")
        logging.info(f"[*] nftables '{self.table_name}' tablosu ve '{self.chain_name}' zinciri devrede.")

    def isolate_ip(self, ip_address):
        """Saldırgan IP adresini çekirdek düzeyinde DROP kuralıyla anında kilitler."""
        rule_check = self._run_cmd(f"nft list chain inet {self.table_name} {self.chain_name}")
        if rule_check and ip_address in rule_check:
            logging.info(f"[!] {ip_address} adresi zaten tecrit altında.")
            return False

        # Öncelikli paket düşürme kuralı ekleniyor
        cmd = f"nft insert rule inet {self.table_name} {self.chain_name} ip saddr {ip_address} counter drop"
        res = self._run_cmd(cmd)
        if res is not None:
            logging.warning(f"[BLOKLANDI] Saldırgan IP: {ip_address} çekirdek seviyesinde deterministik olarak izole edildi!")
            return True
        return False
