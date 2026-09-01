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
            logging.error(f"nftables hatası: {e.stderr.strip()}")
            return None

    def _init_firewall(self):
        """İzolasyon için özel nftables tablosunu ve filtre zincirini hazırlar."""
        self._run_cmd(f"nft add table inet {self.table_name}")
        self._run_cmd(f"nft 'add chain inet {self.table_name} {self.chain_name} {{ type filter hook input priority -100; policy accept; }}'")
        logging.info(f"[*] nftables '{self.table_name}' tablosu ve '{self.chain_name}' zinciri devrede.")

    def isolate_ip(self, ip_address):
        """Saldırgan IP adresini çekirdek düzeyinde tüm portlar için istisnasız kilitler."""
        rules = self.get_blocked_ips()
        if ip_address in rules:
            logging.info(f"[!] {ip_address} adresi zaten tecrit altında.")
            return False

        # En üst öncelikli DROP kuralı
        cmd = f"nft insert rule inet {self.table_name} {self.chain_name} ip saddr {ip_address} counter drop"
        res = self._run_cmd(cmd)
        if res is not None:
            logging.warning(f"[BLOKLANDI] Saldırgan IP: {ip_address} çekirdek seviyesinde tamamen izole edildi!")
            return True
        return False

    def release_ip(self, ip_address):
        """Çekirdekteki kuralı bularak IP'nin engelini kaldırır."""
        rules_output = self._run_cmd(f"nft -a list chain inet {self.table_name} {self.chain_name}")
        if not rules_output:
            return False

        for line in rules_output.splitlines():
            if ip_address in line and "drop" in line and "handle" in line:
                handle_id = line.split("handle")[-1].strip()
                self._run_cmd(f"nft delete rule inet {self.table_name} {self.chain_name} handle {handle_id}")
                logging.info(f"[SERBEST] {ip_address} engel kaldırıldı.")
                return True
        return False

    def get_blocked_ips(self):
        """Şu an çekirdekte engelli olan tüm IP adreslerini liste olarak döner."""
        rules_output = self._run_cmd(f"nft list chain inet {self.table_name} {self.chain_name}")
        blocked = []
        if rules_output:
            for line in rules_output.splitlines():
                if "ip saddr" in line and "drop" in line:
                    parts = line.split()
                    idx = parts.index("saddr")
                    blocked.append(parts[idx + 1])
        return blocked
