import sys
import os

# Projenin ana kök dizinini Python arama yoluna ekliyoruz
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import yaml
import json
import logging
from datetime import datetime, timezone
from scapy.all import sniff, IP, TCP
from containment.blocker import NftablesContainment

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class SecurityEngine:
    def __init__(self, config_path="config/config.yaml"):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.interface = self.config["network"]["interface"]
        self.decoy_ips = set(self.config["network"]["decoy_ips"])
        self.whitelist = set(self.config["whitelist"]["ips"])
        self.log_file = self.config["logging"]["log_file"]

        # nftables izolasyon motoru
        self.blocker = NftablesContainment(
            table_name=self.config["containment"]["table_name"],
            chain_name=self.config["containment"]["chain_name"]
        )

    def _log_incident(self, incident):
        logging.warning(f"(!) TEHDİT ETKİSİZ HALE GETİRİLDİ: {incident['src_ip']} -> {incident['dst_ip']}:{incident['dst_port']}")
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(incident) + "\n")
        except Exception as e:
            logging.error(f"Kayıt hatası: {e}")

    def handle_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

        # Beyaz listedeki IP'leri atla
        if src_ip in self.whitelist:
            return

        # Yalnızca tuzak IP'ye gelen SYN bağlantı denemeleri
        if tcp_flags == "S" and dst_ip in self.decoy_ips:
            # 80 portuna gelen istekleri hemen düşürme; sahte web servisi delil toplasın
            if dst_port == 80:
                return

            # Port 80 dışındaki diğer portlara yapılan taramaları doğrudan tecrit et
            incident = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": src_ip,
                "src_port": packet[TCP].sport,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "action": "AUTO_ISOLATED"
            }
            
            if self.config["containment"]["enabled"]:
                self.blocker.isolate_ip(src_ip)

            self._log_incident(incident)

    def start(self):
        ip_filters = " or ".join([f"dst host {ip}" for ip in self.decoy_ips])
        bpf_filter = f"tcp and ({ip_filters})"
        
        logging.info(f"[*] AED-DC Motoru Devrede.")
        logging.info(f"[*] Dinlenen Arayüz: {self.interface} | BPF Filtresi: {bpf_filter}")
        
        sniff(
            iface=self.interface,
            filter=bpf_filter,
            prn=self.handle_packet,
            store=False
        )

if __name__ == "__main__":
    engine = SecurityEngine()
    engine.start()
