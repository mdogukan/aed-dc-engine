import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import yaml
import json
import logging
from datetime import datetime, timezone
from scapy.all import sniff, IP, TCP
from containment.blocker import NftablesContainment
from database.db import IncidentDatabase

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

class SecurityEngine:
    def __init__(self, config_path="config/config.yaml"):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.interface = self.config["network"]["interface"]
        self.decoy_ips = set(self.config["network"]["decoy_ips"])
        self.whitelist = set(self.config["whitelist"]["ips"])
        self.log_file = self.config["logging"]["log_file"]

        self.blocker = NftablesContainment(
            table_name=self.config["containment"]["table_name"],
            chain_name=self.config["containment"]["chain_name"]
        )
        self.db = IncidentDatabase()

    def _log_incident(self, incident):
        logging.warning(f"(!) PORT TARAMASI ENGELLENDİ: {incident['src_ip']} -> {incident['dst_ip']}:{incident['dst_port']}")
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(incident) + "\n")
            # SQLite veritabanına da yaz
            self.db.add_incident(
                src_ip=incident['src_ip'],
                src_port=incident['src_port'],
                dst_ip=incident['dst_ip'],
                dst_port=incident['dst_port'],
                service_type="RAW_PORT_SCAN",
                action=incident['action']
            )
        except Exception as e:
            logging.error(f"Kayıt hatası: {e}")

    def handle_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags

        if src_ip in self.whitelist:
            return

        if tcp_flags == "S" and dst_ip in self.decoy_ips:
            if dst_port in [80, 22]:
                return

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
        
        logging.info(f"[*] AED-DC Çekirdek Dinleyicisi Devrede | Filtre: {bpf_filter}")
        
        sniff(
            iface=self.interface,
            filter=bpf_filter,
            prn=self.handle_packet,
            store=False
        )

if __name__ == "__main__":
    engine = SecurityEngine()
    engine.start()
