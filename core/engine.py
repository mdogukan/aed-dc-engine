import os
import yaml
import json
import time
import logging
from datetime import datetime, timezone
from collections import defaultdict
from scapy.all import sniff, IP, TCP, ICMP
from containment.blocker import NftablesContainment
from database.db import IncidentDatabase
from api.ws_manager import live_broadcaster

logger = logging.getLogger("AED-DC.Engine")

class SecurityEngine:
    def __init__(self, config_path=None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        if config_path is None:
            candidate_1 = os.path.join(base_dir, "config", "config.yaml")
            candidate_2 = os.path.join(base_dir, "config.yaml")
            config_path = candidate_1 if os.path.exists(candidate_1) else candidate_2

        self.config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    self.config = yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Config okunamadı: {e}")

        net_cfg = self.config.get("network", {})
        self.decoy_ip = net_cfg.get("decoy_ip", "192.168.159.240")
        self.interface = net_cfg.get("interface", "ens33")

        cont_cfg = self.config.get("containment", {})
        table_name = cont_cfg.get("table_name", "aed_filter")
        chain_name = cont_cfg.get("chain_name", "aed_isolation")

        self.blocker = NftablesContainment(table=table_name, chain=chain_name)
        self.db = IncidentDatabase()
        self.log_file = os.path.join(base_dir, "logs", "detections.json")

        self.icmp_tracker = defaultdict(list)
        self.syn_tracker = defaultdict(list)

    def _is_rate_exceeded(self, tracker_dict: dict, ip: str, window_seconds: int = 5, threshold: int = 5) -> bool:
        now = time.time()
        tracker_dict[ip] = [t for t in tracker_dict[ip] if now - t <= window_seconds]
        tracker_dict[ip].append(now)
        return len(tracker_dict[ip]) >= threshold

    def _process_packet(self, packet):
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if dst_ip != self.decoy_ip or src_ip == self.decoy_ip:
                return

            current_ts = datetime.now(timezone.utc).isoformat()

            # 1. ICMP Keşfi (Ping)
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                if icmp_type == 8:
                    forensics = {
                        "icmp_type": 8,
                        "icmp_code": packet[ICMP].code,
                        "ip_ttl": packet[IP].ttl
                    }

                    if self._is_rate_exceeded(self.icmp_tracker, src_ip, window_seconds=5, threshold=5):
                        action_text = "ISOLATED (PING_FLOOD)"
                        event_type = "ATTACK_ISOLATED"
                        logger.warning(f"[AGRESİF KEŞİF TECRİT] {src_ip} -> Çekirdeğe kilitlendi.")
                        self.blocker.isolate_ip(src_ip, timeout_seconds=3600)
                    else:
                        action_text = "RECON_DETECTED"
                        event_type = "RECON_DETECTED"
                        logger.info(f"[SESSİZ GÖZLEM] {src_ip} -> ICMP Keşif pinglemesi yakalandı.")

                    self.db.add_incident(
                        src_ip=src_ip,
                        src_port=0,
                        dst_ip=dst_ip,
                        dst_port=0,
                        service_type="ICMP",
                        action=action_text,
                        forensics=forensics
                    )

                    live_broadcaster.broadcast_from_thread({
                        "event": event_type,
                        "timestamp": current_ts,
                        "src_ip": src_ip,
                        "dst_port": 0,
                        "protocol": "ICMP",
                        "action": action_text,
                        "forensics": forensics
                    })
                    return

            if src_ip in self.blocker.get_blocked_ips():
                return

            # 2. TCP Port Taraması (SYN Scan)
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)

                if "S" in flags and "A" not in flags:
                    if dst_port not in [80, 22]:
                        forensics = {
                            "tcp_flags": flags,
                            "window_size": tcp_layer.window,
                            "ip_ttl": packet[IP].ttl,
                            "payload_len": len(packet[TCP].payload)
                        }

                        if self._is_rate_exceeded(self.syn_tracker, src_ip, window_seconds=5, threshold=3):
                            action_text = "ISOLATED (PORT_SCAN)"
                            event_type = "ATTACK_ISOLATED"
                            logger.warning(f"[PORT TARAMASI TECRİT] {src_ip} -> Çekirdeğe kilitlendi.")
                            self.blocker.isolate_ip(src_ip, timeout_seconds=3600)
                        else:
                            action_text = "PROBE_DETECTED"
                            event_type = "PROBE_DETECTED"
                            logger.info(f"[PORT YOKLAMA] {src_ip} -> Hedef port: {dst_port}")

                        self.db.add_incident(
                            src_ip=src_ip,
                            src_port=tcp_layer.sport,
                            dst_ip=dst_ip,
                            dst_port=dst_port,
                            service_type="TCP_SCAN",
                            action=action_text,
                            forensics=forensics
                        )

                        live_broadcaster.broadcast_from_thread({
                            "event": event_type,
                            "timestamp": current_ts,
                            "src_ip": src_ip,
                            "dst_port": dst_port,
                            "protocol": "TCP/SYN",
                            "action": action_text,
                            "forensics": forensics
                        })
        except Exception as e:
            logger.error(f"Paket işleme hatası: {e}")

    def run(self):
        bpf_filter = f"dst host {self.decoy_ip}"
        logger.info(f"[*] Çekirdek Sniffer Aktif | Arayüz: {self.interface} | Filtre: '{bpf_filter}'")
        try:
            sniff(iface=self.interface, filter=bpf_filter, prn=self._process_packet, store=0)
        except Exception as e:
            logger.error(f"Sniffer hatası: {e}")
