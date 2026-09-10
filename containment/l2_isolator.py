import socket
import struct
import threading
import time
import logging
import ipaddress
import subprocess

logger = logging.getLogger("AED-DC.L2Isolator")

class L2SubnetIsolator:
    """
    Katman 2 (Data Link) Seviyesinde Ajan Kurulumsuz Karantina Motoru.
    Saldırganın ARP tablosunu zehirleyerek (Sinkhole) hem ağ geçidi (North-South)
    hem de yerel sunucularla (East-West) olan tüm L2 iletişimini dondurur.
    """
    SINKHOLE_MAC = "02:de:ad:be:ef:00"
    DECOY_VIP = "192.168.159.240"

    def __init__(self, interface: str = "ens33"):
        self.interface = interface
        self.active_isolations = {}
        self._lock = threading.Lock()
        self.gateway_ip, self.gateway_mac = self._detect_gateway()
        self.local_subnet = self._detect_local_subnet()
        self.server_ip = self._detect_server_ip()

    def _detect_server_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "192.168.159.133"

    def _detect_gateway(self):
        try:
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[0] == self.interface and fields[1] == "00000000":
                        gw_hex = fields[2]
                        gw_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                        # ARP tablosunda yoksa öğrenmeyi tetikle
                        subprocess.run(["ping", "-c", "1", "-W", "1", gw_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        gw_mac = self._resolve_mac_from_arp(gw_ip)
                        return gw_ip, gw_mac
        except Exception as e:
            logger.error(f"Ağ geçidi tespit hatası: {e}")
        return None, None

    def _detect_local_subnet(self):
        try:
            out = subprocess.check_output(f"ip -o -f inet addr show {self.interface}", shell=True).decode()
            for part in out.split():
                if "/" in part and not part.startswith("inet"):
                    return ipaddress.ip_network(part, strict=False)
        except Exception as e:
            logger.error(f"Alt ağ tespit hatası: {e}")
        return None

    def _resolve_mac_from_arp(self, ip_str: str) -> str:
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[0] == ip_str and fields[2] != "0x0":
                        return fields[3].lower()
        except Exception:
            pass
        return None

    def _mac_to_bytes(self, mac_str: str) -> bytes:
        return bytes.fromhex(mac_str.replace(":", ""))

    def _craft_arp_packet(self, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
        eth_header = self._mac_to_bytes(target_mac) + self._mac_to_bytes(sender_mac) + struct.pack("!H", 0x0806)
        arp_header = struct.pack(
            "!HHBBH6s4s6s4s",
            0x0001,
            0x0800,
            6,
            4,
            0x0002,
            self._mac_to_bytes(sender_mac),
            socket.inet_aton(sender_ip),
            self._mac_to_bytes(target_mac),
            socket.inet_aton(target_ip)
        )
        return eth_header + arp_header

    def _send_raw_arp(self, packet: bytes):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
            s.bind((self.interface, 0))
            s.send(packet)
            s.close()
        except Exception:
            pass

    def _isolation_worker(self, target_ip: str, target_mac: str, timeout_seconds: int):
        start_time = time.time()
        logger.warning(f"[L2 KARANTİNA] {target_ip} [{target_mac}] için L2 Sinkhole devrede.")

        while time.time() - start_time < timeout_seconds:
            with self._lock:
                if target_ip not in self.active_isolations:
                    break

            # 1. Saldırgana zehirli paket: "Ağ Geçidi = 02:de:ad:be:ef:00"
            if self.gateway_ip:
                poison_gw = self._craft_arp_packet(
                    sender_mac=self.SINKHOLE_MAC,
                    sender_ip=self.gateway_ip,
                    target_mac=target_mac,
                    target_ip=target_ip
                )
                self._send_raw_arp(poison_gw)

            # 2. Saldırgana zehirli paket: "Yem Sunucu (192.168.159.240) = 02:de:ad:be:ef:00"
            poison_decoy = self._craft_arp_packet(
                sender_mac=self.SINKHOLE_MAC,
                sender_ip=self.DECOY_VIP,
                target_mac=target_mac,
                target_ip=target_ip
            )
            self._send_raw_arp(poison_decoy)

            # 3. Ağ geçidine saldırganı izole eden anons
            if self.gateway_mac and self.gateway_ip:
                poison_gw_table = self._craft_arp_packet(
                    sender_mac=self.SINKHOLE_MAC,
                    sender_ip=target_ip,
                    target_mac=self.gateway_mac,
                    target_ip=self.gateway_ip
                )
                self._send_raw_arp(poison_gw_table)

            time.sleep(2)

        self.release_isolation(target_ip)

    def isolate_l2(self, target_ip: str, timeout_seconds: int = 3600) -> bool:
        if not self.local_subnet:
            return False

        try:
            ip_obj = ipaddress.ip_address(target_ip)
            if ip_obj not in self.local_subnet or target_ip in (self.gateway_ip, "127.0.0.1", self.DECOY_VIP, self.server_ip):
                return False
        except Exception:
            return False

        target_mac = self._resolve_mac_from_arp(target_ip)
        if not target_mac or target_mac == "00:00:00:00:00:00":
            subprocess.run(["ping", "-c", "1", "-W", "1", target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            target_mac = self._resolve_mac_from_arp(target_ip)

        if not target_mac:
            return False

        with self._lock:
            if target_ip in self.active_isolations:
                return True
            t = threading.Thread(target=self._isolation_worker, args=(target_ip, target_mac, timeout_seconds), daemon=True)
            self.active_isolations[target_ip] = (t, target_mac)
            t.start()

        return True

    def release_isolation(self, target_ip: str):
        target_mac = None
        with self._lock:
            if target_ip in self.active_isolations:
                _, target_mac = self.active_isolations.pop(target_ip)

        if target_mac:
            logger.info(f"[L2 ONARIM] {target_ip} için iyileştirici ARP gönderiliyor.")
            real_server_mac = self._resolve_mac_from_arp(self.server_ip) or self._get_interface_mac()
            if real_server_mac:
                heal_decoy = self._craft_arp_packet(
                    sender_mac=real_server_mac,
                    sender_ip=self.DECOY_VIP,
                    target_mac=target_mac,
                    target_ip=target_ip
                )
                for _ in range(3):
                    self._send_raw_arp(heal_decoy)
                    time.sleep(0.1)

    def _get_interface_mac(self):
        try:
            with open(f"/sys/class/net/{self.interface}/address", "r") as f:
                return f.read().strip().lower()
        except Exception:
            return None

l2_isolator = L2SubnetIsolator()
