import re
from collections import defaultdict

from scapy.all import ARP, IP, TCP, Raw, Ether, sniff

from src.tp1.utils.lib import choose_interface


# Detection thresholds
PORT_SCAN_THRESHOLD = 10
SYN_FLOOD_THRESHOLD = 80

# SQL Injection patterns to look for in TCP payloads
SQL_PATTERNS = [
    r"(?i)union\s+select",
    r"(?i)drop\s+table",
    r"(?i)'\s*(or|and)\s*'?1'?\s*=\s*'?1",
    r"(?i)'\s*--",
    r"(?i)1=1",
]


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []
        self.protocols = {}
        self.alerts = []
        # Internal accumulators for stateful detection
        self._syn_per_ip = defaultdict(int)
        self._ports_per_ip = defaultdict(set)
        self._arp_table = {}  # ip -> mac

    def capture_trafic(self) -> None:
        """
        Capture network trafic from an interface
        """
        interface = self.interface

        self.packets = list(
            sniff(iface=interface, count=150, timeout=30, store=1)
        )

    def sort_network_protocols(self) -> None:
        """
        Sort and return all captured network protocols
        """
        counters = defaultdict(int)
        for pkt in self.packets:
            layer = pkt
            while layer and layer.__class__.__name__ != "NoPayload":
                counters[layer.__class__.__name__] += 1
                layer = layer.payload if hasattr(layer, "payload") else None
        self.protocols = dict(counters)

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        return self.protocols

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un trafic est illégitime (exemple : Injection SQL, ARP
        Spoofing, etc)
        a. Noter la tentative d'attaque.
        b. Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c. (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon afficher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()

        self.alerts = []
        for pkt in self.packets:
            self._check_arp_spoofing(pkt)
            self._check_syn_flood(pkt)
            self._check_port_scan(pkt)
            self._check_sql_injection(pkt)

        if self.alerts:
            for alert in self.alerts:
                print(f"[ALERT] {alert['type']} | IP: {alert['src_ip']} | MAC: {alert['src_mac']} | {alert['detail']}")
        else:
            print("All good — no illegitimate traffic detected.")

        self.summary = self.gen_summary()

    def get_summary(self) -> str:
        return self.summary

    def gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        summary += f"Packets captured: {len(self.packets)}\n"
        summary += f"Interface: {self.interface}\n\n"
        summary += "Protocols detected:\n"
        for proto, count in sorted(self.protocols.items(), key=lambda x: -x[1]):
            summary += f"  {proto}: {count} packet(s)\n"
        summary += "\n"
        if self.alerts:
            summary += f"{len(self.alerts)} alert(s) detected:\n"
            for alert in self.alerts:
                summary += f"  [{alert['type']}] {alert['detail']}\n"
                summary += f"    IP: {alert['src_ip']} | MAC: {alert['src_mac']}\n"
        else:
            summary += "No illegitimate traffic detected.\n"
        return summary

    # --- Detection rules ---

    def _check_arp_spoofing(self, pkt) -> None:
        """Detect ARP Spoofing: same IP claimed by a different MAC."""
        if not pkt.haslayer(ARP):
            return
        if pkt[ARP].op != 2:
            return
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        if src_ip in self._arp_table and self._arp_table[src_ip] != src_mac:
            self._record_alert(
                "ARP Spoofing", "ARP", src_ip, src_mac,
                f"IP {src_ip} claimed by {src_mac} (was {self._arp_table[src_ip]})"
            )
        else:
            self._arp_table[src_ip] = src_mac

    def _check_syn_flood(self, pkt) -> None:
        """Detect SYN Flood: too many SYN packets from the same IP."""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        if pkt[TCP].flags != "S":
            return
        src_ip = pkt[IP].src
        self._syn_per_ip[src_ip] += 1
        if self._syn_per_ip[src_ip] == SYN_FLOOD_THRESHOLD:
            self._record_alert(
                "SYN Flood", "TCP", src_ip, self._get_mac(pkt),
                f"{SYN_FLOOD_THRESHOLD} SYN packets received from {src_ip}"
            )

    def _check_port_scan(self, pkt) -> None:
        """Detect port scan: one IP contacts too many distinct ports."""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return
        src_ip = pkt[IP].src
        self._ports_per_ip[src_ip].add(pkt[TCP].dport)
        if len(self._ports_per_ip[src_ip]) == PORT_SCAN_THRESHOLD:
            self._record_alert(
                "Port Scan", "TCP", src_ip, self._get_mac(pkt),
                f"{PORT_SCAN_THRESHOLD} distinct ports scanned from {src_ip}"
            )

    def _check_sql_injection(self, pkt) -> None:
        """Detect SQL Injection patterns in raw TCP payload."""
        if not (pkt.haslayer(Raw) and pkt.haslayer(IP)):
            return
        try:
            payload = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
        except Exception:
            return
        for pattern in SQL_PATTERNS:
            if re.search(pattern, payload):
                self._record_alert(
                    "SQL Injection", "TCP/HTTP", pkt[IP].src, self._get_mac(pkt),
                    f"Suspicious pattern detected in payload from {pkt[IP].src}"
                )
                break

    def _record_alert(self, attack_type, protocol, src_ip, src_mac, detail) -> None:
        """Record an alert (deduplicated by type + IP)."""
        for a in self.alerts:
            if a["type"] == attack_type and a["src_ip"] == src_ip:
                return
        self.alerts.append({
            "type": attack_type,
            "protocol": protocol,
            "src_ip": src_ip,
            "src_mac": src_mac,
            "detail": detail,
        })

    @staticmethod
    def _get_mac(pkt) -> str:
        return pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
