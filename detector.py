"""NetShield IDS - packet capture + rule engine."""
import time
import threading
from collections import defaultdict, Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ---------------- CONFIG (change thresholds here) ----------------
CONFIG = {
    "WINDOW": 10,                 # seconds
    "PORT_SCAN_LIMIT": 15,        # distinct ports from one IP in WINDOW
    "SYN_LIMIT": 100,             # SYN packets from one IP in WINDOW
    "ICMP_LIMIT": 50,             # ping requests from one IP in WINDOW
    "BLACKLIST": {"203.0.113.66", "198.51.100.23"},
    "SUSPICIOUS_PORTS": {23: "Telnet", 4444: "Metasploit default", 31337: "Back Orifice"},
    "LOG_FILE": "alerts.log",
}

SEVERITY = {
    "Port Scan": "High",
    "SYN Flood": "Critical",
    "ICMP Flood": "Medium",
    "Blacklisted IP": "High",
    "Suspicious Port": "Medium",
}

lock = threading.Lock()
ports_seen = defaultdict(list)    # ip -> [(time, port)]
syn_times = defaultdict(list)     # ip -> [time]
icmp_times = defaultdict(list)    # ip -> [time]
last_alert = {}                   # (kind, ip) -> time
alerts = []
proto_count = Counter()
src_count = Counter()
pps = defaultdict(int)            # second -> packets
total_packets = 0
started_at = time.time()


def raise_alert(kind, ip, detail=""):
    """Store an alert (max one per kind+IP every WINDOW seconds)."""
    now = time.time()
    key = (kind, ip)
    if now - last_alert.get(key, 0) < CONFIG["WINDOW"]:
        return
    last_alert[key] = now
    alert = {
        "time": time.strftime("%H:%M:%S"),
        "type": kind,
        "source": ip,
        "severity": SEVERITY.get(kind, "Low"),
        "detail": detail,
    }
    alerts.append(alert)
    print(f"[ALERT] {kind} from {ip} - {detail}")
    try:
        with open(CONFIG["LOG_FILE"], "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {kind} | {ip} | {detail}\n")
    except OSError:
        pass


def process(pkt):
    """Called for every captured packet."""
    global total_packets
    if IP not in pkt:
        return
    now = time.time()
    src, win = pkt[IP].src, CONFIG["WINDOW"]

    with lock:
        total_packets += 1
        pps[int(now)] += 1
        src_count[src] += 1

        if TCP in pkt:
            proto_count["TCP"] += 1
        elif UDP in pkt:
            proto_count["UDP"] += 1
        elif ICMP in pkt:
            proto_count["ICMP"] += 1
        else:
            proto_count["Other"] += 1

        # Rule: blacklisted IP
        if src in CONFIG["BLACKLIST"]:
            raise_alert("Blacklisted IP", src, "Traffic from a blacklisted address")

        # Rules that use TCP SYN packets (new connection attempts)
        if TCP in pkt:
            dport = pkt[TCP].dport
            is_syn = int(pkt[TCP].flags) == 0x02

            if dport in CONFIG["SUSPICIOUS_PORTS"] and is_syn:
                raise_alert("Suspicious Port", src,
                            f"Connection to port {dport} ({CONFIG['SUSPICIOUS_PORTS'][dport]})")

            if is_syn:
                ports_seen[src].append((now, dport))
                ports_seen[src] = [(t, p) for t, p in ports_seen[src] if now - t < win]
                distinct = len({p for _, p in ports_seen[src]})
                if distinct > CONFIG["PORT_SCAN_LIMIT"]:
                    raise_alert("Port Scan", src, f"{distinct} distinct ports in {win}s")

                syn_times[src].append(now)
                syn_times[src] = [t for t in syn_times[src] if now - t < win]
                if len(syn_times[src]) > CONFIG["SYN_LIMIT"]:
                    raise_alert("SYN Flood", src, f"{len(syn_times[src])} SYN packets in {win}s")

        # Rule: ICMP flood (echo requests)
        if ICMP in pkt and pkt[ICMP].type == 8:
            icmp_times[src].append(now)
            icmp_times[src] = [t for t in icmp_times[src] if now - t < win]
            if len(icmp_times[src]) > CONFIG["ICMP_LIMIT"]:
                raise_alert("ICMP Flood", src, f"{len(icmp_times[src])} pings in {win}s")


def start_sniffer(iface=None):
    """Run the sniffer in a background thread."""
    def run():
        try:
            sniff(prn=process, store=False, iface=iface)
        except Exception as e:
            print(f"[ERROR] Sniffer stopped: {e}")
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def snapshot():
    """Data for the dashboard."""
    now = int(time.time())
    with lock:
        for s in [s for s in pps if s < now - 120]:
            del pps[s]
        by_type = Counter(a["type"] for a in alerts)
        return {
            "total_packets": total_packets,
            "total_alerts": len(alerts),
            "unique_attackers": len({a["source"] for a in alerts}),
            "uptime": int(time.time() - started_at),
            "alerts": alerts[-100:][::-1],
            "alerts_by_type": dict(by_type),
            "protocols": dict(proto_count),
            "top_sources": src_count.most_common(5),
            "timeline": {
                "labels": [time.strftime("%H:%M:%S", time.localtime(s)) for s in range(now - 59, now + 1)],
                "values": [pps.get(s, 0) for s in range(now - 59, now + 1)],
            },
        }


def reset():
    global total_packets
    with lock:
        alerts.clear(); ports_seen.clear(); syn_times.clear(); icmp_times.clear()
        last_alert.clear(); proto_count.clear(); src_count.clear(); pps.clear()
        total_packets = 0


def simulate(kind):
    """Inject fake attack packets so you can demo without a second device."""
    dst = "10.0.0.5"
    if kind == "portscan":
        for p in range(1, 31):
            process(IP(src="192.168.56.101", dst=dst) / TCP(dport=p, flags="S"))
    elif kind == "synflood":
        for i in range(130):
            process(IP(src="10.10.10.10", dst=dst) / TCP(sport=1000 + i, dport=80, flags="S"))
    elif kind == "icmp":
        for _ in range(60):
            process(IP(src="172.16.0.99", dst=dst) / ICMP(type=8))
    elif kind == "blacklist":
        process(IP(src="203.0.113.66", dst=dst) / TCP(dport=443, flags="S"))
    elif kind == "badport":
        process(IP(src="192.168.56.77", dst=dst) / TCP(dport=4444, flags="S"))
    else:
        return False
    return True