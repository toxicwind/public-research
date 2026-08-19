#!/usr/bin/env python3
"""
ATR7000 RTLS Reader — Network Reconnaissance & Threat Surface Analyzer
=======================================================================
Targets the Zebra ATR7000/FX-series fixed RFID readers based on:
  - Spec Sheet SS-ATR7000 (Feb 2019)
  - Firmware Release Notes v3.30.18 (Aug 2025)
  - Integration Guide (pts mobile)

OSINT-derived attack surface:
  - CVE-2024-6387 (OpenSSH regreSSHion) — unauthenticated RCE on SSH
  - Web console (Apache 2.4.63, Node.js pages, HTTPS default)
  - LLRP v1.0.1 (TCP 5084) — RFID middleware protocol
  - RM 1.01 (XML over HTTP/HTTPS + SNMP binding)
  - IoT Connector (MQTT/HTTPS/Websocket data endpoints)
  - SNMP (disabled by default in 3.30.18, but historically exposed)
  - FTP/FTPS REMOVED in 3.30.18 (was present in earlier builds)
  - SFTP/SCP/SSH (OpenSSH, patched in 3.30.18)
  - KAFKA interface (CLAS Location Analytics engine)
  - PoE+ 802.3at (Layer 1 power — no network isolation from switch)
"""

import socket, ssl, json, sys, argparse, threading, queue, time, re
from urllib.parse import urljoin

try:
    import requests
except ImportError:
    requests = None

# ATR7000/FX9600 known ports and services
ATR_SERVICES = {
    22:   ("SSH", "OpenSSH (CVE-2024-6387 pre-3.30.18)"),
    80:   ("HTTP", "Web console / RM 1.01 XML / Apache"),
    443:  ("HTTPS", "Web console (forced HTTPS post-3.10.30) / TLS 1.2 / FIPS 140-2 L1"),
    5084: ("LLRP", "EPCglobal LLRP v1.0.1 — RFID middleware"),
    161:  ("SNMP", "RM 1.01 SNMP binding (disabled by default in 3.30.18)"),
    162:  ("SNMP-TRAP", "SNMP traps"),
    21:   ("FTP", "REMOVED in 3.30.18 — may exist on older firmware"),
    990:  ("FTPS", "REMOVED in 3.30.18"),
    1883: ("MQTT", "IoT Connector data endpoint (AWS IoT, generic)"),
    8883: ("MQTTS", "IoT Connector TLS MQTT"),
    9092: ("KAFKA", "CLAS Location Analytics streaming (speculative)"),
    5353: ("mDNS", "Avahi/NetBIOS/RDMPAgent (can be disabled)"),
}

# Known firmware version strings from release notes
FIRMWARE_VERSIONS = [
    "3.30.18", "3.29.19", "3.28.1", "3.21.24", "3.21.21",
    "2.16.29", "2.15.14", "3.10.30", "3.26.90"
]

class ATRScanner:
    def __init__(self, target, timeout=3, threads=50):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = {}
        self.lock = threading.Lock()
        self.q = queue.Queue()
        for port in ATR_SERVICES:
            self.q.put(port)

    def _probe_port(self, port):
        svc, note = ATR_SERVICES[port]
        banner = ""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            # Grab banner for text protocols
            if port in (22, 80, 21, 5084):
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except:
                    pass
            sock.close()
            with self.lock:
                self.results[port] = {
                    "state": "OPEN",
                    "service": svc,
                    "note": note,
                    "banner": banner[:200]
                }
        except (socket.timeout, ConnectionRefusedError, OSError):
            with self.lock:
                self.results[port] = {"state": "CLOSED/FILTERED", "service": svc, "note": note, "banner": ""}
        except Exception as e:
            with self.lock:
                self.results[port] = {"state": "ERROR: " + str(e)[:50], "service": svc, "note": note, "banner": ""}

    def scan(self):
        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            workers.append(t)
        self.q.join()
        for t in workers:
            t.join(timeout=1)
        return self.results

    def _worker(self):
        while True:
            try:
                port = self.q.get(block=False)
            except queue.Empty:
                break
            self._probe_port(port)
            self.q.task_done()

    def analyze(self):
        """Generate threat assessment from scan results."""
        assessment = {
            "target": self.target,
            "risk_score": 0,
            "max_risk": 100,
            "findings": [],
            "exploitable_vectors": [],
            "recommendations": []
        }

        for port, data in self.results.items():
            if data["state"] != "OPEN":
                continue

            if port == 22:
                assessment["risk_score"] += 35
                assessment["findings"].append("SSH (22) OPEN — OpenSSH on ATR7000/FX9600. Pre-3.30.18 firmware vulnerable to CVE-2024-6387 (regreSSHion): unauthenticated remote code execution.")
                assessment["exploitable_vectors"].append("CVE-2024-6387: If firmware < 3.30.18, unauth RCE via signal handler race in sshd.")
                if "OpenSSH" in data.get("banner", ""):
                    ver_match = re.search(r"OpenSSH_([0-9.]+)", data["banner"])
                    if ver_match:
                        assessment["findings"].append("SSH banner version: " + ver_match.group(1))

            elif port == 80:
                assessment["risk_score"] += 15
                assessment["findings"].append("HTTP (80) OPEN — Web console. Post-3.10.30 mandates HTTPS redirect + default password change. If admin never changed default creds, trivial takeover.")
                assessment["exploitable_vectors"].append("Default credentials / credential stuffing on web console.")

            elif port == 443:
                assessment["risk_score"] += 10
                assessment["findings"].append("HTTPS (443) OPEN — Web console with TLS 1.2 + FIPS 140-2 L1. Check for self-signed cert warnings (known false alarm per release notes, but also masks MITM).")
                assessment["exploitable_vectors"].append("TLS downgrade / weak cipher suites if not properly configured.")

            elif port == 5084:
                assessment["risk_score"] += 20
                assessment["findings"].append("LLRP (5084) OPEN — EPCglobal LLRP v1.0.1. This is the RFID middleware protocol. No auth in base spec; reader config can be modified via LLRP if not in secure mode.")
                assessment["exploitable_vectors"].append("LLRP unauthenticated reader reconfiguration / tag data interception.")

            elif port == 161:
                assessment["risk_score"] += 15
                assessment["findings"].append("SNMP (161) OPEN — RM 1.01 SNMP binding. Default community strings (public/private) may persist.")
                assessment["exploitable_vectors"].append("SNMP community string brute force → config extraction / modification.")

            elif port in (21, 990):
                assessment["risk_score"] += 25
                assessment["findings"].append("FTP/FTPS (" + str(port) + ") OPEN — REMOVED in firmware 3.30.18. Presence indicates OLD firmware with known vulnerabilities.")
                assessment["exploitable_vectors"].append("FTP anonymous login / directory traversal / firmware extraction.")

            elif port in (1883, 8883):
                assessment["risk_score"] += 15
                assessment["findings"].append("MQTT (" + str(port) + ") OPEN — IoT Connector endpoint. May stream tag ID + location data to cloud. Check for weak auth or certificate pinning bypass.")
                assessment["exploitable_vectors"].append("MQTT credential harvesting → real-time location data exfiltration.")

        # Risk score cap
        assessment["risk_score"] = min(assessment["risk_score"], 100)

        if assessment["risk_score"] >= 70:
            assessment["recommendations"].append("CRITICAL: Isolate reader on segmented VLAN. Disable SSH if not needed. Upgrade to firmware 3.30.18+ immediately.")
        elif assessment["risk_score"] >= 40:
            assessment["recommendations"].append("HIGH: Review open services. Disable unused protocols (SNMP, FTP if present). Enforce HTTPS-only admin access.")
        else:
            assessment["recommendations"].append("MEDIUM: Verify TLS config. Ensure default passwords changed. Monitor LLRP traffic for anomalies.")

        return assessment

def main():
    parser = argparse.ArgumentParser(description="ATR7000/FX9600 Network Recon & Threat Analyzer")
    parser.add_argument("target", help="IP address or hostname of target reader")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Connection timeout (seconds)")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Thread count")
    parser.add_argument("-o", "--output", help="JSON output file")
    args = parser.parse_args()

    print("[*] Scanning " + args.target + " for ATR7000/FX9600 services...")
    scanner = ATRScanner(args.target, timeout=args.timeout, threads=args.threads)
    results = scanner.scan()
    assessment = scanner.analyze()

    print("\n" + "=" * 60)
    print("TARGET: " + args.target)
    print("RISK SCORE: " + str(assessment["risk_score"]) + "/" + str(assessment["max_risk"]))
    print("=" * 60)

    print("\n[OPEN SERVICES]")
    for port, data in sorted(results.items()):
        if data["state"] == "OPEN":
            print("  " + str(port) + "/tcp  " + data["service"].ljust(12) + " " + data["note"])
            if data["banner"]:
                print("            Banner: " + data["banner"][:80])

    print("\n[THREAT FINDINGS]")
    for f in assessment["findings"]:
        print("  [!] " + f)

    print("\n[EXPLOITABLE VECTORS]")
    for v in assessment["exploitable_vectors"]:
        print("  [→] " + v)

    print("\n[RECOMMENDATIONS]")
    for r in assessment["recommendations"]:
        print("  [*] " + r)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"scan": results, "assessment": assessment}, f, indent=2)
        print("\n[+] Results saved to " + args.output)

if __name__ == "__main__":
    main()
