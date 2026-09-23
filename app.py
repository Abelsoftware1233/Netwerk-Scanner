#!/usr/bin/env python3
"""
NetScanner Pro - Network Reconnaissance Tool
Backend: Flask + nmap + scapy
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import subprocess
import socket
import threading
import os
import re
import json
import time
import ipaddress

app = Flask(__name__, static_folder=".")
CORS(app)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_network_cidr(local_ip):
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(".", filename)

@app.route("/api/local-ip")
def api_local_ip():
    ip = get_local_ip()
    return jsonify({"ip": ip, "network": get_network_cidr(ip)})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    target = data.get("target", get_network_cidr(get_local_ip()))
    
    hosts = []
    try:
        # ping sweep with nmap
        result = subprocess.run(
            ["nmap", "-sn", "--host-timeout", "3s", target],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        # parse nmap output
        current = {}
        for line in output.splitlines():
            m = re.search(r"Nmap scan report for (.+)", line)
            if m:
                raw = m.group(1)
                hostname, ip_addr = "", ""
                ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", raw)
                if ip_match:
                    ip_addr = ip_match.group(1)
                    hostname = raw.split("(")[0].strip()
                else:
                    ip_addr = raw.strip()
                current = {"ip": ip_addr, "hostname": hostname, "status": "up", "mac": "", "vendor": ""}

            if "MAC Address:" in line and current:
                mac_match = re.search(r"MAC Address: ([0-9A-F:]+)\s*(.*)", line)
                if mac_match:
                    current["mac"] = mac_match.group(1)
                    current["vendor"] = mac_match.group(2).strip("()")
                hosts.append(current)
                current = {}

        # also grab hosts that appear without MAC (local machine or direct)
        for line in output.splitlines():
            if "Host is up" in line:
                pass  # handled above

        # fallback: add last host if no MAC line followed
        if current and current.get("ip"):
            hosts.append(current)

    except FileNotFoundError:
        # nmap not installed – fallback pure-python ping sweep
        network = ipaddress.IPv4Network(target, strict=False)
        sample_ips = list(network.hosts())[:30]
        for ip_obj in sample_ips:
            ip_str = str(ip_obj)
            res = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_str],
                capture_output=True
            )
            if res.returncode == 0:
                try:
                    hostname = socket.gethostbyaddr(ip_str)[0]
                except Exception:
                    hostname = ""
                hosts.append({"ip": ip_str, "hostname": hostname, "status": "up", "mac": "", "vendor": ""})

    return jsonify({"hosts": hosts, "target": target, "count": len(hosts)})


@app.route("/api/portscan", methods=["POST"])
def api_portscan():
    data = request.get_json(force=True)
    target_ip = data.get("ip")
    if not target_ip:
        return jsonify({"error": "No IP provided"}), 400

    open_ports = []
    vuln_info = []
    service_info = {}

    try:
        result = subprocess.run(
            ["nmap", "-sV", "--top-ports", "100", "--host-timeout", "10s", target_ip],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        for line in output.splitlines():
            pm = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
            if pm:
                port = int(pm.group(1))
                proto = pm.group(2)
                service = pm.group(3)
                version = pm.group(4).strip()
                open_ports.append({
                    "port": port, "proto": proto,
                    "service": service, "version": version
                })

        # basic vuln hints
        services = [p["service"] for p in open_ports]
        if "ftp" in services:
            vuln_info.append("FTP detected – check anonymous login")
        if "telnet" in services:
            vuln_info.append("Telnet open – plaintext credentials risk")
        if "http" in services or "http-alt" in services:
            vuln_info.append("HTTP open – scan for web vulnerabilities")
        if "smb" in services or "microsoft-ds" in services:
            vuln_info.append("SMB open – EternalBlue risk on unpatched systems")

    except FileNotFoundError:
        # fallback: socket-based scan of common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
        for p in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target_ip, p)) == 0:
                try:
                    service = socket.getservbyport(p)
                except Exception:
                    service = "unknown"
                open_ports.append({"port": p, "proto": "tcp", "service": service, "version": ""})
            s.close()

    vulnerable = len(vuln_info) > 0
    return jsonify({
        "ip": target_ip,
        "open_ports": open_ports,
        "port_count": len(open_ports),
        "vulnerable": vulnerable,
        "vuln_hints": vuln_info
    })


@app.route("/api/mitm-info", methods=["POST"])
def api_mitm_info():
    """Return ARP table and gateway info for MITM awareness."""
    data = request.get_json(force=True)
    target_ip = data.get("ip", "")

    arp_table = []
    try:
        result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                arp_table.append({"ip": parts[0], "mac": parts[2], "iface": parts[-1] if len(parts) > 3 else ""})
    except Exception:
        pass

    gateway = ""
    try:
        r = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
        m = re.search(r"default via (\S+)", r.stdout)
        if m:
            gateway = m.group(1)
    except Exception:
        pass

    return jsonify({
        "target": target_ip,
        "gateway": gateway,
        "arp_table": arp_table[:20],
        "info": "ARP cache retrieved. Use responsibly – only on networks you own."
    })


@app.route("/api/attack-surface", methods=["POST"])
def api_attack_surface():
    """Summarise attack surface for a given IP."""
    data = request.get_json(force=True)
    target_ip = data.get("ip", "")

    findings = []
    risk = "Low"

    try:
        result = subprocess.run(
            ["nmap", "-O", "--osscan-guess", "--host-timeout", "10s", target_ip],
            capture_output=True, text=True, timeout=30
        )
        out = result.stdout
        os_match = re.search(r"OS details: (.+)", out)
        if os_match:
            findings.append(f"OS: {os_match.group(1)}")

        open_cnt = len(re.findall(r"/tcp\s+open", out))
        findings.append(f"{open_cnt} open TCP ports detected")
        if open_cnt > 10:
            risk = "High"
        elif open_cnt > 4:
            risk = "Medium"

    except Exception as e:
        findings.append(f"Quick scan: {str(e)}")

    return jsonify({
        "ip": target_ip,
        "risk": risk,
        "findings": findings,
        "disclaimer": "For authorised testing only."
    })


if __name__ == "__main__":
    print("=" * 50)
    print("  NetScanner Pro – starting on http://localhost:5008")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5008)
