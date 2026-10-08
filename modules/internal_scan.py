#!/usr/bin/env python3
"""
InternalScan - Internal Network Discovery (v6.2)
TrinTech Digital Defense

Designed to be run FROM INSIDE the client network (on-site or VPN).
Performs host discovery, service fingerprinting, hostname resolution,
and basic OS hints. Non-destructive. Authorized use only.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional


def get_local_network() -> str:
    """Best-effort guess of the local /24 network."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return ""


def pick_cidr_from_scope(audit_data: dict) -> Optional[str]:
    """Prefer an explicit CIDR from scope.in_scope_targets."""
    for t in audit_data.get("scope", {}).get("in_scope_targets", []) or []:
        t = str(t).strip()
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses <= 1024:  # up to /22
                return str(net)
        except ValueError:
            continue
    return None


def _resolve_hostname(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ""


def _parse_os_hint(nmap_block: str) -> str:
    """Extract OS hint from nmap -O or service version output."""
    low = nmap_block.lower()
    if "windows" in low or "microsoft" in low:
        if "windows 10" in low or "windows 11" in low:
            return "Windows 10/11 (hint)"
        if "windows server" in low:
            return "Windows Server (hint)"
        return "Windows (hint)"
    if "ubuntu" in low:
        return "Linux-Ubuntu (hint)"
    if "debian" in low:
        return "Linux-Debian (hint)"
    if "centos" in low or "rhel" in low or "red hat" in low:
        return "Linux-RHEL/CentOS (hint)"
    if "openssh" in low:
        return "Linux/Unix (OpenSSH)"
    if "cisco" in low:
        return "Network-Cisco (hint)"
    if "apple" in low or "mac os" in low or "darwin" in low:
        return "macOS (hint)"
    # Running OS detection line
    m = re.search(r"Running:\s*(.+)", nmap_block, re.I)
    if m:
        return m.group(1).strip()[:80]
    m = re.search(r"OS details:\s*(.+)", nmap_block, re.I)
    if m:
        return m.group(1).strip()[:80]
    return "Unknown"


def run_scan(audit_data: dict, target_cidr: str = None) -> dict:
    """
    Run internal discovery with improved fingerprinting.

    Priority for target:
    1. Explicit target_cidr argument
    2. CIDR found in scope.in_scope_targets
    3. Auto-detect local /24
    """
    print("\n[INTERNALSCAN] Starting strengthened internal discovery...")

    if not target_cidr:
        target_cidr = pick_cidr_from_scope(audit_data)
    if not target_cidr:
        target_cidr = get_local_network()

    if not target_cidr:
        print("[INTERNALSCAN] Could not determine target network. Skipping.")
        audit_data["internal_scan"] = {
            "target_cidr": "",
            "hosts_discovered": 0,
            "hosts": [],
            "open_ports": [],
            "findings": [],
            "risk_score": 0,
            "error": "Could not determine local/target network",
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "note": "Provide a CIDR in scope or run from inside the client LAN.",
        }
        return audit_data

    print(f"[INTERNALSCAN] Target range: {target_cidr}")

    hosts: List[Dict[str, Any]] = []
    findings: List[str] = []
    open_ports: List[Dict[str, Any]] = []

    try:
        # Phase 1: Host discovery (ping scan)
        cmd_discover = [
            "nmap", "-sn", "-T4",
            "--max-retries", "1",
            "--host-timeout", "15s",
            target_cidr,
        ]
        res = subprocess.run(cmd_discover, capture_output=True, text=True, timeout=150)

        live_ips: List[str] = []
        for line in res.stdout.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                # Formats: "Nmap scan report for 192.168.1.10"
                #       or "Nmap scan report for hostname (192.168.1.10)"
                candidate = parts[-1].strip("()")
                try:
                    ipaddress.ip_address(candidate)
                    live_ips.append(candidate)
                except ValueError:
                    # hostname form — previous token may be IP in parens already handled
                    for p in parts:
                        p = p.strip("()")
                        try:
                            ipaddress.ip_address(p)
                            live_ips.append(p)
                            break
                        except ValueError:
                            pass

        # Dedup while preserving order
        seen = set()
        live_ips = [ip for ip in live_ips if not (ip in seen or seen.add(ip))]

        print(f"[INTERNALSCAN] Discovered {len(live_ips)} live host(s)")

        # Cap for safety on modest hardware / Termux
        max_hosts = 30
        targets = live_ips[:max_hosts]
        if len(live_ips) > max_hosts:
            findings.append(f"[INFO] Capped port scan at {max_hosts} hosts (discovered {len(live_ips)})")

        # Build initial host records with reverse DNS
        for ip in targets:
            hostname = _resolve_hostname(ip)
            hosts.append({
                "ip": ip,
                "hostname": hostname or None,
                "status": "up",
                "os_hint": "Unknown",
                "ports": [],
                "services": [],
            })

        if targets:
            # Phase 2: Service scan with light version detection
            # Use -sV for fingerprinting; avoid full -O (needs root and is slow)
            cmd_ports = [
                "nmap", "-sS", "-sV", "-T4",
                "--version-intensity", "3",
                "--top-ports", "50",
                "--open",
                "--max-retries", "1",
                "--host-timeout", "45s",
            ] + targets

            res2 = subprocess.run(cmd_ports, capture_output=True, text=True, timeout=420)
            output = res2.stdout or ""

            # Split into per-host blocks
            blocks = re.split(r"Nmap scan report for ", output)
            host_map = {h["ip"]: h for h in hosts}

            for block in blocks[1:]:
                # First line contains host identifier
                first_line = block.splitlines()[0] if block else ""
                current_ip = None
                # Extract IP
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", first_line)
                if m:
                    current_ip = m.group(1)
                else:
                    # try last token
                    tok = first_line.strip().split()[-1].strip("()") if first_line.strip() else ""
                    try:
                        ipaddress.ip_address(tok)
                        current_ip = tok
                    except ValueError:
                        continue

                if current_ip not in host_map:
                    # Host appeared in port scan but not discovery — add it
                    host_map[current_ip] = {
                        "ip": current_ip,
                        "hostname": _resolve_hostname(current_ip) or None,
                        "status": "up",
                        "os_hint": "Unknown",
                        "ports": [],
                        "services": [],
                    }
                    hosts.append(host_map[current_ip])

                hrec = host_map[current_ip]
                hrec["os_hint"] = _parse_os_hint(block)

                for line in block.splitlines():
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        port = parts[0].split("/")[0]
                        # service + version often in remaining fields
                        service = " ".join(parts[2:]) if len(parts) > 2 else "unknown"
                        service = service.strip()

                        if port in ("445", "3389", "135", "139"):
                            risk = "critical"
                        elif port in ("22", "23", "21", "3306", "5432", "1433", "27017", "6379", "9200"):
                            risk = "high"
                        else:
                            risk = "medium"

                        open_ports.append({
                            "host": current_ip,
                            "ip": current_ip,
                            "port": port,
                            "service": service,
                            "risk_level": risk,
                            "source": "internal_nmap",
                        })
                        if port not in hrec["ports"]:
                            hrec["ports"].append(port)
                        if service and service not in hrec["services"]:
                            hrec["services"].append(service)

                        findings.append(
                            f"[INTERNAL] {current_ip}:{port} ({service}) OPEN — {risk}"
                        )

    except subprocess.TimeoutExpired:
        findings.append("[ERROR] Internal scan timed out")
    except FileNotFoundError:
        findings.append("[ERROR] nmap not found — install nmap for internal discovery")
    except Exception as e:
        findings.append(f"[ERROR] {type(e).__name__}: {e}")

    critical = sum(1 for p in open_ports if p.get("risk_level") == "critical")
    high = sum(1 for p in open_ports if p.get("risk_level") == "high")
    risk_score = min(critical * 25 + high * 12 + len(open_ports) * 2, 100)

    # Enrich hosts with port counts
    for h in hosts:
        h["port_count"] = len(h.get("ports") or [])

    audit_data["internal_scan"] = {
        "target_cidr": target_cidr,
        "hosts_discovered": len(hosts),
        "hosts": hosts,
        "open_ports": open_ports,
        "findings": findings,
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": (
            "Unauthenticated internal discovery with service version detection. "
            "OS hints are best-effort from banners. Credentialed checks require the credentialed module."
        ),
    }

    print(
        f"[INTERNALSCAN] Complete: {len(hosts)} hosts, {len(open_ports)} open ports | Risk: {risk_score}/100\n"
    )
    return audit_data


if __name__ == "__main__":
    print("InternalScan standalone test")
    test_data = {"audit_metadata": {}, "internal_scan": {}, "scope": {"in_scope_targets": []}}
    run_scan(test_data)
