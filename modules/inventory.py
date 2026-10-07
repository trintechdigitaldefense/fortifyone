#!/usr/bin/env python3
"""
Inventory - Consolidated asset discovery & inventory
TrinTech Digital Defense

Builds a single inventory from external, internal, OSINT, and credentialed data.
Produces host roles, service summary, and topology notes for reporting.
"""

from __future__ import annotations

import datetime
import re
from typing import Any, Dict, List, Set


def _role_from_ports(ports: List[str], services: List[str]) -> str:
    ps = set(str(p) for p in ports)
    sv = " ".join(services).lower()
    if "3389" in ps or "ms-wbt" in sv:
        return "windows-remote"
    if "445" in ps or "microsoft-ds" in sv:
        return "file/smb"
    if "3306" in ps or "5432" in ps or "1433" in ps or "27017" in ps:
        return "database"
    if "80" in ps or "443" in ps or "8080" in ps or "8443" in ps or "http" in sv:
        return "web"
    if "25" in ps or "587" in ps or "465" in ps or "smtp" in sv:
        return "mail"
    if "22" in ps or "ssh" in sv:
        return "linux/ssh"
    if "53" in ps or "domain" in sv:
        return "dns"
    return "host"


def _os_hint(service_blob: str) -> str:
    s = service_blob.lower()
    if "windows" in s or "microsoft" in s:
        return "Windows (hint)"
    if "ubuntu" in s or "debian" in s:
        return "Linux-Debian/Ubuntu (hint)"
    if "openssh" in s:
        return "Linux/Unix (OpenSSH)"
    if "cisco" in s:
        return "Network-Cisco (hint)"
    return "Unknown"


def build_inventory(audit_data: dict) -> dict:
    """Merge discovery sources into audit_data['inventory']."""
    print("\n[INVENTORY] Building consolidated asset inventory...")

    assets: Dict[str, Dict[str, Any]] = {}

    def ensure(host: str) -> Dict[str, Any]:
        host = (host or "").strip()
        if not host:
            host = "unknown"
        if host not in assets:
            assets[host] = {
                "host": host,
                "ports": [],
                "services": [],
                "sources": [],
                "role": "host",
                "os_hint": "Unknown",
                "risk_flags": [],
            }
        return assets[host]

    # External ports
    for p in (audit_data.get("external_scan") or {}).get("open_ports") or []:
        if not isinstance(p, dict):
            continue
        a = ensure(str(p.get("host") or p.get("ip") or ""))
        port = str(p.get("port") or "")
        svc = str(p.get("service") or "unknown")
        if port and port not in a["ports"]:
            a["ports"].append(port)
        if svc and svc not in a["services"]:
            a["services"].append(svc)
        if "external" not in a["sources"]:
            a["sources"].append("external")
        if p.get("risk_level") in ("critical", "high"):
            a["risk_flags"].append(f"{port}/{svc}:{p.get('risk_level')}")

    # Internal
    internal = audit_data.get("internal_scan") or {}
    for h in internal.get("hosts") or []:
        if isinstance(h, dict):
            a = ensure(str(h.get("ip") or h.get("host") or ""))
            if "internal" not in a["sources"]:
                a["sources"].append("internal")
            if h.get("hostname"):
                a["hostname"] = h.get("hostname")
        elif isinstance(h, str):
            a = ensure(h)
            if "internal" not in a["sources"]:
                a["sources"].append("internal")
    for p in internal.get("open_ports") or []:
        if isinstance(p, dict):
            a = ensure(str(p.get("host") or p.get("ip") or ""))
            port = str(p.get("port") or "")
            svc = str(p.get("service") or "")
            if port and port not in a["ports"]:
                a["ports"].append(port)
            if svc and svc not in a["services"]:
                a["services"].append(svc)
            if "internal" not in a["sources"]:
                a["sources"].append("internal")

    # OSINT subdomains
    for sub in (audit_data.get("osint_recon") or {}).get("subdomains") or []:
        a = ensure(str(sub))
        if "osint" not in a["sources"]:
            a["sources"].append("osint")
        a["role"] = "web/dns"

    # Credentialed hosts
    cred = audit_data.get("credentialed_scan") or {}
    for h in cred.get("hosts_scanned") or []:
        if isinstance(h, dict):
            a = ensure(str(h.get("host") or ""))
            if "credentialed" not in a["sources"]:
                a["sources"].append("credentialed")
            a["credentialed"] = True

    # Derive role / OS
    for a in assets.values():
        a["role"] = _role_from_ports(a["ports"], a["services"])
        a["os_hint"] = _os_hint(" ".join(a["services"]))
        a["ports"] = sorted(a["ports"], key=lambda x: int(x) if x.isdigit() else 99999)
        a["port_count"] = len(a["ports"])

    # Topology notes
    notes = []
    web_hosts = [a["host"] for a in assets.values() if a["role"] == "web"]
    db_hosts = [a["host"] for a in assets.values() if a["role"] == "database"]
    if web_hosts:
        notes.append(f"{len(web_hosts)} web-facing host(s): {', '.join(web_hosts[:5])}")
    if db_hosts:
        notes.append(f"{len(db_hosts)} database-like host(s) — verify not internet-exposed: {', '.join(db_hosts[:5])}")
    dual = [a["host"] for a in assets.values() if "external" in a["sources"] and "internal" in a["sources"]]
    if dual:
        notes.append(f"{len(dual)} host(s) seen on both external and internal scans")

    inventory = {
        "assets": list(assets.values()),
        "asset_count": len(assets),
        "topology_notes": notes,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "Consolidated from external, internal, OSINT, and credentialed modules.",
    }
    audit_data["inventory"] = inventory
    print(f"[INVENTORY] {len(assets)} asset(s) | notes={len(notes)}")
    return audit_data


def run_scan(audit_data: dict) -> dict:
    """Alias for module runner compatibility."""
    return build_inventory(audit_data)
