#!/usr/bin/env python3
"""
Inventory - Consolidated asset discovery & inventory (v6.2)
TrinTech Digital Defense

Builds a single inventory from external, internal, OSINT, and credentialed data.
Produces host roles, service summary, criticality, and topology notes for reporting.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Set


def _role_from_ports(ports: List[str], services: List[str]) -> str:
    ps = set(str(p) for p in ports)
    sv = " ".join(services).lower()
    if "3389" in ps or "ms-wbt" in sv:
        return "windows-remote"
    if "445" in ps or "microsoft-ds" in sv or "smb" in sv:
        return "file/smb"
    if any(p in ps for p in ("3306", "5432", "1433", "27017", "6379")) or any(
        x in sv for x in ("mysql", "postgres", "mssql", "mongodb", "redis")
    ):
        return "database"
    if any(p in ps for p in ("80", "443", "8080", "8443")) or "http" in sv:
        return "web"
    if any(p in ps for p in ("25", "587", "465", "110", "143", "993", "995")) or any(
        x in sv for x in ("smtp", "imap", "pop3")
    ):
        return "mail"
    if "53" in ps or "domain" in sv or "dns" in sv:
        return "dns"
    if "22" in ps or "ssh" in sv:
        return "linux/ssh"
    if any(p in ps for p in ("161", "162")) or "snmp" in sv:
        return "network-mgmt"
    return "host"


def _os_hint(service_blob: str, existing: str = "") -> str:
    if existing and existing != "Unknown":
        return existing
    s = (service_blob or "").lower()
    if "windows" in s or "microsoft" in s or "iis" in s:
        return "Windows (hint)"
    if "ubuntu" in s:
        return "Linux-Ubuntu (hint)"
    if "debian" in s:
        return "Linux-Debian (hint)"
    if "centos" in s or "rhel" in s or "red hat" in s:
        return "Linux-RHEL/CentOS (hint)"
    if "openssh" in s:
        return "Linux/Unix (OpenSSH)"
    if "cisco" in s:
        return "Network-Cisco (hint)"
    if "apple" in s or "mac os" in s:
        return "macOS (hint)"
    return existing or "Unknown"


def _criticality(role: str, risk_flags: List[str], ports: List[str]) -> str:
    """Simple business criticality for reporting."""
    ps = set(str(p) for p in ports)
    if role in ("database", "mail") or any("critical" in f for f in risk_flags):
        return "high"
    if role in ("web", "windows-remote", "file/smb") or "3389" in ps or "445" in ps:
        return "high"
    if role in ("dns", "linux/ssh", "network-mgmt"):
        return "medium"
    if risk_flags:
        return "medium"
    return "low"


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
                "hostname": None,
                "ports": [],
                "services": [],
                "sources": [],
                "role": "host",
                "os_hint": "Unknown",
                "risk_flags": [],
                "criticality": "low",
                "credentialed": False,
            }
        return assets[host]

    # External ports + hosts
    external = audit_data.get("external_scan") or {}
    for p in external.get("open_ports") or []:
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
            flag = f"{port}/{svc}:{p.get('risk_level')}"
            if flag not in a["risk_flags"]:
                a["risk_flags"].append(flag)

    for h in external.get("hosts") or []:
        if isinstance(h, dict):
            a = ensure(str(h.get("host") or ""))
            if "external" not in a["sources"]:
                a["sources"].append("external")
            for port in h.get("ports") or []:
                if str(port) not in a["ports"]:
                    a["ports"].append(str(port))
            for svc in h.get("services") or []:
                if svc and svc not in a["services"]:
                    a["services"].append(svc)

    # Internal
    internal = audit_data.get("internal_scan") or {}
    for h in internal.get("hosts") or []:
        if isinstance(h, dict):
            a = ensure(str(h.get("ip") or h.get("host") or ""))
            if "internal" not in a["sources"]:
                a["sources"].append("internal")
            if h.get("hostname"):
                a["hostname"] = h.get("hostname")
            if h.get("os_hint") and h.get("os_hint") != "Unknown":
                a["os_hint"] = h.get("os_hint")
            for port in h.get("ports") or []:
                if str(port) not in a["ports"]:
                    a["ports"].append(str(port))
            for svc in h.get("services") or []:
                if svc and svc not in a["services"]:
                    a["services"].append(svc)
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
            if p.get("risk_level") in ("critical", "high"):
                flag = f"{port}/{svc}:{p.get('risk_level')}"
                if flag not in a["risk_flags"]:
                    a["risk_flags"].append(flag)

    # OSINT subdomains
    for sub in (audit_data.get("osint_recon") or {}).get("subdomains") or []:
        a = ensure(str(sub))
        if "osint" not in a["sources"]:
            a["sources"].append("osint")
        if a["role"] == "host":
            a["role"] = "web/dns"

    # Credentialed hosts
    cred = audit_data.get("credentialed_scan") or {}
    for h in cred.get("hosts_scanned") or []:
        if isinstance(h, dict):
            a = ensure(str(h.get("host") or ""))
            if "credentialed" not in a["sources"]:
                a["sources"].append("credentialed")
            a["credentialed"] = True
            if h.get("os_hint"):
                a["os_hint"] = h.get("os_hint")

    # Derive role / OS / criticality
    for a in assets.values():
        a["role"] = _role_from_ports(a["ports"], a["services"])
        a["os_hint"] = _os_hint(" ".join(a["services"]), a.get("os_hint") or "")
        a["ports"] = sorted(
            a["ports"], key=lambda x: int(x) if str(x).isdigit() else 99999
        )
        a["port_count"] = len(a["ports"])
        a["criticality"] = _criticality(a["role"], a["risk_flags"], a["ports"])

    # Topology notes
    notes: List[str] = []
    web_hosts = [a["host"] for a in assets.values() if a["role"] == "web"]
    db_hosts = [a["host"] for a in assets.values() if a["role"] == "database"]
    mail_hosts = [a["host"] for a in assets.values() if a["role"] == "mail"]
    dual = [
        a["host"]
        for a in assets.values()
        if "external" in a["sources"] and "internal" in a["sources"]
    ]
    high_crit = [a["host"] for a in assets.values() if a["criticality"] == "high"]

    if web_hosts:
        notes.append(f"{len(web_hosts)} web-facing host(s): {', '.join(web_hosts[:6])}")
    if db_hosts:
        notes.append(
            f"{len(db_hosts)} database-like host(s) — verify not internet-exposed: {', '.join(db_hosts[:5])}"
        )
    if mail_hosts:
        notes.append(f"{len(mail_hosts)} mail-related host(s): {', '.join(mail_hosts[:4])}")
    if dual:
        notes.append(f"{len(dual)} host(s) seen on both external and internal scans")
    if high_crit:
        notes.append(f"{len(high_crit)} high-criticality asset(s) identified")

    # Simple topology edges (logical, not packet-level)
    edges: List[Dict[str, str]] = []
    for a in assets.values():
        if a["role"] == "web" and db_hosts:
            for db in db_hosts[:3]:
                if db != a["host"]:
                    edges.append({"from": a["host"], "to": db, "relation": "web-to-db (inferred)"})
        if a["role"] == "linux/ssh" and a.get("credentialed"):
            edges.append({"from": "auditor", "to": a["host"], "relation": "credentialed-ssh"})

    inventory = {
        "assets": list(assets.values()),
        "asset_count": len(assets),
        "topology_notes": notes,
        "topology_edges": edges[:20],
        "high_criticality_count": len(high_crit),
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": (
            "Consolidated from external, internal, OSINT, and credentialed modules. "
            "Roles and criticality are inferred from ports/services."
        ),
    }
    audit_data["inventory"] = inventory
    print(
        f"[INVENTORY] {len(assets)} asset(s) | high-crit={len(high_crit)} | notes={len(notes)}"
    )
    return audit_data


def run_scan(audit_data: dict) -> dict:
    """Alias for module runner compatibility."""
    return build_inventory(audit_data)
