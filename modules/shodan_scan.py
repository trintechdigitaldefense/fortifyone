#!/usr/bin/env python3
"""
Shodan Integration Module for FortifyOne (Hardened)
Adds Shodan internet-wide scan data to audits
TrinTech Digital Defense

Authorized use only.
"""

import json
import os
import datetime
import urllib.request
import urllib.error
import ssl
import ipaddress


def check_shodan(ip: str) -> dict:
    """Query Shodan for IP information. Never logs or echoes the API key."""
    result = {
        "ip": ip,
        "open_ports": [],
        "vulnerabilities": [],
        "services": [],
        "hostnames": [],
        "org": "",
        "last_update": "",
    }

    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not api_key:
        result["error"] = "No SHODAN_API_KEY configured"
        return result

    # Validate IP before querying
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        result["error"] = "Invalid IP for Shodan query"
        return result

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "FortifyOne-ReconVision"})

        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))

            result["org"] = data.get("org", "Unknown")
            result["hostnames"] = data.get("hostnames", [])
            result["last_update"] = data.get("last_update", "")

            for service in data.get("data", []):
                port_info = {
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "service": service.get("_shodan", {}).get("module", service.get("product", "unknown")),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                }
                result["open_ports"].append(port_info)
                result["services"].append(port_info["service"])

            for vuln in data.get("vulns", []):
                vuln_data = data["vulns"].get(vuln, {})
                result["vulnerabilities"].append({
                    "cve": vuln,
                    "cvss": vuln_data.get("cvss", 0),
                    "summary": (vuln_data.get("summary", "") or "")[:200],
                })

    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["error"] = "Invalid Shodan API key"
        elif e.code == 404:
            result["error"] = "No Shodan data for this IP"
        else:
            result["error"] = f"HTTP {e.code}"
    except Exception as e:
        # Never include API key or full exception details that might leak secrets
        result["error"] = f"{type(e).__name__}"

    return result


def run_scan(audit_data: dict) -> dict:
    """Add Shodan data to existing external_scan section. Non-fatal on failure."""
    ip = audit_data.get("audit_metadata", {}).get("public_ip", "")

    print(f"\n[SHODAN] Querying Shodan for {ip}...")

    shodan_data = check_shodan(ip)

    if shodan_data.get("error"):
        print(f"[SHODAN] {shodan_data['error']}")
        return audit_data

    print(f"[SHODAN] Found {len(shodan_data['open_ports'])} ports | Org: {shodan_data['org']}")

    if shodan_data["vulnerabilities"]:
        print(f"[SHODAN] ⚠ {len(shodan_data['vulnerabilities'])} vulnerabilities found")

    # Ensure external_scan structure exists
    if "external_scan" not in audit_data:
        audit_data["external_scan"] = {
            "open_ports": [],
            "vulnerabilities": [],
            "risk_score": 0,
        }

    existing_ports = audit_data["external_scan"].setdefault("open_ports", [])
    existing_port_numbers = {str(p.get("port")) for p in existing_ports}

    for port in shodan_data["open_ports"]:
        pstr = str(port["port"])
        if pstr not in existing_port_numbers:
            risk = "high" if pstr in ("3389", "445", "22", "23") else "medium"
            existing_ports.append({
                "port": pstr,
                "service": port["service"],
                "product": port.get("product", ""),
                "protocol": port.get("transport", "tcp"),
                "source": "shodan",
                "risk_level": risk,
            })

    for vuln in shodan_data["vulnerabilities"]:
        audit_data["external_scan"].setdefault("vulnerabilities", []).append(
            f"[SHODAN] {vuln['cve']} (CVSS: {vuln['cvss']}): {vuln['summary']}"
        )

    audit_data["external_scan"]["shodan_data"] = {
        "org": shodan_data["org"],
        "hostnames": shodan_data["hostnames"],
        "last_update": shodan_data["last_update"],
    }

    return audit_data


if __name__ == "__main__":
    print("Shodan Module Test")
    print("-" * 40)
    if os.environ.get("SHODAN_API_KEY"):
        test = check_shodan("8.8.8.8")
        print(json.dumps({k: v for k, v in test.items() if k != "error"}, indent=2)[:600])
    else:
        print("No SHODAN_API_KEY set - skipping live test")
        print("Get free API key: https://account.shodan.io/register")
