#!/usr/bin/env python3
"""
Shodan Integration Module for FortifyOne
Adds Shodan internet-wide scan data to audits
TrinTech Digital Defense
"""

import json
import os
import datetime
import urllib.request
import urllib.error
import ssl

def check_shodan(ip: str) -> dict:
    """Query Shodan for IP information."""
    result = {
        "ip": ip,
        "open_ports": [],
        "vulnerabilities": [],
        "services": [],
        "hostnames": [],
        "org": "",
        "last_update": ""
    }
    
    api_key = os.environ.get('SHODAN_API_KEY', '')
    if not api_key:
        result["error"] = "No SHODAN_API_KEY configured"
        return result
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={'User-Agent': 'FortifyOne'})
        
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            
            result["org"] = data.get('org', 'Unknown')
            result["hostnames"] = data.get('hostnames', [])
            result["last_update"] = data.get('last_update', '')
            
            for service in data.get('data', []):
                port_info = {
                    "port": service.get('port'),
                    "transport": service.get('transport', 'tcp'),
                    "service": service.get('_shodan', {}).get('module', service.get('product', 'unknown')),
                    "product": service.get('product', ''),
                    "version": service.get('version', ''),
                }
                result["open_ports"].append(port_info)
                result["services"].append(port_info["service"])
            
            # Check for vulnerabilities
            for vuln in data.get('vulns', []):
                result["vulnerabilities"].append({
                    "cve": vuln,
                    "cvss": data['vulns'][vuln].get('cvss', 0),
                    "summary": data['vulns'][vuln].get('summary', '')[:200]
                })
                
    except urllib.error.HTTPError as e:
        if e.code == 401:
            result["error"] = "Invalid Shodan API key"
        elif e.code == 404:
            result["error"] = "No Shodan data for this IP"
        else:
            result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)
    
    return result

def run_scan(audit_data: dict) -> dict:
    """Add Shodan data to audit."""
    ip = audit_data["audit_metadata"]["public_ip"]
    
    print(f"\n[SHODAN] Querying Shodan for {ip}...")
    
    shodan_data = check_shodan(ip)
    
    if shodan_data.get("error"):
        print(f"[SHODAN] {shodan_data['error']}")
        return audit_data
    
    print(f"[SHODAN] Found {len(shodan_data['open_ports'])} ports")
    print(f"[SHODAN] Org: {shodan_data['org']}")
    
    if shodan_data["vulnerabilities"]:
        print(f"[SHODAN] ⚠ {len(shodan_data['vulnerabilities'])} vulnerabilities found!")
    
    # Merge with existing external scan data
    existing_ports = audit_data["external_scan"]["open_ports"]
    existing_port_numbers = {p["port"] for p in existing_ports}
    
    for port in shodan_data["open_ports"]:
        if str(port["port"]) not in existing_port_numbers:
            existing_ports.append({
                "port": str(port["port"]),
                "service": port["service"],
                "product": port.get("product", ""),
                "protocol": port.get("transport", "tcp"),
                "source": "shodan",
                "risk_level": "high" if str(port["port"]) in ['3389', '445', '22'] else "medium"
            })
    
    # Add Shodan vulns
    for vuln in shodan_data["vulnerabilities"]:
        audit_data["external_scan"]["vulnerabilities"].append(
            f"[SHODAN] {vuln['cve']} (CVSS: {vuln['cvss']}): {vuln['summary']}"
        )
    
    audit_data["external_scan"]["open_ports"] = existing_ports
    audit_data["external_scan"]["shodan_data"] = {
        "org": shodan_data["org"],
        "hostnames": shodan_data["hostnames"],
        "last_update": shodan_data["last_update"]
    }
    
    return audit_data

if __name__ == "__main__":
    print("Shodan Module Test")
    print("-" * 40)
    
    if os.environ.get('SHODAN_API_KEY'):
        test = check_shodan("8.8.8.8")
        print(json.dumps(test, indent=2)[:500])
    else:
        print("No SHODAN_API_KEY set - skipping test")
        print("Get free API key: https://account.shodan.io/register")
