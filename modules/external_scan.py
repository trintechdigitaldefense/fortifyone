#!/usr/bin/env python3
"""
ReconVision - External Footprint Scanner
TrinTech Digital Defense
"""

import json
import subprocess
import datetime
import socket

def run_scan(audit_data: dict) -> dict:
    target_ip = audit_data["audit_metadata"]["public_ip"].strip()
    domain = audit_data["audit_metadata"]["domain"].strip()
    
    print(f"\n[RECONVISION] Scanning target: {target_ip} ({domain})...")
    open_ports = []
    findings = []
    
    if target_ip and target_ip != "0.0.0.0":
        try:
            cmd = ["nmap", "-sS", "-T4", "--top-ports", "50", "-sV", "--version-intensity", "3", target_ip]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if "Nmap scan report" in res.stdout:
                for line in res.stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        port_id = parts[0].split("/")[0]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        open_ports.append({
                            "port": port_id,
                            "service": service,
                            "risk_level": "critical" if port_id in ["3389", "445"] else "medium"
                        })
                        findings.append(f"[ACTIVE] Port {port_id} ({service}) OPEN")
        except Exception as e:
            findings.append(f"[ERROR] Scan error: {e}")
            
    risk_score = min(len(open_ports) * 20, 100)
    
    audit_data["external_scan"] = {
        "open_ports": open_ports,
        "vulnerabilities": findings,
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat()
    }
    
    print(f"[RECONVISION] Complete: {len(open_ports)} open ports found | Risk: {risk_score}/100\n")
    return audit_data
