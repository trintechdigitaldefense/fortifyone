#!/usr/bin/env python3
"""
ReconVision - External Footprint Scanner (v6.2)
TrinTech Digital Defense

Multi-target external discovery with improved service fingerprinting.
Supports single IP, domain, multiple targets, and small CIDR ranges.
Authorized use only.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import subprocess
from typing import Any, Dict, List, Optional


def is_valid_domain(domain: str) -> bool:
    domain = (domain or "").strip().lower()
    if not domain:
        return False
    if not re.match(
        r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$",
        domain,
    ):
        return False
    forbidden = set(";|&$`<>()\n\r\\\"'")
    return not any(c in domain for c in forbidden)


def parse_target(raw: str) -> Optional[Dict[str, str]]:
    """Parse a single target into a normalized dict. None if invalid."""
    raw = (raw or "").strip()
    if not raw:
        return None

    try:
        net = ipaddress.ip_network(raw, strict=False)
        if net.num_addresses > 512:  # max /23 for external
            print(
                f"[RECONVISION] Skipping oversized range {raw} "
                f"({net.num_addresses} addresses). Max /23."
            )
            return None
        return {
            "type": "cidr" if "/" in raw else "ip",
            "value": str(net) if "/" in raw else str(net.network_address),
            "original": raw,
        }
    except ValueError:
        pass

    if is_valid_domain(raw):
        return {"type": "domain", "value": raw.lower(), "original": raw}

    return None


def collect_targets(audit_data: dict) -> List[Dict[str, str]]:
    """Build target list from scope + legacy metadata fields."""
    targets: List[Dict[str, str]] = []
    seen = set()

    for t in audit_data.get("scope", {}).get("in_scope_targets", []) or []:
        parsed = parse_target(str(t))
        if parsed and parsed["value"] not in seen:
            targets.append(parsed)
            seen.add(parsed["value"])

    meta = audit_data.get("audit_metadata", {})
    for key in ("public_ip", "domain"):
        val = meta.get(key, "")
        if val:
            parsed = parse_target(str(val))
            if parsed and parsed["value"] not in seen:
                targets.append(parsed)
                seen.add(parsed["value"])

    return targets


def _risk_for_port(port: str, service: str) -> str:
    p = str(port)
    s = (service or "").lower()
    if p in ("3389", "445", "135", "139", "5900") or "ms-wbt" in s or "microsoft-ds" in s:
        return "critical"
    if p in ("22", "23", "21", "3306", "5432", "1433", "27017", "6379", "9200", "2375", "2376"):
        return "high"
    if p in ("80", "443", "8080", "8443", "25", "587", "465"):
        return "medium"
    return "medium"


def scan_single_target(target: Dict[str, str], timeout: int = 200) -> Dict[str, Any]:
    """Scan one target (IP, domain, or small CIDR)."""
    value = target["value"]
    ttype = target["type"]
    result: Dict[str, Any] = {
        "target": value,
        "type": ttype,
        "open_ports": [],
        "hosts": [],
        "findings": [],
        "error": None,
    }

    if value in ("0.0.0.0", "127.0.0.1", "::1", "localhost") or value.startswith("127."):
        result["error"] = "Refusing to scan localhost"
        result["findings"].append("[ERROR] Refusing to scan localhost / zero address")
        return result

    print(f"[RECONVISION] Scanning {ttype}: {value}...")

    try:
        cmd = [
            "nmap",
            "-sS",
            "-sV",
            "-T4",
            "--top-ports", "100",
            "--version-intensity", "4",
            "--open",
            "--max-retries", "2",
            "--host-timeout", "100s",
            value,
        ]
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        output = res.stdout or ""

        if "Nmap scan report" not in output and res.returncode != 0:
            result["error"] = f"nmap rc={res.returncode}"
            result["findings"].append(f"[ERROR] nmap failed: {(res.stderr or '')[:150]}")
            return result

        # Parse per-host blocks
        blocks = re.split(r"Nmap scan report for ", output)
        for block in blocks[1:]:
            first = block.splitlines()[0] if block else ""
            # Extract host / IP
            host_label = first.strip()
            ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", first)
            host_ip = ip_match.group(1) if ip_match else host_label.split()[0].strip("()")

            host_rec = {
                "host": host_ip,
                "label": host_label[:120],
                "ports": [],
                "services": [],
            }

            for line in block.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_id = parts[0].split("/")[0]
                    service = " ".join(parts[2:]).strip() if len(parts) > 2 else "unknown"
                    risk = _risk_for_port(port_id, service)

                    port_entry = {
                        "host": host_ip,
                        "port": port_id,
                        "service": service,
                        "risk_level": risk,
                        "source": "nmap",
                    }
                    result["open_ports"].append(port_entry)
                    host_rec["ports"].append(port_id)
                    if service not in host_rec["services"]:
                        host_rec["services"].append(service)

                    result["findings"].append(
                        f"[ACTIVE] {host_ip}:{port_id} ({service}) OPEN — {risk}"
                    )

            if host_rec["ports"]:
                result["hosts"].append(host_rec)

    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
        result["findings"].append(f"[ERROR] Scan of {value} timed out")
    except FileNotFoundError:
        result["error"] = "nmap not found"
        result["findings"].append("[ERROR] nmap binary not found")
    except Exception as e:
        result["error"] = str(e)
        result["findings"].append(f"[ERROR] {type(e).__name__}: {e}")

    return result


def run_scan(audit_data: dict) -> dict:
    """Multi-target external scan with improved fingerprinting."""
    targets = collect_targets(audit_data)

    if not targets:
        audit_data["external_scan"] = {
            "open_ports": [],
            "hosts": [],
            "vulnerabilities": ["[ERROR] No valid targets found"],
            "risk_score": 0,
            "targets_scanned": [],
            "targets_count": 0,
            "errors": 0,
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "error": "No valid targets",
        }
        print("[RECONVISION] No valid targets to scan")
        return audit_data

    print(f"\n[RECONVISION] Multi-target mode: {len(targets)} target(s)")

    all_ports: List[Dict] = []
    all_hosts: List[Dict] = []
    all_findings: List[str] = []
    per_target: List[Dict] = []
    errors = 0

    max_targets = 30
    if len(targets) > max_targets:
        print(f"[RECONVISION] Limiting to first {max_targets} targets (had {len(targets)})")
        targets = targets[:max_targets]

    for t in targets:
        res = scan_single_target(t)
        per_target.append({
            "target": res["target"],
            "type": res["type"],
            "open_ports_count": len(res["open_ports"]),
            "hosts_count": len(res.get("hosts") or []),
            "error": res["error"],
        })
        all_ports.extend(res["open_ports"])
        all_hosts.extend(res.get("hosts") or [])
        all_findings.extend(res["findings"])
        if res["error"]:
            errors += 1

    critical = sum(1 for p in all_ports if p.get("risk_level") == "critical")
    high = sum(1 for p in all_ports if p.get("risk_level") == "high")
    medium = len(all_ports) - critical - high
    risk_score = min(critical * 30 + high * 15 + medium * 5, 100)

    audit_data["external_scan"] = {
        "open_ports": all_ports,
        "hosts": all_hosts,
        "vulnerabilities": all_findings,
        "risk_score": risk_score,
        "targets_scanned": per_target,
        "targets_count": len(targets),
        "errors": errors,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "External footprint with service version detection. Non-destructive.",
    }

    print(
        f"[RECONVISION] Complete: {len(targets)} targets, "
        f"{len(all_hosts)} host(s), {len(all_ports)} open ports | Risk: {risk_score}/100\n"
    )
    return audit_data
