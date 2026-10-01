#!/usr/bin/env python3
"""
ReconVision - External Footprint Scanner (v4.3 Multi-Target)
TrinTech Digital Defense

Supports single IP, domain, multiple targets, and CIDR ranges.
Authorized use only.
"""

import datetime
import ipaddress
import re
import subprocess
from typing import List, Dict, Any, Tuple, Optional


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
    """
    Parse a single target string into a normalized dict.
    Returns None if invalid.
    Supports: IPv4, IPv6, CIDR (v4/v6), domain.
    """
    raw = (raw or "").strip()
    if not raw:
        return None

    # Try CIDR / IP first
    try:
        net = ipaddress.ip_network(raw, strict=False)
        # Safety: reject huge ranges
        if net.num_addresses > 512:  # /23 and larger blocked for external scans
            print(f"[RECONVISION] Skipping oversized range {raw} ({net.num_addresses} addresses). Max /23 (512 hosts).")
            return None
        return {
            "type": "cidr" if "/" in raw else "ip",
            "value": str(net) if "/" in raw else str(net.network_address),
            "original": raw,
        }
    except ValueError:
        pass

    # Domain
    if is_valid_domain(raw):
        return {"type": "domain", "value": raw.lower(), "original": raw}

    return None


def collect_targets(audit_data: dict) -> List[Dict[str, str]]:
    """
    Build the list of targets to scan from scope.in_scope_targets
    plus legacy public_ip / domain fields.
    """
    targets: List[Dict[str, str]] = []
    seen = set()

    # Prefer explicit scope list
    scope_targets = audit_data.get("scope", {}).get("in_scope_targets", []) or []
    for t in scope_targets:
        parsed = parse_target(str(t))
        if parsed and parsed["value"] not in seen:
            targets.append(parsed)
            seen.add(parsed["value"])

    # Fallback / also include primary fields if not already present
    meta = audit_data.get("audit_metadata", {})
    for key in ("public_ip", "domain"):
        val = meta.get(key, "")
        if val:
            parsed = parse_target(str(val))
            if parsed and parsed["value"] not in seen:
                targets.append(parsed)
                seen.add(parsed["value"])

    return targets


def scan_single_target(target: Dict[str, str], timeout: int = 180) -> Dict[str, Any]:
    """Scan one target (IP, domain, or small CIDR). Returns result dict."""
    value = target["value"]
    ttype = target["type"]
    result = {
        "target": value,
        "type": ttype,
        "open_ports": [],
        "findings": [],
        "error": None,
    }

    # Refuse localhost
    if value in ("0.0.0.0", "127.0.0.1", "::1", "localhost") or value.startswith("127."):
        result["error"] = "Refusing to scan localhost"
        result["findings"].append("[ERROR] Refusing to scan localhost / zero address")
        return result

    print(f"[RECONVISION] Scanning {ttype}: {value}...")

    try:
        cmd = [
            "nmap",
            "-sS",
            "-T4",
            "--top-ports", "100",
            "-sV",
            "--version-intensity", "3",
            "--open",
            "--max-retries", "2",
            "--host-timeout", "90s",
            value,
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        current_host = value
        if "Nmap scan report" not in res.stdout and res.returncode != 0:
            result["error"] = f"nmap rc={res.returncode}"
            result["findings"].append(f"[ERROR] nmap failed: {res.stderr[:150]}")
        else:
            for line in res.stdout.splitlines():
                if "Nmap scan report for" in line:
                    # Extract host if scanning a range
                    parts = line.split()
                    current_host = parts[-1].strip("()")
                elif "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_id = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else "unknown"

                    if port_id in ("3389", "445", "135", "139", "5900"):
                        risk = "critical"
                    elif port_id in ("22", "23", "21", "3306", "5432", "1433", "27017"):
                        risk = "high"
                    else:
                        risk = "medium"

                    result["open_ports"].append({
                        "host": current_host,
                        "port": port_id,
                        "service": service,
                        "risk_level": risk,
                        "source": "nmap",
                    })
                    result["findings"].append(
                        f"[ACTIVE] {current_host}:{port_id} ({service}) OPEN — {risk}"
                    )

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
    """
    Multi-target external scan.
    Uses scope.in_scope_targets when present; falls back to single public_ip/domain.
    """
    targets = collect_targets(audit_data)

    if not targets:
        audit_data["external_scan"] = {
            "open_ports": [],
            "vulnerabilities": ["[ERROR] No valid targets found"],
            "risk_score": 0,
            "targets_scanned": [],
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "error": "No valid targets",
        }
        print("[RECONVISION] No valid targets to scan")
        return audit_data

    print(f"\n[RECONVISION] Multi-target mode: {len(targets)} target(s)")

    all_ports: List[Dict] = []
    all_findings: List[str] = []
    per_target: List[Dict] = []
    errors = 0

    # Safety limit
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
            "error": res["error"],
        })
        all_ports.extend(res["open_ports"])
        all_findings.extend(res["findings"])
        if res["error"]:
            errors += 1

    # Aggregate risk
    critical = sum(1 for p in all_ports if p["risk_level"] == "critical")
    high = sum(1 for p in all_ports if p["risk_level"] == "high")
    medium = len(all_ports) - critical - high
    risk_score = min(critical * 30 + high * 15 + medium * 6, 100)

    audit_data["external_scan"] = {
        "open_ports": all_ports,
        "vulnerabilities": all_findings,
        "risk_score": risk_score,
        "targets_scanned": per_target,
        "targets_count": len(targets),
        "errors": errors,
        "scan_timestamp": datetime.datetime.now().isoformat(),
    }

    print(f"[RECONVISION] Complete: {len(targets)} targets, {len(all_ports)} open ports | Risk: {risk_score}/100\n")
    return audit_data
