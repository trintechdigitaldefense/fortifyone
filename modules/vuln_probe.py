#!/usr/bin/env python3
"""
VulnProbe v6.1 - Real vulnerability identification (safe, non-destructive)
TrinTech Digital Defense

Combines:
  - Expanded safe NSE scripts
  - Version/banner heuristics for known risky products
  - Curated template matching (config/vuln_templates.json)
  - Exposure heuristics for high-risk services
"""

from __future__ import annotations

import datetime
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

SAFE_SCRIPTS = [
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-ccs-injection",
    "ssl-dh-params",
    "smb-vuln-ms17-010",
    "smb-vuln-ms08-067",
    "smb-vuln-cve2009-3103",
    "http-slowloris-check",
    "http-csrf",
    "http-enum",
    "ftp-anon",
    "ftp-proftpd-backdoor",
    "sshv1",
    "ssh-auth-methods",
    "rdp-enum-encryption",
    "rdp-vuln-ms12-020",
    "mysql-empty-password",
    "mysql-info",
    "ms-sql-info",
    "ms-sql-empty-password",
    "redis-info",
    "mongodb-info",
    "dns-zone-transfer",
    "smtp-open-relay",
    "vnc-info",
    "afp-path-vuln",
]

# Banner/version patterns -> finding (severity, title, remediation)
VERSION_HEURISTICS: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"openssh[_\s]?([0-6]\.\d|7\.[0-3])", re.I),
     "high", "Outdated OpenSSH version indicated",
     "Upgrade OpenSSH to a current supported release; disable weak algorithms."),
    (re.compile(r"apache[/\s](1\.|2\.[0-2]\.)", re.I),
     "high", "Outdated Apache HTTP Server version indicated",
     "Upgrade Apache to a supported 2.4.x release and apply security patches."),
    (re.compile(r"nginx[/\s](0\.|1\.[0-9]\.|1\.1[0-7]\.)", re.I),
     "medium", "Older nginx version indicated",
     "Upgrade nginx to a current stable release."),
    (re.compile(r"microsoft[-\s]?iis[/\s]([1-7]\.)", re.I),
     "high", "Legacy IIS version indicated",
     "Upgrade IIS / underlying Windows; isolate or retire unsupported hosts."),
    (re.compile(r"openssl[/\s](0\.|1\.0\.[0-1])", re.I),
     "critical", "Severely outdated OpenSSL indicated",
     "Upgrade OpenSSL immediately; rotate certificates/keys if exposure is likely."),
    (re.compile(r"proftpd[/\s]1\.[0-2]\.", re.I),
     "high", "Older ProFTPD version indicated",
     "Upgrade ProFTPD or replace with SFTP; disable anonymous access."),
    (re.compile(r"vsftpd[/\s]2\.", re.I),
     "high", "Older vsftpd version indicated",
     "Upgrade vsftpd; prefer SFTP over FTP."),
    (re.compile(r"mysql[/\s](5\.[0-6]\.|4\.)", re.I),
     "high", "End-of-life MySQL version indicated",
     "Upgrade MySQL/MariaDB to a supported release; restrict network exposure."),
    (re.compile(r"postgresql[/\s](8\.|9\.|10\.)", re.I),
     "high", "Older PostgreSQL version indicated",
     "Upgrade PostgreSQL to a supported major version."),
    (re.compile(r"dropbear", re.I),
     "medium", "Dropbear SSH detected",
     "Ensure Dropbear is patched; prefer OpenSSH for production management."),
]


def _load_templates() -> List[dict]:
    candidates = [
        Path(__file__).resolve().parent.parent / "config" / "vuln_templates.json",
        Path("config/vuln_templates.json"),
    ]
    for p in candidates:
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data.get("templates", [])
            except Exception:
                pass
    return []


def _apply_templates(findings: List[dict], open_ports: List[dict], nse_text: str) -> List[dict]:
    templates = _load_templates()
    nse_low = nse_text.lower()
    seen: Set[Tuple] = {(f.get("target"), f.get("title")) for f in findings}

    for t in templates:
        tid = t.get("id", "")
        title = t.get("title", tid)
        sev = t.get("severity", "medium")
        rem = t.get("remediation", "Validate and remediate.")
        controls = t.get("controls") or []

        match_nse = [m.lower() for m in t.get("match_nse", [])]
        if match_nse and any(m in nse_low for m in match_nse):
            key = ("nse", title)
            if key not in seen:
                findings.append({
                    "target": "nse",
                    "title": title,
                    "detail": f"Template {tid} matched NSE output",
                    "severity": sev,
                    "source": f"template:{tid}",
                    "remediation": rem,
                    "controls": controls,
                })
                seen.add(key)

        ports = set(str(x) for x in t.get("match_port", []))
        services = [s.lower() for s in t.get("match_service", [])]
        for p in open_ports:
            port = str(p.get("port", ""))
            service = (p.get("service") or "").lower()
            host = p.get("host") or p.get("ip") or "unknown"
            hit = (ports and port in ports) or (services and any(s in service for s in services))
            if hit:
                key = (host, title)
                if key not in seen:
                    findings.append({
                        "target": host,
                        "port": port,
                        "title": title,
                        "detail": f"Service {service or 'unknown'} on port {port} matched template {tid}",
                        "severity": sev,
                        "source": f"template:{tid}",
                        "remediation": rem,
                        "controls": controls,
                    })
                    seen.add(key)
    return findings


def _version_findings(banner_text: str, target: str) -> List[dict]:
    out = []
    for pat, sev, title, rem in VERSION_HEURISTICS:
        m = pat.search(banner_text)
        if m:
            out.append({
                "target": target,
                "title": title,
                "detail": m.group(0)[:120],
                "severity": sev,
                "source": "version-heuristic",
                "remediation": rem,
                "controls": ["PR.IP-1", "CIS-7.1"],
            })
    return out


def _exposure_heuristics(open_ports: List[dict]) -> List[dict]:
    findings = []
    seen = set()
    for p in open_ports:
        service = (p.get("service") or "").lower()
        port = str(p.get("port", ""))
        host = p.get("host") or p.get("ip") or "unknown"
        key_base = (host, port)

        rules = [
            (("445", "microsoft-ds", "smb"), "critical", "SMB service exposed",
             "SMB on untrusted networks is high risk. Block from internet; require VPN."),
            (("3389", "ms-wbt", "rdp"), "critical", "RDP exposed",
             "Do not expose RDP to the internet. Use VPN/jump host + MFA + NLA."),
            (("23", "telnet"), "critical", "Telnet service detected",
             "Disable Telnet; use SSH only."),
            (("21", "ftp"), "high", "FTP service exposed",
             "Prefer SFTP; disable anonymous FTP; require encryption."),
            (("6379", "redis"), "critical", "Redis port exposed",
             "Bind Redis to localhost; require AUTH; never expose publicly."),
            (("27017", "mongodb"), "critical", "MongoDB port exposed",
             "Require auth; bind private; firewall public access."),
            (("9200", "elastic"), "critical", "Elasticsearch-like port exposed",
             "Enable authentication; restrict network access."),
            (("2375", "2376", "docker"), "critical", "Docker API port exposed",
             "Never expose Docker API to the internet without TLS + auth."),
            (("5900", "vnc"), "high", "VNC exposed",
             "Disable or firewall VNC; prefer modern remote access with MFA."),
            (("1433", "ms-sql"), "high", "MSSQL exposed",
             "Firewall SQL Server; strong auth; private connectivity."),
            (("3306", "mysql"), "high", "MySQL/MariaDB exposed",
             "Bind private; strong auth; no public internet exposure."),
            (("5432", "postgres"), "high", "PostgreSQL exposed",
             "Restrict to private networks; require auth + TLS."),
        ]
        for keys, sev, title, rem in rules:
            if port in keys or any(k in service for k in keys if not k.isdigit()):
                if key_base not in seen:
                    findings.append({
                        "target": host, "port": port, "title": title,
                        "detail": f"{service or 'unknown'} on {host}:{port}",
                        "severity": sev, "source": "exposure-heuristic",
                        "remediation": rem, "controls": ["PR.AC-3", "CIS-5.1"],
                    })
                    seen.add(key_base)
                break
    return findings


def run_scan(audit_data: dict) -> dict:
    print("\n[VULNPROBE] Starting vulnerability identification (NSE + version + templates)...")

    external = audit_data.get("external_scan", {})
    open_ports = list(external.get("open_ports") or [])
    # Also include internal open ports for exposure context
    for p in (audit_data.get("internal_scan") or {}).get("open_ports") or []:
        if isinstance(p, dict):
            open_ports.append(p)

    targets: Set[str] = set()
    for p in open_ports:
        host = p.get("host") or p.get("ip")
        if host:
            targets.add(str(host))
    primary = audit_data.get("audit_metadata", {}).get("public_ip")
    if primary and primary not in ("0.0.0.0", "127.0.0.1"):
        targets.add(primary)
    domain = audit_data.get("audit_metadata", {}).get("domain")
    if domain:
        targets.add(domain)

    if not targets:
        audit_data["vuln_probe"] = {
            "findings": [], "risk_score": 0, "templates_loaded": len(_load_templates()),
            "note": "No targets available for probing",
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        print("[VULNPROBE] No targets – skipped")
        return audit_data

    findings: List[Dict[str, Any]] = []
    script_hits = 0
    nse_blob: List[str] = []
    target_list = list(targets)[:8]
    print(f"[VULNPROBE] Probing {len(target_list)} target(s)...")

    for target in target_list:
        try:
            cmd = [
                "nmap", "-sV", "-T4",
                "--version-intensity", "4",
                "--script", ",".join(SAFE_SCRIPTS),
                "--script-args", "unsafe=0",
                "--top-ports", "100", "--open",
                "--max-retries", "1", "--host-timeout", "120s",
                target,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            out = res.stdout or ""
            nse_blob.append(out)
            findings.extend(_version_findings(out, target))

            current_port = None
            for line in out.splitlines():
                line_s = line.strip()
                if "/tcp" in line_s and "open" in line_s:
                    parts = line_s.split()
                    current_port = parts[0].split("/")[0]
                    # Capture version strings into open_ports if missing
                    if len(parts) > 3:
                        ver_blob = " ".join(parts[2:])
                        open_ports.append({
                            "host": target, "port": current_port,
                            "service": ver_blob, "source": "vuln_probe-sv",
                        })
                up = line_s.upper()
                if "VULNERABLE" in up or "LIKELY VULNERABLE" in up:
                    script_hits += 1
                    findings.append({
                        "target": target,
                        "port": current_port or "unknown",
                        "title": f"NSE vulnerability indicator on {target}",
                        "detail": line_s[:220],
                        "severity": "critical" if "VULNERABLE" in up else "high",
                        "source": "nmap-nse",
                        "remediation": "Validate NSE finding and patch/mitigate the affected service.",
                        "controls": ["PR.IP-1"],
                    })
                if "anonymous" in line_s.lower() and "logged" in line_s.lower():
                    findings.append({
                        "target": target, "port": current_port or "21",
                        "title": "Anonymous access indicated",
                        "detail": line_s[:200], "severity": "high", "source": "nmap-nse",
                        "remediation": "Disable anonymous access.",
                        "controls": ["PR.AC-1"],
                    })
                if "sshv1" in line_s.lower() or "ssh protocol 1" in line_s.lower():
                    findings.append({
                        "target": target, "port": "22",
                        "title": "Obsolete SSHv1 protocol supported",
                        "detail": line_s[:200], "severity": "high", "source": "nmap-nse",
                        "remediation": "Disable SSH protocol 1; allow SSH-2 only.",
                        "controls": ["PR.AC-3"],
                    })
        except subprocess.TimeoutExpired:
            findings.append({
                "target": target, "title": "Probe timed out",
                "detail": f"Scan of {target} exceeded time limit",
                "severity": "info", "source": "vuln_probe",
            })
        except FileNotFoundError:
            findings.append({
                "target": target, "title": "nmap not found",
                "detail": "Install nmap to enable vulnerability probing",
                "severity": "info", "source": "vuln_probe",
            })
            break
        except Exception as e:
            findings.append({
                "target": target, "title": f"Probe error: {type(e).__name__}",
                "detail": str(e)[:150], "severity": "info", "source": "vuln_probe",
            })

    nse_text = "\n".join(nse_blob)
    findings = _apply_templates(findings, open_ports, nse_text)
    findings.extend(_exposure_heuristics(open_ports))

    # Dedup by target+title
    deduped = []
    seen_keys = set()
    for f in findings:
        k = (f.get("target"), f.get("title"), f.get("port"))
        if k not in seen_keys:
            seen_keys.add(k)
            deduped.append(f)

    crit = sum(1 for f in deduped if f.get("severity") == "critical")
    high = sum(1 for f in deduped if f.get("severity") == "high")
    med = sum(1 for f in deduped if f.get("severity") == "medium")
    risk = min(crit * 25 + high * 12 + med * 5, 100)
    templates_n = len(_load_templates())

    audit_data["vuln_probe"] = {
        "findings": deduped,
        "script_hits": script_hits,
        "targets_probed": len(target_list),
        "templates_loaded": templates_n,
        "risk_score": risk,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "NSE + version heuristics + templates + exposure rules (non-destructive).",
    }
    print(f"[VULNPROBE] Complete: {len(deduped)} findings | NSE hits={script_hits} | templates={templates_n} | Risk {risk}/100")
    return audit_data
