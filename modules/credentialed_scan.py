#!/usr/bin/env python3
"""
CredentialedScan - SSH + WinRM (MVP) with multi-host inventory support
TrinTech Digital Defense

Safe, non-destructive credentialed checks.
Credentials are NEVER stored in the audit JSON — only via env / CLI / inventory file.

SSH Env:
  FORTIFYONE_SSH_HOST / FORTIFYONE_SSH_USER / FORTIFYONE_SSH_KEY / FORTIFYONE_SSH_PORT
  FORTIFYONE_SSH_INVENTORY   path to simple inventory file (host user [key] [port] per line)

WinRM Env (optional, requires pywinrm for full checks):
  FORTIFYONE_WINRM_HOST / FORTIFYONE_WINRM_USER / FORTIFYONE_WINRM_PASS
  (or use inventory with winrm: prefix)
"""

from __future__ import annotations

import datetime
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _ssh_base(host: str, user: str, key: str, port: int) -> List[str]:
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=12",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
    ]
    if key:
        cmd += ["-i", key]
    cmd.append(f"{user}@{host}")
    return cmd


def _run_ssh(host: str, user: str, key: str, port: int, remote_cmd: str, timeout: int = 25) -> Tuple[int, str]:
    base = _ssh_base(host, user, key, port)
    full = base + [remote_cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (r.stderr or "")
        return r.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except FileNotFoundError:
        return -2, "ssh binary not found"
    except Exception as e:
        return -3, f"{type(e).__name__}: {e}"


def _load_inventory() -> List[Dict[str, Any]]:
    """Load multi-host inventory from env or file.
    Format (one per line):
      host user [key_path] [port]
      winrm:host user   # WinRM targets
    """
    hosts: List[Dict[str, Any]] = []
    inv_path = _env("FORTIFYONE_SSH_INVENTORY")
    if inv_path and Path(inv_path).is_file():
        with open(inv_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if not parts:
                    continue
                if parts[0].lower().startswith("winrm:"):
                    h = parts[0].split(":", 1)[-1]
                    u = parts[1] if len(parts) > 1 else _env("FORTIFYONE_WINRM_USER")
                    hosts.append({"type": "winrm", "host": h, "user": u})
                else:
                    h = parts[0]
                    u = parts[1] if len(parts) > 1 else _env("FORTIFYONE_SSH_USER")
                    k = parts[2] if len(parts) > 2 else _env("FORTIFYONE_SSH_KEY")
                    p = int(parts[3]) if len(parts) > 3 else int(_env("FORTIFYONE_SSH_PORT", "22") or 22)
                    hosts.append({"type": "ssh", "host": h, "user": u, "key": k, "port": p})
    # Single-host fallback from classic env
    if not hosts:
        h = _env("FORTIFYONE_SSH_HOST")
        u = _env("FORTIFYONE_SSH_USER")
        if h and u:
            hosts.append({
                "type": "ssh",
                "host": h,
                "user": u,
                "key": _env("FORTIFYONE_SSH_KEY"),
                "port": int(_env("FORTIFYONE_SSH_PORT", "22") or 22),
            })
        wh = _env("FORTIFYONE_WINRM_HOST")
        wu = _env("FORTIFYONE_WINRM_USER")
        if wh:
            hosts.append({"type": "winrm", "host": wh, "user": wu or None})
    return hosts


def _ssh_checks(host: str, user: str, key: str, port: int) -> Tuple[List[Dict], int]:
    """Run the standard SSH hardening checks against one host."""
    findings: List[Dict[str, Any]] = []
    checks_run = 0

    rc, out = _run_ssh(host, user, key, port, "uname -a; id; echo '---'; hostname; uptime")
    checks_run += 1
    if rc == -2:
        findings.append({
            "title": "ssh client not available",
            "detail": out,
            "severity": "info",
            "category": "Credentialed",
            "host": host,
        })
        return findings, checks_run
    if rc != 0:
        findings.append({
            "title": f"SSH connection failed to {user}@{host}:{port}",
            "detail": out[:300],
            "severity": "high",
            "category": "Credentialed",
            "host": host,
            "remediation": "Verify key-based auth, network path, and authorized_keys.",
            "controls": ["PR.AC-3", "CIS-5.1"],
        })
        return findings, checks_run

    findings.append({
        "title": f"SSH session established ({host})",
        "detail": out[:280],
        "severity": "info",
        "category": "Credentialed",
        "host": host,
    })

    # SSH hardening
    rc2, out2 = _run_ssh(
        host, user, key, port,
        "grep -E '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|MaxAuthTries)[[:space:]]' /etc/ssh/sshd_config 2>/dev/null || echo 'sshd_config unreadable'",
    )
    checks_run += 1
    low = out2.lower()
    if "passwordauthentication yes" in low:
        findings.append({
            "title": "SSH PasswordAuthentication is yes",
            "detail": out2[:220],
            "severity": "high",
            "category": "SSH Hardening",
            "host": host,
            "remediation": "Set PasswordAuthentication no; use keys only.",
            "controls": ["PR.AC-3", "CIS-5.1"],
        })
    if "permitrootlogin yes" in low:
        findings.append({
            "title": "SSH PermitRootLogin is yes",
            "detail": out2[:220],
            "severity": "critical",
            "category": "SSH Hardening",
            "host": host,
            "remediation": "Set PermitRootLogin no or prohibit-password.",
            "controls": ["PR.AC-3", "PR.AC-4"],
        })
    if "permitemptypasswords yes" in low:
        findings.append({
            "title": "SSH PermitEmptyPasswords is yes",
            "detail": out2[:200],
            "severity": "critical",
            "category": "SSH Hardening",
            "host": host,
            "remediation": "Set PermitEmptyPasswords no immediately.",
            "controls": ["PR.AC-1"],
        })
    if "x11forwarding yes" in low:
        findings.append({
            "title": "SSH X11Forwarding is yes",
            "detail": out2[:200],
            "severity": "medium",
            "category": "SSH Hardening",
            "host": host,
            "remediation": "Disable X11Forwarding unless required.",
            "controls": ["PR.AC-3"],
        })

    # World-writable
    rc3, out3 = _run_ssh(
        host, user, key, port,
        "find /etc /usr/local/etc -maxdepth 2 -type f -perm -0002 2>/dev/null | head -20",
    )
    checks_run += 1
    if out3 and "timeout" not in out3 and rc3 == 0 and out3.strip():
        findings.append({
            "title": "World-writable files under /etc (sample)",
            "detail": out3[:400],
            "severity": "high",
            "category": "Filesystem",
            "host": host,
            "remediation": "Remove world-write bit from configuration files.",
            "controls": ["PR.DS-5", "CIS-3.3"],
        })

    # Listeners
    rc4, out4 = _run_ssh(
        host, user, key, port,
        "(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | head -50",
    )
    checks_run += 1
    if out4 and rc4 == 0:
        risky = []
        for line in out4.splitlines():
            if any(x in line for x in (":23 ", ":445 ", ":3389 ", ":5900 ", ":21 ", ":512 ", ":513 ", ":514 ")):
                risky.append(line.strip())
        if risky:
            findings.append({
                "title": "Potentially risky listening services",
                "detail": "; ".join(risky)[:400],
                "severity": "high",
                "category": "Network",
                "host": host,
                "remediation": "Disable or firewall cleartext/management services.",
                "controls": ["PR.AC-3", "CIS-5.1"],
            })

    # Patch / reboot
    rc5, out5 = _run_ssh(
        host, user, key, port,
        "(test -f /var/run/reboot-required && echo REBOOT_REQUIRED; "
        "apt-get -s upgrade 2>/dev/null | grep -E 'upgraded|Inst ' | head -5; "
        "yum check-update --security 2>/dev/null | head -5) || true",
    )
    checks_run += 1
    if "REBOOT_REQUIRED" in out5:
        findings.append({
            "title": "Reboot required on host",
            "detail": out5[:200],
            "severity": "medium",
            "category": "Patching",
            "host": host,
            "remediation": "Schedule reboot to apply kernel/security updates.",
            "controls": ["PR.IP-1", "CIS-7.1"],
        })
    if "Inst " in out5 or "upgraded" in out5 or "Security" in out5:
        findings.append({
            "title": "Package updates may be available",
            "detail": out5[:300],
            "severity": "medium",
            "category": "Patching",
            "host": host,
            "remediation": "Apply security updates and enable automatic security patches.",
            "controls": ["PR.IP-1"],
        })

    # Sudo / UID 0
    rc6, out6 = _run_ssh(
        host, user, key, port,
        "(grep -E '^[^#].*ALL=.*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -10; "
        "echo '---'; awk -F: '$3==0{print $1}' /etc/passwd) || true",
    )
    checks_run += 1
    if out6 and "NOPASSWD" in out6:
        findings.append({
            "title": "NOPASSWD sudo entries detected",
            "detail": out6[:300],
            "severity": "high",
            "category": "Privilege",
            "host": host,
            "remediation": "Review and restrict passwordless sudo to the minimum necessary.",
            "controls": ["PR.AC-4", "CIS-5.4"],
        })
    if out6 and "---" in out6:
        roots = [l.strip() for l in out6.split("---")[-1].splitlines() if l.strip()]
        if len(roots) > 1:
            findings.append({
                "title": "Multiple UID 0 accounts",
                "detail": ", ".join(roots)[:200],
                "severity": "high",
                "category": "Privilege",
                "host": host,
                "remediation": "Only one root account (UID 0) should exist.",
                "controls": ["PR.AC-4"],
            })

    # Firewall
    rc7, out7 = _run_ssh(
        host, user, key, port,
        "(ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null || iptables -L -n 2>/dev/null | head -5 || echo 'no_firewall_tool') || true",
    )
    checks_run += 1
    low7 = out7.lower()
    if "inactive" in low7 or "not running" in low7 or "no_firewall_tool" in low7:
        findings.append({
            "title": "Host firewall appears inactive or unmanaged",
            "detail": out7[:250],
            "severity": "medium",
            "category": "Network",
            "host": host,
            "remediation": "Enable and configure a host firewall (ufw, firewalld, or nftables).",
            "controls": ["PR.AC-3", "CIS-5.1"],
        })

    # Passwordless local accounts via passwd -S style sample
    rc8b, out8b = _run_ssh(
        host, user, key, port,
        "getent passwd | awk -F: '$3>=1000 && $3<65000 {print $1}' | head -20 | while read u; do passwd -S \"$u\" 2>/dev/null; done | grep -E ' NP | L ' | head -10 || true",
    )
    checks_run += 1
    if out8b and "NP" in out8b:
        findings.append({
            "title": "Passwordless (NP) local account(s) indicated",
            "detail": out8b[:300],
            "severity": "critical",
            "category": "Identity",
            "host": host,
            "remediation": "Set passwords or lock accounts; enforce password policy.",
            "controls": ["PR.AC-1", "CIS-4.1"],
        })

    # SUID binaries sample (world-related risk)
    rc9, out9 = _run_ssh(
        host, user, key, port,
        "find /usr /bin /sbin -type f -perm -4000 2>/dev/null | head -25",
    )
    checks_run += 1
    if out9 and rc9 == 0 and out9.strip():
        findings.append({
            "title": "SUID binaries present (sample inventory)",
            "detail": out9[:400],
            "severity": "info",
            "category": "Privilege",
            "host": host,
            "remediation": "Review SUID binaries; remove unexpected setuid bits.",
            "controls": ["PR.AC-4"],
        })

    # Unattended upgrades / automatic security updates
    rc10, out10 = _run_ssh(
        host, user, key, port,
        "(cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; systemctl is-enabled unattended-upgrades 2>/dev/null; dnf -q versionlock list 2>/dev/null | head -3) || true",
    )
    checks_run += 1
    low10 = out10.lower()
    if out10 and "1" not in out10 and "enabled" not in low10:
        findings.append({
            "title": "Automatic security updates may not be enabled",
            "detail": out10[:250] or "No auto-upgrades configuration detected",
            "severity": "medium",
            "category": "Patching",
            "host": host,
            "remediation": "Enable unattended-upgrades (Debian/Ubuntu) or equivalent automatic security updates.",
            "controls": ["PR.IP-1", "CIS-7.1"],
        })

    # fail2ban / intrusion prevention hint
    rc11, out11 = _run_ssh(
        host, user, key, port,
        "(systemctl is-active fail2ban 2>/dev/null || systemctl is-active sshguard 2>/dev/null || echo 'no_bruteforce_protection') || true",
    )
    checks_run += 1
    if "no_bruteforce_protection" in out11 or (out11 and "inactive" in out11 and "active" not in out11):
        findings.append({
            "title": "No fail2ban/sshguard-style protection detected",
            "detail": out11[:200],
            "severity": "low",
            "category": "Network",
            "host": host,
            "remediation": "Deploy fail2ban or equivalent against SSH/auth brute force.",
            "controls": ["PR.AC-3"],
        })

    # Kernel / OS version for patching context
    rc12, out12 = _run_ssh(
        host, user, key, port,
        "uname -r; cat /etc/os-release 2>/dev/null | head -6",
    )
    checks_run += 1
    if out12 and rc12 == 0:
        findings.append({
            "title": "OS / kernel inventory",
            "detail": out12[:300],
            "severity": "info",
            "category": "Inventory",
            "host": host,
            "remediation": "Track OS lifecycle; upgrade EOL platforms.",
            "controls": ["ID.AM-1"],
        })

    return findings, checks_run


def _winrm_checks(host: str, user: Optional[str]) -> Dict[str, Any]:
    """WinRM readiness + optional authenticated checks if pywinrm is present."""
    result: Dict[str, Any] = {
        "configured": bool(host),
        "host": host or None,
        "user": user or None,
        "status": "not_configured",
        "findings": [],
        "note": "WinRM full checks require pywinrm. No passwords are stored in audit data.",
    }
    if not host:
        return result

    # TCP probe
    try:
        import socket
        open_ports = []
        for port, label in ((5985, "HTTP"), (5986, "HTTPS")):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(f"{port}/{label}")
                sock.close()
            except Exception:
                pass
        if open_ports:
            result["status"] = f"ports_open: {', '.join(open_ports)}"
            result["note"] = (
                f"WinRM port(s) open on {host}. "
                "Full credentialed checks require pywinrm + explicit authorization."
            )
        else:
            result["status"] = "ports_closed_or_filtered"
    except Exception as e:
        result["status"] = f"probe_error: {type(e).__name__}"

    # Optional authenticated checks
    try:
        import winrm  # type: ignore
        password = _env("FORTIFYONE_WINRM_PASS")
        if user and password:
            for scheme, port in (("https", 5986), ("http", 5985)):
                try:
                    sess = winrm.Session(
                        f"{scheme}://{host}:{port}/wsman",
                        auth=(user, password),
                        transport="ntlm",
                        server_cert_validation="ignore",
                    )
                    r = sess.run_cmd("hostname")
                    if r.status_code == 0:
                        result["status"] = f"authenticated_{scheme}"
                        result["hostname"] = (r.std_out or b"").decode(errors="ignore").strip()
                        # Simple safe checks
                        for cmd, title, sev in [
                            ("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"", "OS info", "info"),
                            ("net localgroup administrators", "Local administrators", "info"),
                            ("wmic qfe get HotFixID,InstalledOn /format:table", "Installed hotfixes (sample)", "info"),
                        ]:
                            try:
                                rr = sess.run_cmd(cmd)
                                out = (rr.std_out or b"").decode(errors="ignore")[:400]
                                result["findings"].append({
                                    "title": title,
                                    "detail": out,
                                    "severity": sev,
                                    "category": "WinRM",
                                    "host": host,
                                })
                            except Exception:
                                pass
                        break
                except Exception as e:
                    result["note"] = f"Auth attempt failed ({scheme}): {type(e).__name__}"
        else:
            result["note"] += " Set FORTIFYONE_WINRM_PASS for authenticated checks (never stored)."
    except ImportError:
        result["note"] = "pywinrm not installed — TCP readiness only. pip install pywinrm for full support."

    return result


def run_scan(
    audit_data: dict,
    ssh_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None,
    ssh_port: int = 22,
) -> dict:
    """
    Multi-host credentialed SSH checks + WinRM readiness / optional auth.
    Skips cleanly if nothing is configured.
    """
    print("\n[CREDENTIALED] Starting credentialed checks (SSH multi-host + WinRM)...")

    inventory = _load_inventory()

    # Allow single-host override from function args (legacy)
    if ssh_host and ssh_user and not any(h.get("host") == ssh_host for h in inventory):
        inventory.insert(0, {
            "type": "ssh",
            "host": ssh_host,
            "user": ssh_user,
            "key": ssh_key or _env("FORTIFYONE_SSH_KEY"),
            "port": ssh_port,
        })

    all_findings: List[Dict[str, Any]] = []
    total_checks = 0
    hosts_scanned: List[Dict[str, Any]] = []
    winrm_results: List[Dict[str, Any]] = []

    if not inventory:
        audit_data["credentialed_scan"] = {
            "enabled": False,
            "hosts_scanned": [],
            "findings": [],
            "risk_score": 0,
            "winrm": {},
            "note": "Skipped — set FORTIFYONE_SSH_HOST/USER (and KEY) or FORTIFYONE_SSH_INVENTORY",
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        print("[CREDENTIALED] Skipped (no hosts configured).")
        return audit_data

    for entry in inventory:
        if entry.get("type") == "winrm":
            wr = _winrm_checks(entry.get("host", ""), entry.get("user"))
            winrm_results.append(wr)
            for f in wr.get("findings", []):
                all_findings.append(f)
            hosts_scanned.append({"host": entry.get("host"), "type": "winrm", "status": wr.get("status")})
        else:
            h = entry["host"]
            u = entry.get("user") or ""
            k = entry.get("key") or ""
            p = int(entry.get("port") or 22)
            print(f"[CREDENTIALED] SSH → {u}@{h}:{p}")
            findings, checks = _ssh_checks(h, u, k, p)
            all_findings.extend(findings)
            total_checks += checks
            hosts_scanned.append({
                "host": h, "user": u, "type": "ssh",
                "findings": len(findings), "checks_run": checks,
            })

    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    high = sum(1 for f in all_findings if f.get("severity") == "high")
    medium = sum(1 for f in all_findings if f.get("severity") == "medium")
    risk_score = min(critical * 30 + high * 15 + medium * 8, 100)

    primary_winrm = winrm_results[0] if winrm_results else {}

    audit_data["credentialed_scan"] = {
        "enabled": True,
        "hosts_scanned": hosts_scanned,
        "hosts_count": len(hosts_scanned),
        "checks_run": total_checks,
        "findings": all_findings,
        "risk_score": risk_score,
        "winrm": primary_winrm,
        "winrm_all": winrm_results,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "SSH key-based multi-host MVP. Passwords never stored in audit JSON.",
    }
    print(f"[CREDENTIALED] Complete: {len(hosts_scanned)} host(s), {len(all_findings)} findings | Risk {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    print(run_scan({}).get("credentialed_scan"))
