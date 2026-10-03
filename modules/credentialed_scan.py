#!/usr/bin/env python3
"""
CredentialedScan - SSH MVP + WinRM readiness (safe, non-destructive)
TrinTech Digital Defense

Runs authorized remote checks over SSH using key-based auth.
Credentials are NEVER stored in the audit JSON — only via env/CLI.

Env (SSH):
  FORTIFYONE_SSH_HOST
  FORTIFYONE_SSH_USER
  FORTIFYONE_SSH_KEY      path to private key
  FORTIFYONE_SSH_PORT     default 22

Env (WinRM readiness — optional, no secrets stored):
  FORTIFYONE_WINRM_HOST
  FORTIFYONE_WINRM_USER
"""

from __future__ import annotations

import datetime
import os
import subprocess
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


def _winrm_readiness() -> Dict[str, Any]:
    host = _env("FORTIFYONE_WINRM_HOST")
    user = _env("FORTIFYONE_WINRM_USER")
    result = {
        "configured": bool(host and user),
        "host": host or None,
        "user": user or None,
        "status": "not_configured",
        "note": "WinRM auth requires pywinrm + secure credential handling (planned). No passwords are stored.",
    }
    if not host:
        return result
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        for port, label in ((5985, "HTTP"), (5986, "HTTPS")):
            try:
                rc = sock.connect_ex((host, port))
                if rc == 0:
                    result["status"] = f"port_{port}_open_{label}"
                    result["note"] = (
                        f"WinRM port {port} ({label}) appears open on {host}. "
                        "Full credentialed checks require pywinrm and explicit authorization."
                    )
                    break
            except Exception:
                continue
        else:
            result["status"] = "ports_closed_or_filtered"
        sock.close()
    except Exception as e:
        result["status"] = f"probe_error: {type(e).__name__}"
    return result


def run_scan(
    audit_data: dict,
    ssh_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None,
    ssh_port: int = 22,
) -> dict:
    print("\n[CREDENTIALED] Starting credentialed checks (SSH MVP + WinRM readiness)...")

    host = (ssh_host or _env("FORTIFYONE_SSH_HOST") or "").strip()
    user = (ssh_user or _env("FORTIFYONE_SSH_USER") or "").strip()
    key = (ssh_key or _env("FORTIFYONE_SSH_KEY") or "").strip()
    try:
        port = int(_env("FORTIFYONE_SSH_PORT", str(ssh_port)) or ssh_port)
    except ValueError:
        port = 22

    findings: List[Dict[str, Any]] = []
    checks_run = 0
    winrm = _winrm_readiness()

    if not host or not user:
        audit_data["credentialed_scan"] = {
            "enabled": False,
            "findings": [],
            "risk_score": 0,
            "winrm": winrm,
            "note": "Skipped - set FORTIFYONE_SSH_HOST and FORTIFYONE_SSH_USER (and key) to enable SSH checks",
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        print("[CREDENTIALED] Skipped SSH (no host/user). WinRM readiness recorded.")
        return audit_data

    rc, out = _run_ssh(host, user, key, port, "uname -a; id; echo '---'; hostname; uptime")
    checks_run += 1
    if rc == -2:
        findings.append({
            "title": "ssh client not available",
            "detail": out,
            "severity": "info",
            "category": "Credentialed",
        })
        audit_data["credentialed_scan"] = {
            "enabled": True, "host": host, "user": user,
            "findings": findings, "risk_score": 0, "winrm": winrm,
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        return audit_data
    if rc != 0:
        findings.append({
            "title": f"SSH connection failed to {user}@{host}:{port}",
            "detail": out[:300],
            "severity": "high",
            "category": "Credentialed",
            "remediation": "Verify key-based auth, network path, and authorized_keys.",
        })
    else:
        findings.append({
            "title": "SSH session established",
            "detail": out[:280],
            "severity": "info",
            "category": "Credentialed",
        })

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
                "remediation": "Set PasswordAuthentication no; use keys only.",
            })
        if "permitrootlogin yes" in low:
            findings.append({
                "title": "SSH PermitRootLogin is yes",
                "detail": out2[:220],
                "severity": "critical",
                "category": "SSH Hardening",
                "remediation": "Set PermitRootLogin no or prohibit-password.",
            })
        if "permitemptypasswords yes" in low:
            findings.append({
                "title": "SSH PermitEmptyPasswords is yes",
                "detail": out2[:200],
                "severity": "critical",
                "category": "SSH Hardening",
                "remediation": "Set PermitEmptyPasswords no immediately.",
            })
        if "x11forwarding yes" in low:
            findings.append({
                "title": "SSH X11Forwarding is yes",
                "detail": out2[:200],
                "severity": "medium",
                "category": "SSH Hardening",
                "remediation": "Disable X11Forwarding unless required.",
            })

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
                "remediation": "Remove world-write bit from configuration files.",
            })

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
                    "remediation": "Disable or firewall cleartext/management services.",
                })
            else:
                findings.append({
                    "title": "Listening ports captured",
                    "detail": f"{len(out4.splitlines())} lines collected for review",
                    "severity": "info",
                    "category": "Network",
                })

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
                "remediation": "Schedule reboot to apply kernel/security updates.",
            })
        if "Inst " in out5 or "upgraded" in out5 or "Security" in out5:
            findings.append({
                "title": "Package updates may be available",
                "detail": out5[:300],
                "severity": "medium",
                "category": "Patching",
                "remediation": "Apply security updates and enable automatic security patches.",
            })

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
                "remediation": "Review and restrict passwordless sudo to the minimum necessary.",
            })
        if out6 and "---" in out6:
            roots = [l.strip() for l in out6.split("---")[-1].splitlines() if l.strip()]
            if len(roots) > 1:
                findings.append({
                    "title": "Multiple UID 0 accounts",
                    "detail": ", ".join(roots)[:200],
                    "severity": "high",
                    "category": "Privilege",
                    "remediation": "Only one root account (UID 0) should exist.",
                })

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
                "remediation": "Enable and configure a host firewall (ufw, firewalld, or nftables).",
            })

    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    risk_score = min(critical * 30 + high * 15 + medium * 8, 100)

    audit_data["credentialed_scan"] = {
        "enabled": True,
        "host": host,
        "user": user,
        "port": port,
        "checks_run": checks_run,
        "findings": findings,
        "risk_score": risk_score,
        "winrm": winrm,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "SSH key-based MVP. Passwords never stored. WinRM readiness only (no auth).",
    }
    print(f"[CREDENTIALED] Complete: {len(findings)} findings | Risk {risk_score}/100 | WinRM={winrm.get('status')}\n")
    return audit_data


if __name__ == "__main__":
    print(run_scan({}).get("credentialed_scan"))
