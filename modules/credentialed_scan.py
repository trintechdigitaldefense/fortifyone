#!/usr/bin/env python3
"""
CredentialedScan - SSH MVP (safe, non-destructive)
TrinTech Digital Defense

Runs authorized remote checks over SSH using key-based auth.
Credentials are NEVER stored in the audit JSON — only via env/CLI.

Env:
  FORTIFYONE_SSH_HOST
  FORTIFYONE_SSH_USER
  FORTIFYONE_SSH_KEY      path to private key
  FORTIFYONE_SSH_PORT     default 22
"""

from __future__ import annotations

import datetime
import os
import shlex
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
    # Single remote command string — no shell on local side beyond list form
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


def run_scan(
    audit_data: dict,
    ssh_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None,
    ssh_port: int = 22,
) -> dict:
    """
    Optional credentialed SSH checks.
    Skips cleanly if no host/user configured.
    """
    print("\n[CREDENTIALED] Starting SSH credentialed checks (MVP)...")

    host = (ssh_host or _env("FORTIFYONE_SSH_HOST") or "").strip()
    user = (ssh_user or _env("FORTIFYONE_SSH_USER") or "").strip()
    key = (ssh_key or _env("FORTIFYONE_SSH_KEY") or "").strip()
    try:
        port = int(_env("FORTIFYONE_SSH_PORT", str(ssh_port)) or ssh_port)
    except ValueError:
        port = 22

    if not host or not user:
        audit_data["credentialed_scan"] = {
            "enabled": False,
            "findings": [],
            "risk_score": 0,
            "note": "Skipped — set FORTIFYONE_SSH_HOST and FORTIFYONE_SSH_USER (and key) to enable",
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        print("[CREDENTIALED] Skipped (no SSH host/user configured)")
        return audit_data

    findings: List[Dict[str, Any]] = []
    checks_run = 0

    # Connectivity / identity
    rc, out = _run_ssh(host, user, key, port, "uname -a; id; echo '---'; hostname")
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
            "findings": findings, "risk_score": 0,
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
            "detail": out[:240],
            "severity": "info",
            "category": "Credentialed",
        })

        # Password auth in sshd_config
        rc2, out2 = _run_ssh(
            host, user, key, port,
            "grep -E '^(PasswordAuthentication|PermitRootLogin)\s' /etc/ssh/sshd_config 2>/dev/null || echo 'sshd_config unreadable'",
        )
        checks_run += 1
        low = out2.lower()
        if "passwordauthentication yes" in low:
            findings.append({
                "title": "SSH PasswordAuthentication is yes",
                "detail": out2[:200],
                "severity": "high",
                "category": "SSH Hardening",
                "remediation": "Set PasswordAuthentication no; use keys only.",
            })
        if "permitrootlogin yes" in low:
            findings.append({
                "title": "SSH PermitRootLogin is yes",
                "detail": out2[:200],
                "severity": "critical",
                "category": "SSH Hardening",
                "remediation": "Set PermitRootLogin no or prohibit-password.",
            })

        # World-writable sensitive paths sample
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

        # Listening services (limited)
        rc4, out4 = _run_ssh(
            host, user, key, port,
            "(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | head -40",
        )
        checks_run += 1
        if out4 and rc4 == 0:
            risky = []
            for line in out4.splitlines():
                if any(x in line for x in (":23 ", ":445 ", ":3389 ", ":5900 ", ":21 ")):
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

        # Unattended upgrades / pending updates hint (Debian/Ubuntu)
        rc5, out5 = _run_ssh(
            host, user, key, port,
            "(test -f /var/run/reboot-required && echo REBOOT_REQUIRED; "
            "apt-get -s upgrade 2>/dev/null | grep -E 'upgraded|Inst ' | head -5) || true",
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
        if "Inst " in out5 or "upgraded" in out5:
            findings.append({
                "title": "Package updates may be available",
                "detail": out5[:300],
                "severity": "medium",
                "category": "Patching",
                "remediation": "Apply security updates and enable automatic security patches.",
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
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "SSH key-based MVP only. Passwords are never stored in audit data. WinRM planned later.",
    }
    print(f"[CREDENTIALED] Complete: {len(findings)} findings | Risk {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    print(run_scan({})
          .get("credentialed_scan"))
