#!/usr/bin/env python3
"""
WatchMode - Lightweight scheduled / continuous external monitoring
TrinTech Digital Defense

Runs a safe subset of external checks (ports + TLS + basic web) and
produces a delta against the previous snapshot for the same client/targets.
Intended for cron / retainer use. Non-destructive only.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _snapshot_key(audit: dict) -> str:
    meta = audit.get("audit_metadata", {})
    client = (meta.get("client_name") or "unknown").replace(" ", "_")
    return f"watch_{client}"


def _load_previous(data_dir: Path, key: str) -> Optional[dict]:
    path = data_dir / f"{key}_last.json"
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _save_snapshot(data_dir: Path, key: str, snap: dict) -> Path:
    path = data_dir / f"{key}_last.json"
    path.write_text(json.dumps(snap, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def _extract_snapshot(audit: dict) -> dict:
    """Lightweight snapshot of external-facing state."""
    ext = audit.get("external_scan", {})
    tls = audit.get("tls_posture", {})
    web = audit.get("web_probe", {})
    ports = sorted(
        f"{p.get('host')}:{p.get('port')}/{p.get('service')}"
        for p in (ext.get("open_ports") or [])
        if isinstance(p, dict)
    )
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "open_ports": ports,
        "tls_risk": tls.get("risk_score", 0),
        "tls_findings": len(tls.get("findings") or []),
        "web_risk": web.get("risk_score", 0),
        "web_cms": web.get("cms"),
        "external_risk": ext.get("risk_score", 0),
    }


def compute_delta(previous: Optional[dict], current: dict) -> Dict[str, Any]:
    """Compare two snapshots and return human-readable delta."""
    if not previous:
        return {
            "status": "baseline",
            "message": "First watch run — baseline established.",
            "new_ports": current.get("open_ports") or [],
            "closed_ports": [],
            "risk_change": 0,
        }

    prev_ports = set(previous.get("open_ports") or [])
    curr_ports = set(current.get("open_ports") or [])
    new_ports = sorted(curr_ports - prev_ports)
    closed_ports = sorted(prev_ports - curr_ports)
    risk_change = (current.get("external_risk") or 0) - (previous.get("external_risk") or 0)

    status = "unchanged"
    if new_ports or closed_ports or abs(risk_change) >= 5:
        status = "changed"

    return {
        "status": status,
        "message": (
            f"Delta: +{len(new_ports)} new ports, -{len(closed_ports)} closed, "
            f"risk {risk_change:+d}"
        ),
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "risk_change": risk_change,
        "previous_timestamp": previous.get("timestamp"),
        "current_timestamp": current.get("timestamp"),
    }


def run_watch(audit_data: dict, data_dir: Path) -> dict:
    """
    Assume external + tls + web modules have already been run on audit_data.
    Produce delta and store new baseline.
    """
    key = _snapshot_key(audit_data)
    current = _extract_snapshot(audit_data)
    previous = _load_previous(data_dir, key)
    delta = compute_delta(previous, current)
    _save_snapshot(data_dir, key, current)

    audit_data["watch"] = {
        "key": key,
        "current": current,
        "delta": delta,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    print(f"[WATCH] {delta.get('message')}")
    return audit_data
