#!/usr/bin/env python3
"""Sample FortifyOne plugin — extra header checks (safe)."""
PLUGIN_NAME = "sample_header_check"
PLUGIN_VERSION = "1.0"

def run(audit_data: dict) -> dict:
    # Example: surface any TLS findings already present under a plugin key
    tls = audit_data.get("tls_posture", {})
    findings = tls.get("findings") or []
    audit_data.setdefault("plugins", {})
    audit_data["plugins"]["sample_header_check"] = {
        "extra_notes": f"Saw {len(findings)} TLS/HTTP findings",
        "status": "ok",
    }
    return audit_data
