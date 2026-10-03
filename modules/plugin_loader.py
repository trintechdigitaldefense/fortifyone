#!/usr/bin/env python3
"""
PluginLoader - Simple extensibility for FortifyOne
TrinTech Digital Defense

Drop a Python file into modules/plugins/ that defines:
  PLUGIN_NAME = "mycheck"
  PLUGIN_VERSION = "1.0"
  def run(audit_data: dict) -> dict: ...

The loader discovers and runs enabled plugins safely.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

PLUGINS_DIR = Path(__file__).resolve().parent / "plugins"


def discover_plugins() -> List[Dict[str, Any]]:
    """Return list of available plugins with metadata."""
    found = []
    if not PLUGINS_DIR.is_dir():
        return found
    for path in sorted(PLUGINS_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"fortify_plugin_{path.stem}", path)
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            name = getattr(mod, "PLUGIN_NAME", path.stem)
            version = getattr(mod, "PLUGIN_VERSION", "0.0")
            run_fn = getattr(mod, "run", None)
            if callable(run_fn):
                found.append({
                    "name": name,
                    "version": version,
                    "path": str(path),
                    "run": run_fn,
                    "module": mod,
                })
        except Exception as e:
            found.append({
                "name": path.stem,
                "version": "error",
                "path": str(path),
                "error": str(e),
                "run": None,
            })
    return found


def run_plugins(audit_data: dict, only: List[str] | None = None) -> dict:
    """Execute discovered plugins. Results stored under audit_data['plugins']."""
    plugins = discover_plugins()
    results: Dict[str, Any] = {}
    for p in plugins:
        name = p["name"]
        if only and name not in only:
            continue
        if not p.get("run"):
            results[name] = {"error": p.get("error", "no run()")}
            continue
        try:
            print(f"[PLUGIN] Running {name} v{p.get('version')}...")
            audit_data = p["run"](audit_data)
            results[name] = {"status": "ok", "version": p.get("version")}
        except Exception as e:
            results[name] = {"status": "error", "error": f"{type(e).__name__}: {e}"}
            print(f"[PLUGIN] {name} failed: {e}")
    audit_data.setdefault("plugins", {})
    audit_data["plugins"]["ran"] = results
    audit_data["plugins"]["available"] = [
        {"name": p["name"], "version": p.get("version"), "path": p.get("path")}
        for p in plugins
    ]
    return audit_data


def list_plugins() -> List[Dict[str, str]]:
    return [
        {"name": p["name"], "version": str(p.get("version")), "path": p.get("path", "")}
        for p in discover_plugins()
    ]
