#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                 FORTIFYONE AUDIT FRAMEWORK                  ║
║                 TrinTech Digital Defense                    ║
║            "Securing Your Digital World"                    ║
║                      Version 4.2 (Client-Ready)             ║
╚══════════════════════════════════════════════════════════════╝

Complete Cybersecurity Audit Orchestrator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Modules: ReconVision │ InternalScan │ PolicyEngine │ BreachVault │ SaaS-Sentinel │ ReportGenius
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AUTHORIZED USE ONLY.
Unauthorized scanning of systems you do not own or lack written
permission to test is illegal under the Trinidad & Tobago Cybercrime Act
and equivalent laws worldwide.
"""

import json
import os
import sys
import socket
import datetime
import ipaddress
import re
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

BRAND = {
    "name": "TrinTech Digital Defense",
    "tagline": "Securing Your Digital World",
    "url": "https://trintechdigitaldefense.github.io",
    "github": "https://github.com/trintechdigitaldefense",
    "facebook": "https://www.facebook.com/share/1ZCKz7dfpY/",
    "email": "contact@trintechdefense.com",
    "version": "4.2.0",
    "build": "Client-Ready"
}

AUTHORIZED_USE_NOTICE = """
[bold red]⚠ AUTHORIZED USE ONLY[/bold red]
This tool is for authorized security assessments only.
Unauthorized scanning is illegal. TrinTech Digital Defense accepts no liability for misuse.
Trinidad & Tobago Cybercrime Act and equivalent laws apply.
"""

console = Console()
app = typer.Typer(
    help=f"FortifyOne v{BRAND['version']} - {BRAND['name']}",
    epilog=f"{BRAND['tagline']} | {BRAND['url']}"
)

BASE_DIR = Path(__file__).parent.resolve()
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"
MODULES_DIR = BASE_DIR / "modules"
SCHEMA_PATH = CONFIG_DIR / "schema.json"

for d in [CONFIG_DIR, DATA_DIR, OUTPUT_DIR, MODULES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

def validate_ip(ip: str) -> str:
    ip = (ip or "").strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")

def validate_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", domain):
        raise ValueError(f"Invalid domain format: {domain}")
    forbidden = set(";|&$`<>()\n\r\\\"'")
    if any(c in domain for c in forbidden):
        raise ValueError("Domain contains forbidden characters")
    return domain

def sanitize_client_name(name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_\- ]", "", (name or "")).strip()
    if not clean or len(clean) > 80:
        raise ValueError("Invalid or empty client name after sanitization")
    return clean

def print_auth_notice():
    console.print(Panel(AUTHORIZED_USE_NOTICE.strip(), border_style="red", title="Legal Notice"))

def load_schema() -> dict:
    if not SCHEMA_PATH.exists():
        console.print(f"[red]✗ Schema missing at {SCHEMA_PATH}[/red]")
        raise FileNotFoundError(str(SCHEMA_PATH))
    with open(SCHEMA_PATH) as f:
        return json.load(f)

def save_audit(data: dict, client_name: str) -> Path:
    safe_name = sanitize_client_name(client_name)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{safe_name.replace(' ', '_')}_{ts}.json"
    fpath = DATA_DIR / fname
    with open(fpath, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(fpath, 0o600)
    except OSError:
        pass
    return fpath

def find_audit_files() -> list:
    return sorted(DATA_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)

def get_memory_mb() -> Optional[int]:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return None

def print_brand_header():
    console.print(Panel.fit(
        f"[bold cyan]FORTIFYONE[/bold cyan] [white]AUDIT FRAMEWORK[/white]\n"
        f"[bold]{BRAND['name']}[/bold]\n"
        f"[dim italic]\"{BRAND['tagline']}\"[/dim italic]\n"
        f"[dim]v{BRAND['version']} | {BRAND['build']} | {BRAND['url']}[/dim]",
        border_style="cyan"
    ))

def get_api_status() -> dict:
    return {
        "Censys": bool(os.environ.get("CENSYS_API_ID")),
        "Shodan": bool(os.environ.get("SHODAN_API_KEY")),
        "HIBP": bool(os.environ.get("HIBP_API_KEY")),
    }

def print_api_table():
    apis = get_api_status()
    table = Table(title="API Integrations", box=box.SIMPLE)
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="white")
    for name, configured in apis.items():
        table.add_row(name, "[green]✓ Connected[/green]" if configured else "[dim]○ Not Configured[/dim]")
    console.print(table)

@app.command()
def new(
    client_name: str = typer.Option(..., "--client", "-c", help="Client company name"),
    domain: str = typer.Option(..., "--domain", "-d", help="Client domain"),
    public_ip: str = typer.Option(..., "--ip", "-i", help="Client public IP"),
    industry: str = typer.Option("General", "--industry", help="Industry: Healthcare, Legal, Finance, Retail"),
    authorized_by: str = typer.Option("", "--authorized-by", help="Name of person authorizing the assessment"),
):
    """Create a new security audit engagement with scope/ROE support."""
    print_brand_header()
    print_auth_notice()
    try:
        client_name = sanitize_client_name(client_name)
        domain = validate_domain(domain)
        public_ip = validate_ip(public_ip)
    except ValueError as e:
        console.print(f"[red]✗ Validation failed: {e}[/red]")
        raise typer.Exit(1)

    audit = load_schema()
    audit["audit_metadata"].update({
        "client_name": client_name,
        "domain": domain,
        "public_ip": public_ip,
        "industry": industry,
        "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(),
        "framework_version": BRAND["version"],
    })
    # Scope / ROE defaults
    audit["scope"] = {
        "in_scope_targets": [public_ip, domain],
        "out_of_scope": [],
        "roe_text": "Authorized security assessment only. No denial-of-service, no social engineering of staff without explicit written approval, no data exfiltration.",
        "authorized_by": authorized_by or "Client representative",
        "authorization_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "notes": ""
    }

    fpath = save_audit(audit, client_name)
    console.print(f"\n[green]✓[/green] Audit engagement created for [bold]{client_name}[/bold]")
    console.print(f"[dim]Saved: {fpath.name}[/dim]")
    table = Table(title="Engagement Details", box=box.ROUNDED)
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Client", client_name)
    table.add_row("Domain", domain)
    table.add_row("Public IP", public_ip)
    table.add_row("Industry", industry)
    table.add_row("Authorized By", authorized_by or "(not specified)")
    table.add_row("Frameworks", "NIST CSF, CIS v8, HIPAA")
    console.print(table)
    console.print(f"\n[bold green]▶ Next:[/bold green] fortifyone run --file {fpath.name}")

@app.command(name="list")
def list_audits():
    """List all saved audit engagements."""
    print_brand_header()
    files = find_audit_files()
    if not files:
        console.print("[yellow]No audit files found.[/yellow]")
        return
    table = Table(title="Saved Audits", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Client", style="white")
    table.add_column("Date", style="dim")
    table.add_column("Size", style="dim")
    for i, f in enumerate(files, 1):
        try:
            with open(f) as jf:
                data = json.load(jf)
            client = data.get("audit_metadata", {}).get("client_name", f.stem)
            date = data.get("audit_metadata", {}).get("date", "Unknown")[:10]
        except Exception:
            client, date = f.stem, "Unknown"
        table.add_row(str(i), client, date, f"{f.stat().st_size/1024:.1f} KB")
    console.print(table)

@app.command()
def run(
    module: str = typer.Option("all", "--module", "-m", help="Module: all, external, internal, policy, breach, saas"),
    audit_file: str = typer.Option(..., "--file", "-f", help="Audit JSON filename"),
):
    """Execute automated security audit modules."""
    print_brand_header()
    print_auth_notice()
    fpath = Path(audit_file)
    if not fpath.is_absolute():
        fpath = DATA_DIR / audit_file
    if not fpath.exists():
        console.print(f"[red]✗ File not found: {fpath}[/red]")
        raise typer.Exit(1)
    with open(fpath) as f:
        audit = json.load(f)
    client = audit["audit_metadata"]["client_name"]
    domain = audit["audit_metadata"]["domain"]
    try:
        validate_domain(domain)
        validate_ip(audit["audit_metadata"]["public_ip"])
    except ValueError as e:
        console.print(f"[red]✗ Stored target failed validation: {e}[/red]")
        raise typer.Exit(1)
    console.print(f"[bold]Target:[/bold] {client} ([dim]{domain}[/dim])\n")
    module_results = {}
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        if module in ("all", "external"):
            task = progress.add_task("[cyan]🔍 ReconVision...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from external_scan import run_scan
                audit = run_scan(audit)
                ports = len(audit["external_scan"].get("open_ports", []))
                risk = audit["external_scan"].get("risk_score", 0)
                module_results["External"] = f"{ports} ports | Risk {risk}/100"
                progress.update(task, description=f"[green]✓ ReconVision - {ports} ports[/green]")
            except Exception as e:
                progress.update(task, description=f"[red]✗ ReconVision: {e}[/red]")
            try:
                from shodan_scan import run_scan as shodan_run
                audit = shodan_run(audit)
                if audit.get("external_scan", {}).get("shodan_data"):
                    module_results["Shodan"] = "Enriched"
            except Exception:
                pass
        if module in ("all", "internal"):
            task = progress.add_task("[cyan]🖧 InternalScan...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from internal_scan import run_scan as internal_run
                audit = internal_run(audit)
                hosts = audit.get("internal_scan", {}).get("hosts_discovered", 0)
                ports = len(audit.get("internal_scan", {}).get("open_ports", []))
                module_results["Internal"] = f"{hosts} hosts, {ports} ports"
                progress.update(task, description=f"[green]✓ InternalScan - {hosts} hosts[/green]")
            except Exception as e:
                progress.update(task, description=f"[yellow]⚠ InternalScan: {e}[/yellow]")
        if module in ("all", "policy"):
            task = progress.add_task("[cyan]📋 PolicyEngine...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from policy_engine import run_questionnaire
                audit = run_questionnaire(audit, interactive=False)
                pct = audit["policy_compliance"]["overall_compliance_percentage"]
                module_results["Policy"] = f"{pct:.0f}% compliant"
                progress.update(task, description=f"[green]✓ PolicyEngine - {pct:.0f}%[/green]")
            except Exception as e:
                progress.update(task, description=f"[red]✗ PolicyEngine: {e}[/red]")
        if module in ("all", "breach"):
            task = progress.add_task("[cyan]🔐 BreachVault...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from breach_vault import run_scan as breach_scan
                audit = breach_scan(audit)
                comp = audit["breach_exposure"].get("compromised_credentials", 0)
                module_results["Credentials"] = f"{comp} exposures"
                progress.update(task, description=f"[green]✓ BreachVault - {comp} exposures[/green]")
            except Exception as e:
                progress.update(task, description=f"[red]✗ BreachVault: {e}[/red]")
        if module in ("all", "saas"):
            task = progress.add_task("[cyan]☁️ SaaS-Sentinel...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from saas_sentinel import run_scan as saas_scan
                audit = saas_scan(audit)
                grade = audit["saas_posture"].get("score_grade", "?")
                module_results["SaaS"] = f"Grade {grade}"
                progress.update(task, description=f"[green]✓ SaaS-Sentinel - Grade {grade}[/green]")
            except Exception as e:
                progress.update(task, description=f"[yellow]⚠ SaaS-Sentinel: {e}[/yellow]")
    updated = save_audit(audit, f"{client}_updated")
    console.print(f"\n[bold green]═══ Audit Complete ═══[/bold green]")
    if module_results:
        t = Table(title="Results", box=box.ROUNDED)
        t.add_column("Module", style="cyan")
        t.add_column("Result")
        for m, r in module_results.items():
            t.add_row(m, r)
        console.print(t)
    console.print(f"\n[dim]Saved: {updated.name}[/dim]")
    console.print(f"[bold green]▶ Report:[/bold green] fortifyone report --file {updated.name}")

@app.command()
def report(audit_file: str = typer.Option(..., "--file", "-f", help="Audit JSON filename")):
    """Generate executive HTML + CSV remediation plan."""
    print_brand_header()
    print_auth_notice()
    fpath = Path(audit_file)
    if not fpath.is_absolute():
        fpath = DATA_DIR / audit_file
    if not fpath.exists():
        console.print(f"[red]✗ File not found[/red]")
        raise typer.Exit(1)
    with open(fpath) as f:
        audit = json.load(f)
    client = audit["audit_metadata"]["client_name"]
    out_dir = OUTPUT_DIR / sanitize_client_name(client).replace(" ", "_")
    out_dir.mkdir(exist_ok=True)
    try:
        sys.path.insert(0, str(MODULES_DIR))
        from report_builder import generate_executive_report, generate_remediation_plan
        html_path = generate_executive_report(audit, str(out_dir))
        csv_path = generate_remediation_plan(audit, str(out_dir))
        console.print(f"[green]✓[/green] Executive Report: {Path(html_path).name}")
        console.print(f"[green]✓[/green] Remediation Plan: {Path(csv_path).name}")
        json_path = out_dir / "audit_summary.json"
        with open(json_path, "w") as f:
            json.dump(audit, f, indent=2, default=str)
        console.print(f"[green]✓[/green] Raw Data: audit_summary.json")
    except Exception as e:
        console.print(f"[red]✗ Report failed: {e}[/red]")
        raise typer.Exit(1)
    console.print(f"\n[bold]Location:[/bold] {out_dir}")

@app.command()
def quick(
    domain: str = typer.Option(..., "--domain", "-d"),
    industry: str = typer.Option("General", "--industry"),
    ip: str = typer.Option(None, "--ip", "-i"),
):
    """One-command rapid external audit."""
    print_brand_header()
    print_auth_notice()
    try:
        domain = validate_domain(domain)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]")
        raise typer.Exit(1)
    if not ip:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            console.print(f"[red]✗ Could not resolve {domain}[/red]")
            raise typer.Exit(1)
    else:
        ip = validate_ip(ip)
    client_name = sanitize_client_name(domain.split(".")[0].title())
    audit = load_schema()
    audit["audit_metadata"].update({
        "client_name": client_name, "domain": domain, "public_ip": ip,
        "industry": industry, "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(), "framework_version": BRAND["version"], "audit_type": "quick"
    })
    audit["scope"] = {"in_scope_targets": [ip, domain], "out_of_scope": [], "roe_text": "Quick external assessment only.", "authorized_by": "Operator", "authorization_date": datetime.datetime.now().strftime("%Y-%m-%d")}
    console.print(f"[bold]Quick Audit:[/bold] {domain} ({ip})\n")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for name, mod in [("ReconVision", "external_scan"), ("BreachVault", "breach_vault"), ("PolicyEngine", "policy_engine"), ("SaaS-Sentinel", "saas_sentinel")]:
            task = progress.add_task(f"[cyan]{name}...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                if mod == "external_scan":
                    from external_scan import run_scan
                    audit = run_scan(audit)
                    try:
                        from shodan_scan import run_scan as s
                        audit = s(audit)
                    except Exception:
                        pass
                elif mod == "breach_vault":
                    from breach_vault import run_scan as run_scan
                    audit = run_scan(audit)
                elif mod == "policy_engine":
                    from policy_engine import run_questionnaire
                    audit = run_questionnaire(audit)
                elif mod == "saas_sentinel":
                    from saas_sentinel import run_scan as run_scan
                    audit = run_scan(audit)
                progress.update(task, description=f"[green]✓ {name}[/green]")
            except Exception:
                progress.update(task, description=f"[yellow]⚠ {name}[/yellow]")
    fpath = save_audit(audit, f"quick_{client_name}")
    console.print(f"\n[dim]Saved: {fpath.name}[/dim]")
    console.print(f"[bold green]▶ Report:[/bold green] fortifyone report --file {fpath.name}")

@app.command()
def info():
    """System dashboard and module status."""
    print_brand_header()
    mem = get_memory_mb()
    t = Table(title="System Status", box=box.ROUNDED)
    t.add_column("Item", style="cyan")
    t.add_column("Value")
    t.add_row("Python", sys.version.split()[0])
    t.add_row("Memory", f"{mem} MB" if mem else "Unknown")
    t.add_row("Version", BRAND["version"])
    t.add_row("Build", BRAND["build"])
    t.add_row("Audits", str(len(find_audit_files())))
    console.print(t)
    mod_table = Table(title="Module Status", box=box.ROUNDED)
    mod_table.add_column("Module", style="cyan")
    mod_table.add_column("File")
    mod_table.add_column("Status")
    modules = {
        "ReconVision": "external_scan.py",
        "InternalScan": "internal_scan.py",
        "PolicyEngine": "policy_engine.py",
        "BreachVault": "breach_vault.py",
        "SaaS-Sentinel": "saas_sentinel.py",
        "ReportGenius": "report_builder.py",
        "Shodan": "shodan_scan.py",
    }
    for name, filename in modules.items():
        exists = (MODULES_DIR / filename).exists()
        mod_table.add_row(name, filename, "[green]✓ Ready[/green]" if exists else "[red]✗ Missing[/red]")
    console.print(mod_table)
    print_api_table()

@app.command()
def about():
    """About TrinTech Digital Defense."""
    console.print(Panel.fit(
        f"[bold cyan]{BRAND['name']}[/bold cyan]\n\n[white]\"{BRAND['tagline']}\"[/white]\n\n[dim]FortifyOne v{BRAND['version']} ({BRAND['build']})\n\nProfessional cybersecurity auditing for local businesses.\n\n• External + Internal scanning\n• Industry-aware PolicyEngine\n• Credential exposure + SaaS posture\n• Executive HTML + CSV remediation\n\n🌐 {BRAND['url']}\n📧 {BRAND['email']}[/dim]",
        title="About", border_style="cyan", box=box.ROUNDED
    ))

if __name__ == "__main__":
    app()
