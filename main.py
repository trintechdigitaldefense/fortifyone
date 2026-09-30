#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║                 FORTIFYONE AUDIT FRAMEWORK                  ║
║                 TrinTech Digital Defense                    ║
║            "Securing Your Digital World"                    ║
║                      Version 4.1 (Hardened)                 ║
╚══════════════════════════════════════════════════════════════╝

Complete Cybersecurity Audit Orchestrator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Modules: ReconVision │ PolicyEngine │ BreachVault │ SaaS-Sentinel │ ReportGenius
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
from rich.text import Text
from rich import box

# ══════════════════════════════════════════════════════════════
# TRINTECH BRANDING & CONFIGURATION
# ══════════════════════════════════════════════════════════════

BRAND = {
    "name": "TrinTech Digital Defense",
    "tagline": "Securing Your Digital World",
    "url": "https://trintechdigitaldefense.github.io",
    "github": "https://github.com/trintechdigitaldefense",
    "facebook": "https://www.facebook.com/share/1ZCKz7dfpY/",
    "email": "contact@trintechdefense.com",
    "version": "4.1.0",
    "build": "Hardened"
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

# ══════════════════════════════════════════════════════════════
# PATHS & INITIALIZATION
# ══════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.resolve()
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"
MODULES_DIR = BASE_DIR / "modules"
SCHEMA_PATH = CONFIG_DIR / "schema.json"

for d in [CONFIG_DIR, DATA_DIR, OUTPUT_DIR, MODULES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════
# VALIDATION & SANITIZATION (HARDENED)
# ══════════════════════════════════════════════════════════════

def validate_ip(ip: str) -> str:
    """Strict IP validation. Raises ValueError on failure."""
    ip = (ip or "").strip()
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")

def validate_domain(domain: str) -> str:
    """Strict domain validation + block shell metacharacters."""
    domain = (domain or "").strip().lower()
    if not re.match(
        r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$",
        domain,
    ):
        raise ValueError(f"Invalid domain format: {domain}")
    forbidden = set(";|&$`<>()\n\r\\\"'")
    if any(c in domain for c in forbidden):
        raise ValueError("Domain contains forbidden characters")
    return domain

def sanitize_client_name(name: str) -> str:
    """Make client name safe for filenames. No path traversal."""
    clean = re.sub(r"[^a-zA-Z0-9_\- ]", "", (name or "")).strip()
    if not clean or len(clean) > 80:
        raise ValueError("Invalid or empty client name after sanitization")
    return clean

def print_auth_notice():
    """Print authorized-use warning."""
    console.print(Panel(AUTHORIZED_USE_NOTICE.strip(), border_style="red", title="Legal Notice"))

# ══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def load_schema() -> dict:
    """Load the universal audit data schema."""
    if not SCHEMA_PATH.exists():
        console.print(f"[red]✗ Schema missing at {SCHEMA_PATH}[/red]")
        raise FileNotFoundError(str(SCHEMA_PATH))
    with open(SCHEMA_PATH) as f:
        return json.load(f)

def save_audit(data: dict, client_name: str) -> Path:
    """Save audit data with timestamp. Sanitized name + restrictive permissions."""
    safe_name = sanitize_client_name(client_name)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{safe_name.replace(' ', '_')}_{ts}.json"
    fpath = DATA_DIR / fname
    with open(fpath, "w") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(fpath, 0o600)  # Owner read/write only
    except OSError:
        pass
    return fpath

def find_audit_files() -> list:
    """Return all audit files sorted by modification time."""
    return sorted(DATA_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)

def get_memory_mb() -> Optional[int]:
    """Get available system memory in MB."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    return int(line.split()[1]) // 1024
    except Exception:
        pass
    return None

def print_brand_header():
    """Print the TrinTech branded header."""
    console.print(Panel.fit(
        f"[bold cyan]FORTIFYONE[/bold cyan] [white]AUDIT FRAMEWORK[/white]\n"
        f"[bold]{BRAND['name']}[/bold]\n"
        f"[dim italic]\"{BRAND['tagline']}\"[/dim italic]\n"
        f"[dim]v{BRAND['version']} | {BRAND['build']} | {BRAND['url']}[/dim]",
        border_style="cyan"
    ))

def get_api_status() -> dict:
    """Check which API integrations are configured."""
    return {
        "Censys": bool(os.environ.get("CENSYS_API_ID")),
        "Shodan": bool(os.environ.get("SHODAN_API_KEY")),
        "HIBP": bool(os.environ.get("HIBP_API_KEY")),
    }

def print_api_table():
    """Display API integration status."""
    apis = get_api_status()
    table = Table(title="API Integrations", box=box.SIMPLE)
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="white")
    for name, configured in apis.items():
        if configured:
            table.add_row(name, "[green]✓ Connected[/green]")
        else:
            table.add_row(name, "[dim]○ Not Configured[/dim]")
    console.print(table)

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone new
# ══════════════════════════════════════════════════════════════

@app.command()
def new(
    client_name: str = typer.Option(..., "--client", "-c", help="Client company name"),
    domain: str = typer.Option(..., "--domain", "-d", help="Client domain (e.g., example.com)"),
    public_ip: str = typer.Option(..., "--ip", "-i", help="Client public IP address"),
    industry: str = typer.Option("General", "--industry", help="Industry: Healthcare, Legal, Finance, Retail, etc."),
):
    """
    🚀 Create a new security audit engagement.
    
    Example:
        fortifyone new --client "Acme Corp" --domain "acme.com" --ip "203.0.113.1" --industry "Healthcare"
    """
    print_brand_header()
    print_auth_notice()

    # Validate inputs early
    try:
        client_name = sanitize_client_name(client_name)
        domain = validate_domain(domain)
        public_ip = validate_ip(public_ip)
    except ValueError as e:
        console.print(f"[red]✗ Validation failed: {e}[/red]")
        raise typer.Exit(1)

    mem = get_memory_mb()
    console.print(f"[dim]System: Python {sys.version.split()[0]} | Memory: {mem} MB[/dim]")
    print_api_table()

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
    table.add_row("Frameworks", "NIST CSF, CIS v8, HIPAA")
    table.add_row("Auditor", BRAND["name"])
    console.print(table)

    console.print(f"\n[bold green]▶ Next Steps:[/bold green]")
    console.print(f"  [cyan]fortifyone run --file {fpath.name}[/cyan]")
    console.print(f"  [cyan]fortifyone list[/cyan]")
    console.print(f"\n[dim]{BRAND['tagline']} | {BRAND['url']}[/dim]")

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone list
# ══════════════════════════════════════════════════════════════

@app.command(name="list")
def list_audits():
    """
    📋 List all saved audit engagements.
    """
    print_brand_header()

    files = find_audit_files()
    if not files:
        console.print("[yellow]No audit files found.[/yellow]")
        console.print(f"[dim]Create one: fortifyone new --help[/dim]")
        return

    table = Table(title="Saved Audits", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Client", style="white")
    table.add_column("Date", style="dim")
    table.add_column("Size", style="dim")
    table.add_column("Status", style="green")

    for i, f in enumerate(files, 1):
        try:
            with open(f) as jf:
                data = json.load(jf)
            client = data.get("audit_metadata", {}).get("client_name", f.stem)
            date = data.get("audit_metadata", {}).get("date", "Unknown")[:10]
        except Exception:
            client = f.stem
            date = "Unknown"

        size_kb = f.stat().st_size / 1024
        status = "Updated" if "updated" in f.stem else "New"
        table.add_row(str(i), client, date, f"{size_kb:.1f} KB", status)

    console.print(table)
    console.print(f"\n[dim]Total: {len(files)} audits | Directory: {DATA_DIR}[/dim]")
    console.print(f"[dim]{BRAND['tagline']} | {BRAND['url']}[/dim]")

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone run
# ══════════════════════════════════════════════════════════════

@app.command()
def run(
    module: str = typer.Option("all", "--module", "-m", help="Module to run: all, external, policy, breach, saas"),
    audit_file: str = typer.Option(..., "--file", "-f", help="Audit JSON filename"),
):
    """
    ⚡ Execute automated security audit modules.
    
    Examples:
        fortifyone run --file client_20250101_120000.json
        fortifyone run --module breach --file client_20250101_120000.json
        fortifyone run --module external --file client_20250101_120000.json
    """
    print_brand_header()
    print_auth_notice()

    fpath = Path(audit_file)
    if not fpath.is_absolute():
        fpath = DATA_DIR / audit_file

    if not fpath.exists():
        console.print(f"[red]✗ File not found: {fpath}[/red]")
        console.print("[dim]Use 'fortifyone list' to see available audits[/dim]")
        raise typer.Exit(1)

    with open(fpath) as f:
        audit = json.load(f)

    client = audit["audit_metadata"]["client_name"]
    domain = audit["audit_metadata"]["domain"]

    # Re-validate stored targets before scanning
    try:
        validate_domain(domain)
        validate_ip(audit["audit_metadata"]["public_ip"])
    except ValueError as e:
        console.print(f"[red]✗ Stored target failed validation: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Target:[/bold] {client} ([dim]{domain}[/dim])")
    mem = get_memory_mb()
    if mem:
        console.print(f"[dim]Memory: {mem} MB[/dim]")
    console.print()

    module_results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # ── ReconVision: External Scan ──
        if module in ("all", "external"):
            task = progress.add_task("[cyan]🔍 ReconVision - External Scan...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from external_scan import run_scan
                audit = run_scan(audit)
                ports = len(audit["external_scan"].get("open_ports", []))
                risk = audit["external_scan"].get("risk_score", 0)
                module_results["External Scan"] = f"{ports} ports | Risk: {risk}/100"
                progress.update(task, description=f"[green]✓ ReconVision - {ports} ports, risk {risk}/100[/green]")
            except Exception as e:
                progress.update(task, description=f"[red]✗ ReconVision failed: {e}[/red]")

            # ── Shodan enrichment (optional, non-fatal) ──
            try:
                from shodan_scan import run_scan as shodan_run
                audit = shodan_run(audit)
                if audit.get("external_scan", {}).get("shodan_data"):
                    module_results["Shodan"] = "Enriched"
            except Exception as e:
                # Silent on missing key / network issues
                pass

        # ── PolicyEngine: Compliance Check ──
        if module in ("all", "policy"):
            task = progress.add_task("[cyan]📋 PolicyEngine - Compliance Check...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from policy_engine import run_questionnaire
                audit = run_questionnaire(audit, interactive=False)
                pct = audit["policy_compliance"]["overall_compliance_percentage"]
                module_results["Policy"] = f"{pct:.0f}% compliant"
                progress.update(task, description=f"[green]✓ PolicyEngine - {pct:.0f}% compliance[/green]")
            except Exception as e:
                progress.update(task, description=f"[red]✗ PolicyEngine failed: {e}[/red]")

        # ── BreachVault: Credential Check ──
        if module in ("all", "breach"):
            task = progress.add_task("[cyan]🔐 BreachVault - Credential Check...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from breach_vault import run_scan as breach_scan
                audit = breach_scan(audit)
                comp = audit["breach_exposure"].get("compromised_credentials", 0)
                risk = audit["breach_exposure"].get("risk_level", "unknown")
                module_results["Credentials"] = f"{comp} exposures | {risk.upper()}"
                progress.update(task, description=f"[green]✓ BreachVault - {comp} exposures ({risk})[/green]")
            except Exception as e:
                progress.update(task, description=f"[red]✗ BreachVault failed: {e}[/red]")

        # ── SaaS-Sentinel: Cloud Check ──
        if module in ("all", "saas"):
            task = progress.add_task("[cyan]☁️  SaaS-Sentinel - Cloud Security...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from saas_sentinel import run_scan as saas_scan
                audit = saas_scan(audit)
                grade = audit["saas_posture"].get("score_grade", "?")
                score = audit["saas_posture"].get("score", 0)
                module_results["SaaS"] = f"Grade {grade} ({score}/100)"
                progress.update(task, description=f"[green]✓ SaaS-Sentinel - Grade {grade} ({score}/100)[/green]")
            except Exception as e:
                progress.update(task, description=f"[yellow]⚠ SaaS-Sentinel: {e}[/yellow]")

    updated = save_audit(audit, f"{client}_updated")

    console.print(f"\n[bold green]═══ Audit Complete ═══[/bold green]")

    if module_results:
        results_table = Table(title="Results Summary", box=box.ROUNDED)
        results_table.add_column("Module", style="cyan")
        results_table.add_column("Result", style="white")
        for mod, result in module_results.items():
            results_table.add_row(mod, result)
        console.print(results_table)

    console.print(f"\n[dim]Saved: {updated.name}[/dim]")
    console.print(f"[bold green]▶ Generate Report:[/bold green]")
    console.print(f"  [cyan]fortifyone report --file {updated.name}[/cyan]")
    console.print(f"\n[dim]{BRAND['tagline']} | {BRAND['url']}[/dim]")

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone report
# ══════════════════════════════════════════════════════════════

@app.command()
def report(
    audit_file: str = typer.Option(..., "--file", "-f", help="Audit JSON filename"),
):
    """
    📊 Generate comprehensive audit deliverables.
    
    Outputs:
        - Executive HTML Report
        - Remediation Plan (CSV)
        - Raw Audit Data (JSON)
    """
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
    out_dir = OUTPUT_DIR / sanitize_client_name(client).replace(" ", "_")
    out_dir.mkdir(exist_ok=True)

    console.print(f"[bold]Generating reports for:[/bold] {client}\n")

    try:
        sys.path.insert(0, str(MODULES_DIR))
        from report_builder import generate_executive_report, generate_remediation_plan

        html_path = generate_executive_report(audit, str(out_dir))
        console.print(f"[green]✓[/green] Executive Report: [dim]{Path(html_path).name}[/dim]")

        csv_path = generate_remediation_plan(audit, str(out_dir))
        console.print(f"[green]✓[/green] Remediation Plan: [dim]{Path(csv_path).name}[/dim]")

        json_path = out_dir / "audit_summary.json"
        with open(json_path, "w") as f:
            json.dump(audit, f, indent=2, default=str)
        try:
            os.chmod(json_path, 0o600)
        except OSError:
            pass
        console.print(f"[green]✓[/green] Raw Data: [dim]{json_path.name}[/dim]")

        audit_report = {
            "generator": BRAND["name"],
            "version": BRAND["version"],
            "url": BRAND["url"],
            "timestamp": datetime.datetime.now().isoformat(),
            "audit_data": audit,
        }
        branded_json = out_dir / f"{sanitize_client_name(client).replace(' ', '_')}_Complete_Audit.json"
        with open(branded_json, "w") as f:
            json.dump(audit_report, f, indent=2, default=str)
        try:
            os.chmod(branded_json, 0o600)
        except OSError:
            pass
        console.print(f"[green]✓[/green] Complete Report: [dim]{branded_json.name}[/dim]")

    except Exception as e:
        console.print(f"[red]✗ Report generation failed: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold green]═══ Reports Ready ═══[/bold green]")
    console.print(f"[bold]Location:[/bold] {out_dir}")
    console.print(f"\n[dim]{BRAND['tagline']} | {BRAND['url']}[/dim]")

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone quick
# ══════════════════════════════════════════════════════════════

@app.command()
def quick(
    domain: str = typer.Option(..., "--domain", "-d", help="Target domain"),
    industry: str = typer.Option("General", "--industry", help="Industry context"),
    ip: str = typer.Option(None, "--ip", "-i", help="Optional public IP (auto-resolved if omitted)"),
):
    """
    ⚡ One-command rapid audit.
    
    Example:
        fortifyone quick --domain example.com --industry Healthcare
    """
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
            console.print(f"[dim]Resolved: {domain} → {ip}[/dim]")
        except Exception:
            console.print(f"[red]✗ Could not resolve {domain}[/red]")
            raise typer.Exit(1)
    else:
        try:
            ip = validate_ip(ip)
        except ValueError as e:
            console.print(f"[red]✗ {e}[/red]")
            raise typer.Exit(1)

    client_name = domain.split(".")[0].title()
    try:
        client_name = sanitize_client_name(client_name)
    except ValueError:
        client_name = "Quick_Audit"

    audit = load_schema()
    audit["audit_metadata"].update({
        "client_name": client_name,
        "domain": domain,
        "public_ip": ip,
        "industry": industry,
        "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(),
        "audit_type": "quick",
        "framework_version": BRAND["version"],
    })

    console.print(f"[bold]Quick Audit:[/bold] {domain} ([dim]{ip}[/dim])\n")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:

        task1 = progress.add_task("[cyan]ReconVision...", total=None)
        try:
            sys.path.insert(0, str(MODULES_DIR))
            from external_scan import run_scan
            audit = run_scan(audit)
            # Shodan enrichment
            try:
                from shodan_scan import run_scan as shodan_run
                audit = shodan_run(audit)
            except Exception:
                pass
            progress.update(task1, description="[green]✓[/green] ReconVision")
        except Exception:
            progress.update(task1, description="[yellow]⚠[/yellow] ReconVision")

        task2 = progress.add_task("[cyan]BreachVault...", total=None)
        try:
            from breach_vault import run_scan as breach_scan
            audit = breach_scan(audit)
            progress.update(task2, description="[green]✓[/green] BreachVault")
        except Exception:
            progress.update(task2, description="[yellow]⚠[/yellow] BreachVault")

        task3 = progress.add_task("[cyan]PolicyEngine...", total=None)
        try:
            from policy_engine import run_questionnaire
            audit = run_questionnaire(audit, interactive=False)
            progress.update(task3, description="[green]✓[/green] PolicyEngine")
        except Exception:
            progress.update(task3, description="[yellow]⚠[/yellow] PolicyEngine")

        task4 = progress.add_task("[cyan]SaaS-Sentinel...", total=None)
        try:
            from saas_sentinel import run_scan as saas_scan
            audit = saas_scan(audit)
            progress.update(task4, description="[green]✓[/green] SaaS-Sentinel")
        except Exception:
            progress.update(task4, description="[yellow]⚠[/yellow] SaaS-Sentinel")

    fpath = save_audit(audit, f"quick_{client_name}")

    # Summary
    external = audit.get("external_scan", {})
    breach = audit.get("breach_exposure", {})
    policy = audit.get("policy_compliance", {})
    saas = audit.get("saas_posture", {})

    table = Table(title="Quick Audit Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Result", style="white")
    table.add_row("Open Ports", str(len(external.get("open_ports", []))))
    table.add_row("External Risk", f"{external.get('risk_score', 0)}/100")
    table.add_row("Credential Exposures", str(breach.get("compromised_credentials", 0)))
    table.add_row("Breach Risk", str(breach.get("risk_level", "unknown")).upper())
    table.add_row("Policy Compliance", f"{policy.get('overall_compliance_percentage', 0):.0f}%")
    table.add_row("SaaS Grade", f"{saas.get('score_grade', 'N/A')} ({saas.get('score', 0)}/100)")
    console.print(table)

    console.print(f"\n[dim]Saved: {fpath.name}[/dim]")
    console.print(f"[bold green]▶ Generate Report:[/bold green]")
    console.print(f"  [cyan]fortifyone report --file {fpath.name}[/cyan]")
    console.print(f"\n[dim]{BRAND['tagline']} | {BRAND['url']}[/dim]")

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone info
# ══════════════════════════════════════════════════════════════

@app.command()
def info():
    """
    📊 System dashboard and module status.
    """
    print_brand_header()

    mem = get_memory_mb()
    sys_table = Table(title="System Status", box=box.ROUNDED)
    sys_table.add_column("Item", style="cyan")
    sys_table.add_column("Value", style="white")
    sys_table.add_row("Python", sys.version.split()[0])
    sys_table.add_row("Memory Available", f"{mem} MB" if mem else "Unknown")
    sys_table.add_row("Framework Version", BRAND["version"])
    sys_table.add_row("Build", BRAND["build"])
    sys_table.add_row("Audit Files", str(len(find_audit_files())))
    sys_table.add_row("Schema Status", "✓ Loaded" if SCHEMA_PATH.exists() else "✗ Missing")
    console.print(sys_table)

    mod_table = Table(title="Module Status", box=box.ROUNDED)
    mod_table.add_column("Module", style="cyan")
    mod_table.add_column("File", style="dim")
    mod_table.add_column("Status", style="white")

    modules = {
        "ReconVision": "external_scan.py",
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

    console.print(f"\n[bold]Contact:[/bold] {BRAND['email']}")
    console.print(f"[bold]Website:[/bold] {BRAND['url']}")
    console.print(f"[bold]GitHub:[/bold] {BRAND['github']}")
    console.print(f"\n[dim]{BRAND['tagline']} | {BRAND['url']}[/dim]")

# ══════════════════════════════════════════════════════════════
# COMMAND: fortifyone about
# ══════════════════════════════════════════════════════════════

@app.command()
def about():
    """
    🛡️  About TrinTech Digital Defense.
    """
    console.print(Panel.fit(
        f"""[bold cyan]{BRAND['name']}[/bold cyan]
        
        [white]\"{BRAND['tagline']}\"[/white]
        
        [dim]FortifyOne Audit Framework v{BRAND['version']} ({BRAND['build']})
        
        Professional cybersecurity auditing for local businesses.
        Built for rapid deployment on any device.
        
        Comprehensive security audits covering:
        • External Vulnerability Scanning (Nmap + Shodan)
        • Compliance Assessment (HIPAA, NIST, CIS)
        • Credential Exposure Analysis
        • SaaS/Cloud Security Posture
        • Executive Reporting with Attack Simulations
        
        ─────────────────────────────────
        
        🌐 {BRAND['url']}
        📧 {BRAND['email']}
        💻 {BRAND['github']}
        📱 {BRAND['facebook']}[/dim]""",
        title="About",
        border_style="cyan",
        box=box.ROUNDED
    ))

# ══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app()
