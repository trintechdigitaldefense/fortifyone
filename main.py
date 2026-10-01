#!/usr/bin/env python3
"""
FortifyOne Audit Framework v4.5 (VulnAware)
TrinTech Digital Defense – Securing Your Digital World
AUTHORIZED USE ONLY.
"""
import json, os, sys, socket, datetime, ipaddress, re
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

BRAND = {"name": "TrinTech Digital Defense", "tagline": "Securing Your Digital World",
         "url": "https://trintechdigitaldefense.github.io", "github": "https://github.com/trintechdigitaldefense",
         "email": "contact@trintechdefense.com", "version": "4.5.0", "build": "VulnAware"}
AUTHORIZED_USE_NOTICE = "[bold red]⚠ AUTHORIZED USE ONLY[/bold red]\nAuthorized security assessments only. Unauthorized scanning is illegal."
console = Console()
app = typer.Typer(help=f"FortifyOne v{BRAND['version']}")
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_DIR, DATA_DIR, OUTPUT_DIR, MODULES_DIR = BASE_DIR/"config", BASE_DIR/"data", BASE_DIR/"output", BASE_DIR/"modules"
SCHEMA_PATH = CONFIG_DIR / "schema.json"
for d in [CONFIG_DIR, DATA_DIR, OUTPUT_DIR, MODULES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

def validate_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", domain):
        raise ValueError(f"Invalid domain: {domain}")
    if any(c in domain for c in ";|&$`<>()\n\r\\\"'"):
        raise ValueError("Forbidden characters")
    return domain

def validate_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw: raise ValueError("Empty target")
    try:
        net = ipaddress.ip_network(raw, strict=False)
        if net.num_addresses > 512: raise ValueError("Range too large (max /23)")
        return str(net) if "/" in raw else str(net.network_address)
    except ValueError as e:
        if "too large" in str(e): raise
    return validate_domain(raw)

def sanitize_client_name(name: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_\- ]", "", (name or "")).strip()
    if not clean or len(clean) > 80: raise ValueError("Invalid client name")
    return clean

def parse_targets_list(targets_str=None, targets_file=None, primary_ip=None, primary_domain=None) -> List[str]:
    collected = []
    if targets_str:
        for part in re.split(r"[,;\s]+", targets_str):
            if part.strip(): collected.append(part.strip())
    if targets_file:
        path = Path(targets_file)
        if not path.exists(): raise ValueError(f"File not found: {targets_file}")
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"): collected.append(line)
    if primary_ip: collected.append(primary_ip)
    if primary_domain: collected.append(primary_domain)
    seen, valid = set(), []
    for t in collected:
        try:
            norm = validate_target(t)
            if norm not in seen:
                valid.append(norm); seen.add(norm)
        except ValueError as e:
            console.print(f"[yellow]⚠ Skipping '{t}': {e}[/yellow]")
    if not valid: raise ValueError("No valid targets")
    return valid

def print_auth_notice():
    console.print(Panel(AUTHORIZED_USE_NOTICE, border_style="red", title="Legal Notice"))

def load_schema() -> dict:
    with open(SCHEMA_PATH) as f: return json.load(f)

def save_audit(data: dict, client_name: str) -> Path:
    safe = sanitize_client_name(client_name)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fpath = DATA_DIR / f"{safe.replace(' ', '_')}_{ts}.json"
    with open(fpath, "w") as f: json.dump(data, f, indent=2)
    try: os.chmod(fpath, 0o600)
    except OSError: pass
    return fpath

def find_audit_files() -> list:
    return sorted(DATA_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)

def print_brand_header():
    console.print(Panel.fit(f"[bold cyan]FORTIFYONE[/bold cyan] v{BRAND['version']} ({BRAND['build']})\n[bold]{BRAND['name']}[/bold]\n[dim]{BRAND['tagline']}[/dim]", border_style="cyan"))

@app.command()
def new(client_name: str = typer.Option(..., "--client", "-c"),
        domain: str = typer.Option(None, "--domain", "-d"),
        public_ip: str = typer.Option(None, "--ip", "-i"),
        targets: str = typer.Option(None, "--targets", "-t"),
        targets_file: str = typer.Option(None, "--targets-file"),
        industry: str = typer.Option("General", "--industry"),
        authorized_by: str = typer.Option("", "--authorized-by")):
    """Create multi-target engagement."""
    print_brand_header(); print_auth_notice()
    try:
        client_name = sanitize_client_name(client_name)
        target_list = parse_targets_list(targets, targets_file, public_ip, domain)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    primary_domain, primary_ip = domain or "", public_ip or ""
    for t in target_list:
        try:
            ipaddress.ip_network(t, strict=False)
            if not primary_ip and "/" not in t: primary_ip = t
        except ValueError:
            if not primary_domain: primary_domain = t
    if not primary_ip:
        for t in target_list:
            try: primary_ip = str(ipaddress.ip_address(t)); break
            except ValueError: pass
    if not primary_ip: primary_ip = "0.0.0.0"
    audit = load_schema()
    audit["audit_metadata"].update({"client_name": client_name, "domain": primary_domain or target_list[0],
        "public_ip": primary_ip, "industry": industry, "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(), "framework_version": BRAND["version"]})
    audit["scope"] = {"in_scope_targets": target_list, "out_of_scope": [],
        "roe_text": "Authorized security assessment only. No DoS, no social engineering without written approval.",
        "authorized_by": authorized_by or "Client representative",
        "authorization_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "notes": f"{len(target_list)} target(s)"}
    fpath = save_audit(audit, client_name)
    console.print(f"[green]✓[/green] Created for [bold]{client_name}[/bold] ({len(target_list)} targets)")
    console.print(f"[dim]{fpath.name}[/dim] → fortifyone run --file {fpath.name}")

@app.command(name="list")
def list_audits():
    print_brand_header()
    files = find_audit_files()
    if not files: console.print("[yellow]No audits.[/yellow]"); return
    t = Table(title="Audits", box=box.ROUNDED)
    t.add_column("#", style="cyan"); t.add_column("Client"); t.add_column("Date", style="dim")
    for i, f in enumerate(files, 1):
        try:
            with open(f) as jf: data = json.load(jf)
            client = data.get("audit_metadata", {}).get("client_name", f.stem)
            date = str(data.get("audit_metadata", {}).get("date", ""))[:10]
        except Exception: client, date = f.stem, "?"
        t.add_row(str(i), client, date)
    console.print(t)

@app.command()
def run(module: str = typer.Option("all", "--module", "-m"),
        audit_file: str = typer.Option(..., "--file", "-f")):
    """Run modules (includes VulnProbe)."""
    print_brand_header(); print_auth_notice()
    fpath = Path(audit_file) if Path(audit_file).is_absolute() else DATA_DIR / audit_file
    if not fpath.exists(): console.print("[red]✗ Not found[/red]"); raise typer.Exit(1)
    with open(fpath) as f: audit = json.load(f)
    client = audit["audit_metadata"]["client_name"]
    console.print(f"[bold]Target:[/bold] {client}\n")
    results = {}
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        if module in ("all", "external"):
            task = progress.add_task("[cyan]🔍 ReconVision...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                from external_scan import run_scan
                audit = run_scan(audit)
                results["External"] = f"{audit['external_scan'].get('targets_count',1)} targets, {len(audit['external_scan'].get('open_ports',[]))} ports"
                progress.update(task, description="[green]✓ ReconVision[/green]")
            except Exception as e: progress.update(task, description=f"[red]✗ {e}[/red]")
            try:
                from shodan_scan import run_scan as s; audit = s(audit)
            except Exception: pass
        if module in ("all", "vuln", "external"):
            task = progress.add_task("[cyan]🔬 VulnProbe...", total=None)
            try:
                from vuln_probe import run_scan as vp
                audit = vp(audit)
                results["VulnProbe"] = f"{len(audit.get('vuln_probe',{}).get('findings',[]))} findings"
                progress.update(task, description="[green]✓ VulnProbe[/green]")
            except Exception as e: progress.update(task, description=f"[yellow]⚠ {e}[/yellow]")
        if module in ("all", "internal"):
            task = progress.add_task("[cyan]🖧 InternalScan...", total=None)
            try:
                from internal_scan import run_scan as ir
                audit = ir(audit)
                results["Internal"] = f"{audit.get('internal_scan',{}).get('hosts_discovered',0)} hosts"
                progress.update(task, description="[green]✓ InternalScan[/green]")
            except Exception as e: progress.update(task, description=f"[yellow]⚠ {e}[/yellow]")
        if module in ("all", "policy"):
            task = progress.add_task("[cyan]📋 PolicyEngine...", total=None)
            try:
                from policy_engine import run_questionnaire
                audit = run_questionnaire(audit)
                results["Policy"] = f"{audit['policy_compliance']['overall_compliance_percentage']:.0f}%"
                progress.update(task, description="[green]✓ PolicyEngine[/green]")
            except Exception as e: progress.update(task, description=f"[red]✗ {e}[/red]")
        if module in ("all", "breach"):
            task = progress.add_task("[cyan]🔐 BreachVault...", total=None)
            try:
                from breach_vault import run_scan as br
                audit = br(audit)
                results["Credentials"] = f"{audit['breach_exposure'].get('compromised_credentials',0)} hits"
                progress.update(task, description="[green]✓ BreachVault[/green]")
            except Exception as e: progress.update(task, description=f"[red]✗ {e}[/red]")
        if module in ("all", "saas"):
            task = progress.add_task("[cyan]☁️ SaaS-Sentinel...", total=None)
            try:
                from saas_sentinel import run_scan as sr
                audit = sr(audit)
                results["SaaS"] = audit["saas_posture"].get("score_grade", "?")
                progress.update(task, description="[green]✓ SaaS-Sentinel[/green]")
            except Exception as e: progress.update(task, description=f"[yellow]⚠ {e}[/yellow]")
    updated = save_audit(audit, f"{client}_updated")
    console.print("\n[bold green]═══ Complete ═══[/bold green]")
    if results:
        t = Table(box=box.ROUNDED); t.add_column("Module", style="cyan"); t.add_column("Result")
        for m, r in results.items(): t.add_row(m, r)
        console.print(t)
    console.print(f"[dim]{updated.name}[/dim] → fortifyone report --file {updated.name}")

@app.command()
def report(audit_file: str = typer.Option(..., "--file", "-f")):
    """HTML + PDF + CSV reports."""
    print_brand_header(); print_auth_notice()
    fpath = Path(audit_file) if Path(audit_file).is_absolute() else DATA_DIR / audit_file
    if not fpath.exists(): console.print("[red]✗ Not found[/red]"); raise typer.Exit(1)
    with open(fpath) as f: audit = json.load(f)
    client = audit["audit_metadata"]["client_name"]
    out_dir = OUTPUT_DIR / sanitize_client_name(client).replace(" ", "_")
    out_dir.mkdir(exist_ok=True)
    try:
        sys.path.insert(0, str(MODULES_DIR))
        from report_builder import generate_executive_report, generate_remediation_plan, generate_pdf_report
        html = generate_executive_report(audit, str(out_dir))
        csvp = generate_remediation_plan(audit, str(out_dir))
        pdf = generate_pdf_report(audit, str(out_dir))
        console.print(f"[green]✓[/green] HTML: {Path(html).name}")
        console.print(f"[green]✓[/green] PDF:  {Path(pdf).name}" if pdf else "[yellow]⚠ PDF skipped (pip install fpdf2)[/yellow]")
        console.print(f"[green]✓[/green] CSV:  {Path(csvp).name}")
        with open(out_dir / "audit_summary.json", "w") as f: json.dump(audit, f, indent=2, default=str)
    except Exception as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    console.print(f"\n[bold]{out_dir}[/bold]")

@app.command()
def quick(domain: str = typer.Option(None, "--domain", "-d"),
          ip: str = typer.Option(None, "--ip", "-i"),
          targets: str = typer.Option(None, "--targets", "-t"),
          targets_file: str = typer.Option(None, "--targets-file"),
          industry: str = typer.Option("General", "--industry")):
    """One-shot multi-target audit."""
    print_brand_header(); print_auth_notice()
    try: target_list = parse_targets_list(targets, targets_file, ip, domain)
    except ValueError as e: console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    primary_domain, primary_ip = domain or "", ip or ""
    for t in target_list:
        try:
            ipaddress.ip_network(t, strict=False)
            if not primary_ip and "/" not in t: primary_ip = t
        except ValueError:
            if not primary_domain: primary_domain = t
    if not primary_ip and primary_domain:
        try: primary_ip = socket.gethostbyname(primary_domain)
        except Exception: primary_ip = target_list[0]
    client_name = sanitize_client_name((primary_domain or target_list[0]).split(".")[0].title())
    audit = load_schema()
    audit["audit_metadata"].update({"client_name": client_name, "domain": primary_domain or "",
        "public_ip": primary_ip or "0.0.0.0", "industry": industry, "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(), "framework_version": BRAND["version"], "audit_type": "quick"})
    audit["scope"] = {"in_scope_targets": target_list, "out_of_scope": [], "roe_text": "Quick assessment.",
                      "authorized_by": "Operator", "authorization_date": datetime.datetime.now().strftime("%Y-%m-%d")}
    console.print(f"[bold]Quick:[/bold] {len(target_list)} targets\n")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for name, mod in [("ReconVision","external_scan"),("VulnProbe","vuln_probe"),("BreachVault","breach_vault"),
                          ("PolicyEngine","policy_engine"),("SaaS-Sentinel","saas_sentinel")]:
            task = progress.add_task(f"[cyan]{name}...", total=None)
            try:
                sys.path.insert(0, str(MODULES_DIR))
                if mod == "external_scan":
                    from external_scan import run_scan; audit = run_scan(audit)
                    try:
                        from shodan_scan import run_scan as s; audit = s(audit)
                    except Exception: pass
                elif mod == "vuln_probe":
                    from vuln_probe import run_scan as rs; audit = rs(audit)
                elif mod == "breach_vault":
                    from breach_vault import run_scan as rs; audit = rs(audit)
                elif mod == "policy_engine":
                    from policy_engine import run_questionnaire; audit = run_questionnaire(audit)
                else:
                    from saas_sentinel import run_scan as rs; audit = rs(audit)
                progress.update(task, description=f"[green]✓ {name}[/green]")
            except Exception: progress.update(task, description=f"[yellow]⚠ {name}[/yellow]")
    fpath = save_audit(audit, f"quick_{client_name}")
    console.print(f"[dim]{fpath.name}[/dim] → fortifyone report --file {fpath.name}")

@app.command()
def info():
    print_brand_header()
    t = Table(title="Status", box=box.ROUNDED); t.add_column("Item", style="cyan"); t.add_column("Value")
    t.add_row("Version", BRAND["version"]); t.add_row("Build", BRAND["build"]); t.add_row("Audits", str(len(find_audit_files())))
    console.print(t)
    mt = Table(title="Modules", box=box.ROUNDED); mt.add_column("Module", style="cyan"); mt.add_column("Status")
    for name, fn in [("ReconVision","external_scan.py"),("VulnProbe","vuln_probe.py"),("InternalScan","internal_scan.py"),
                     ("PolicyEngine","policy_engine.py"),("BreachVault","breach_vault.py"),("SaaS-Sentinel","saas_sentinel.py"),
                     ("ReportGenius","report_builder.py")]:
        mt.add_row(name, "[green]✓[/green]" if (MODULES_DIR/fn).exists() else "[red]✗[/red]")
    console.print(mt)

@app.command()
def about():
    console.print(Panel.fit(f"[bold cyan]{BRAND['name']}[/bold cyan]\n{BRAND['tagline']}\n\nFortifyOne v{BRAND['version']} ({BRAND['build']})\nMulti-target + VulnProbe + PDF reports\n\n{BRAND['url']}", title="About", border_style="cyan"))

if __name__ == "__main__":
    app()
