#!/usr/bin/env python3
"""FortifyOne Audit Engine v6.1 - TrinTech Digital Defense. AUTHORIZED USE ONLY."""
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
         "url": "https://trintechdigitaldefense.github.io", "version": "6.1.0", "build": "Professional"}
NOTICE = "[bold red]⚠ AUTHORIZED USE ONLY[/bold red]\nAuthorized assessments only. Unauthorized scanning is illegal."
console = Console()
app = typer.Typer(help=f"FortifyOne v{BRAND['version']}")
BASE = Path(__file__).parent.resolve()
CONFIG, DATA, OUTPUT, MODULES = BASE/"config", BASE/"data", BASE/"output", BASE/"modules"
SCHEMA = CONFIG/"schema.json"
for d in (CONFIG, DATA, OUTPUT, MODULES):
    d.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(MODULES))
try:
    from crypto_utils import save_json_secure, load_json_secure, sign_file, verify_file, crypto_status, is_encrypted_bytes
    HAS_CRYPTO_UTILS = True
except ImportError:
    HAS_CRYPTO_UTILS = False

def validate_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", d):
        raise ValueError(f"Invalid domain: {d}")
    if any(c in d for c in ";|&$`<>()\n\r\\\"'"):
        raise ValueError("Forbidden characters")
    return d

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

def parse_targets(targets_str=None, targets_file=None, ip=None, domain=None) -> List[str]:
    collected = []
    if targets_str:
        for p in re.split(r"[,;\s]+", targets_str):
            if p.strip(): collected.append(p.strip())
    if targets_file:
        path = Path(targets_file)
        if not path.exists(): raise ValueError(f"File not found: {targets_file}")
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"): collected.append(line)
    if ip: collected.append(ip)
    if domain: collected.append(domain)
    seen, valid = set(), []
    for t in collected:
        try:
            n = validate_target(t)
            if n not in seen:
                valid.append(n); seen.add(n)
        except ValueError as e:
            console.print(f"[yellow]⚠ Skip '{t}': {e}[/yellow]")
    if not valid: raise ValueError("No valid targets")
    return valid

def load_schema() -> dict:
    with open(SCHEMA) as f: return json.load(f)

def save_audit(data: dict, client: str, passphrase: Optional[str] = None) -> Path:
    safe = sanitize_client_name(client)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = DATA / f"{safe.replace(' ', '_')}_{ts}.json"
    if HAS_CRYPTO_UTILS:
        if save_json_secure(path, data, passphrase=passphrase):
            console.print("[dim]🔒 Audit saved encrypted[/dim]")
    else:
        with open(path, "w") as f: json.dump(data, f, indent=2)
        try: os.chmod(path, 0o600)
        except OSError: pass
    return path

def find_audits() -> list:
    return sorted(list(DATA.glob("*.json")), key=os.path.getmtime, reverse=True)

def header():
    console.print(Panel.fit(f"[bold cyan]FORTIFYONE[/bold cyan] v{BRAND['version']} ({BRAND['build']})\n[bold]{BRAND['name']}[/bold]\n[dim]{BRAND['tagline']}[/dim]", border_style="cyan"))

def auth():
    console.print(Panel(NOTICE, border_style="red", title="Legal Notice"))

def load_audit(name: str, passphrase: Optional[str] = None) -> dict:
    path = Path(name) if Path(name).is_absolute() else DATA / name
    if not path.exists():
        console.print("[red]✗ File not found[/red]"); raise typer.Exit(1)
    if HAS_CRYPTO_UTILS:
        try: return load_json_secure(path, passphrase=passphrase)
        except ValueError as e:
            console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    with open(path) as f: return json.load(f)

def _sign_outputs(paths: list, passphrase: Optional[str] = None):
    if not HAS_CRYPTO_UTILS: return
    for p in paths:
        if p and Path(p).is_file():
            sig = sign_file(Path(p), passphrase=passphrase)
            if sig: console.print(f"[dim]🔏 Signed: {Path(p).name}.sig[/dim]")


@app.command()
def init(
    client_name: str = typer.Option(..., "--client", "-c"),
    domain: str = typer.Option(None, "--domain", "-d"),
    ip: str = typer.Option(None, "--ip", "-i"),
    targets: str = typer.Option(None, "--targets", "-t"),
    targets_file: str = typer.Option(None, "--targets-file"),
    industry: str = typer.Option("General", "--industry"),
    authorized_by: str = typer.Option(..., "--roe", "--authorized-by", help="ROE reference or authorizer name (required)"),
    service: str = typer.Option("standard", "--service", help="micro | standard | smallbiz | full"),
    passphrase: str = typer.Option(None, "--passphrase", "-p"),
):
    """Create engagement with ROE reference (primary operator entrypoint)."""
    header(); auth()
    # Engagement ID: ENG-YYMMDD-XXXX
    import secrets
    eng_id = f"ENG-{datetime.datetime.now().strftime('%y%m%d')}-{secrets.token_hex(3).upper()}"
    try:
        tlist = parse_targets(targets, targets_file, ip, domain)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    schema = load_schema()
    meta = schema["audit_metadata"]
    meta["client_name"] = sanitize_client_name(client_name)
    meta["domain"] = domain or ""
    meta["public_ip"] = ip or ""
    meta["industry"] = industry
    meta["date"] = datetime.datetime.now().isoformat()
    meta["framework_version"] = BRAND["version"]
    meta["engagement_id"] = eng_id
    meta["service_tier"] = service
    schema["scope"]["in_scope_targets"] = tlist
    schema["scope"]["authorized_by"] = authorized_by
    schema["scope"]["authorization_date"] = datetime.datetime.now().strftime("%Y-%m-%d")
    schema["scope"]["roe_text"] = (
        f"ROE {eng_id}. Authorized security assessment only. "
        "No DoS, no social engineering without written approval, no data exfiltration. "
        f"Authorized by: {authorized_by}."
    )
    schema["scope"]["notes"] = f"{len(tlist)} target(s) | tier={service}"
    path = save_audit(schema, client_name, passphrase=passphrase)
    console.print(f"[green]✓[/green] Engagement [bold]{eng_id}[/bold] — {meta['client_name']} ({len(tlist)} targets)")
    console.print(f"[dim]ROE:[/dim] {authorized_by}")
    console.print(f"[dim]{path.name}[/dim] → fortifyone run -f {path.name}")
    console.print("[dim]Workflow: init → run → report → pack[/dim]")


@app.command()
def new(client_name: str = typer.Option(..., "--client", "-c"),
        domain: str = typer.Option(None, "--domain", "-d"),
        public_ip: str = typer.Option(None, "--ip", "-i"),
        targets: str = typer.Option(None, "--targets", "-t"),
        targets_file: str = typer.Option(None, "--targets-file"),
        industry: str = typer.Option("General", "--industry"),
        authorized_by: str = typer.Option("", "--authorized-by"),
        passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """Create multi-target engagement."""
    header(); auth()
    try:
        client_name = sanitize_client_name(client_name)
        tlist = parse_targets(targets, targets_file, public_ip, domain)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    primary_domain, primary_ip = domain or "", public_ip or ""
    for t in tlist:
        try:
            ipaddress.ip_network(t, strict=False)
            if not primary_ip and "/" not in t: primary_ip = t
        except ValueError:
            if not primary_domain: primary_domain = t
    if not primary_ip:
        for t in tlist:
            try:
                primary_ip = str(ipaddress.ip_address(t)); break
            except ValueError: pass
    if not primary_ip: primary_ip = "0.0.0.0"
    audit = load_schema()
    audit["audit_metadata"].update({"client_name": client_name, "domain": primary_domain or tlist[0],
        "public_ip": primary_ip, "industry": industry, "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(), "framework_version": BRAND["version"]})
    audit["scope"] = {"in_scope_targets": tlist, "out_of_scope": [],
        "roe_text": "Authorized security assessment only. No DoS, no social engineering without written approval, no data exfiltration.",
        "authorized_by": authorized_by or "Client representative",
        "authorization_date": datetime.datetime.now().strftime("%Y-%m-%d"), "notes": f"{len(tlist)} target(s)"}
    path = save_audit(audit, client_name, passphrase=passphrase)
    console.print(f"[green]✓[/green] Created [bold]{client_name}[/bold] ({len(tlist)} targets)")
    console.print(f"[dim]{path.name}[/dim] → fortifyone run -f {path.name}")

@app.command(name="list")
def list_cmd():
    header()
    files = find_audits()
    if not files: console.print("[yellow]No audits.[/yellow]"); return
    t = Table(title="Audits", box=box.ROUNDED)
    t.add_column("#", style="cyan"); t.add_column("Client"); t.add_column("Date", style="dim"); t.add_column("Enc", style="dim")
    for i, f in enumerate(files, 1):
        enc = ""
        try:
            if HAS_CRYPTO_UTILS and is_encrypted_bytes(f.read_bytes()[:16]):
                enc, c, dt = "🔒", f.stem, "encrypted"
            else:
                with open(f) as jf: d = json.load(jf)
                c = d.get("audit_metadata", {}).get("client_name", f.stem)
                dt = str(d.get("audit_metadata", {}).get("date", ""))[:10]
        except Exception: c, dt = f.stem, "?"
        t.add_row(str(i), c, dt, enc)
    console.print(t)

@app.command()
def run(module: str = typer.Option("all", "--module", "-m",
            help="all, external, vuln, web, tls, osint, internal, local, credentialed, policy, breach, saas, inventory, plugins"),
        audit_file: str = typer.Option(..., "--file", "-f"),
        passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """Run audit modules."""
    header(); auth()
    audit = load_audit(audit_file, passphrase=passphrase)
    client = audit["audit_metadata"]["client_name"]
    console.print(f"[bold]Target:[/bold] {client}\n")
    mods = {m.strip().lower() for m in module.split(",")}
    def want(*names):
        return "all" in mods or any(n in mods for n in names)
    results = {}
    def go(name, key, importer):
        task = progress.add_task(f"[cyan]{name}...", total=None)
        try:
            nonlocal audit
            audit = importer()(audit)
            results[key] = "done"
            progress.update(task, description=f"[green]✓ {name}[/green]")
        except Exception as e:
            progress.update(task, description=f"[yellow]⚠ {name}: {e}[/yellow]")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        if want("external"):
            go("ReconVision", "External", lambda: __import__("external_scan", fromlist=["run_scan"]).run_scan)
            try:
                from shodan_scan import run_scan as s; audit = s(audit)
            except Exception: pass
        if want("vuln", "external"):
            go("VulnProbe", "Vuln", lambda: __import__("vuln_probe", fromlist=["run_scan"]).run_scan)
        if want("web"):
            go("WebProbe", "Web", lambda: __import__("web_probe", fromlist=["run_scan"]).run_scan)
        if want("tls", "web"):
            go("TLSPosture", "TLS", lambda: __import__("tls_posture", fromlist=["run_scan"]).run_scan)
        if want("internal"):
            go("InternalScan", "Internal", lambda: __import__("internal_scan", fromlist=["run_scan"]).run_scan)
        if want("local"):
            go("LocalHardening", "Local", lambda: __import__("local_hardening", fromlist=["run_scan"]).run_scan)
        if want("credentialed"):
            go("Credentialed", "Credentialed", lambda: __import__("credentialed_scan", fromlist=["run_scan"]).run_scan)
        if want("policy"):
            go("PolicyEngine", "Policy", lambda: __import__("policy_engine", fromlist=["run_questionnaire"]).run_questionnaire)
        if want("breach"):
            go("BreachVault", "Breach", lambda: __import__("breach_vault", fromlist=["run_scan"]).run_scan)
        if want("saas"):
            go("SaaS-Sentinel", "SaaS", lambda: __import__("saas_sentinel", fromlist=["run_scan"]).run_scan)
        if want("osint"):
            go("OSINT", "OSINT", lambda: __import__("osint_recon", fromlist=["run_scan"]).run_scan)
        if want("inventory"):
            go("Inventory", "Inventory", lambda: __import__("inventory", fromlist=["run_scan"]).run_scan)
        if want("plugins"):
            go("Plugins", "Plugins", lambda: __import__("plugin_loader", fromlist=["run_plugins"]).run_plugins)
    if "External" in results:
        results["External"] = f"{audit.get('external_scan',{}).get('targets_count',1)} targets, {len(audit.get('external_scan',{}).get('open_ports',[]))} ports"
    if "Vuln" in results: results["Vuln"] = f"{len(audit.get('vuln_probe',{}).get('findings',[]))} findings"
    if "Web" in results: results["Web"] = f"CMS={audit.get('web_probe',{}).get('cms') or 'n/a'}"
    if "TLS" in results: results["TLS"] = f"{len(audit.get('tls_posture',{}).get('findings',[]))} findings, risk {audit.get('tls_posture',{}).get('risk_score',0)}"
    if "Internal" in results: results["Internal"] = f"{audit.get('internal_scan',{}).get('hosts_discovered',0)} hosts"
    if "Local" in results: results["Local"] = f"{len(audit.get('local_hardening',{}).get('findings',[]))} findings"
    if "Credentialed" in results: results["Credentialed"] = f"{audit.get('credentialed_scan',{}).get('hosts_count',0)} hosts, {len(audit.get('credentialed_scan',{}).get('findings',[]))} findings"
    if "Policy" in results: results["Policy"] = f"{audit.get('policy_compliance',{}).get('overall_compliance_percentage',0):.0f}%"
    if "Breach" in results: results["Breach"] = f"{audit.get('breach_exposure',{}).get('compromised_credentials',0)} hits"
    if "SaaS" in results: results["SaaS"] = audit.get("saas_posture",{}).get("score_grade","?")
    if "Plugins" in results: results["Plugins"] = f"{len(audit.get('plugins',{}).get('ran',{}))} ran"
    try:
        from inventory import build_inventory
        audit = build_inventory(audit)
        results["Inventory"] = f"{audit.get('inventory',{}).get('asset_count',0)} assets"
    except Exception as ie:
        console.print(f"[yellow]Inventory: {ie}[/yellow]")
    try:
        from scoring import apply_scoring
        audit = apply_scoring(audit)
        results["Score"] = f"{audit.get('scoring',{}).get('score',0)}/100 {audit.get('scoring',{}).get('grade','?')}"
    except Exception as se:
        console.print(f"[yellow]Scoring: {se}[/yellow]")
    updated = save_audit(audit, f"{client}_updated", passphrase=passphrase)
    console.print("\n[bold green]═══ Complete ═══[/bold green]")
    if results:
        t = Table(box=box.ROUNDED); t.add_column("Module", style="cyan"); t.add_column("Result")
        for m, r in results.items(): t.add_row(m, str(r))
        console.print(t)
    console.print(f"[dim]{updated.name}[/dim] → fortifyone report -f {updated.name}")

@app.command()
def report(audit_file: str = typer.Option(..., "--file", "-f"),
           passphrase: str = typer.Option(None, "--passphrase", "-p"),
           redacted: bool = typer.Option(False, "--redacted", help="Generate client-shareable redacted outputs")):
    """HTML + multi-page PDF + engagement letter + CSV + interactive dashboard (auto-signed)."""
    header(); auth()
    audit = load_audit(audit_file, passphrase=passphrase)
    if redacted:
        from dashboard import redact_audit
        audit = redact_audit(audit)
        console.print("[dim]Redacted mode — internal IPs scrubbed[/dim]")
    client = audit["audit_metadata"]["client_name"]
    out = OUTPUT / sanitize_client_name(client).replace(" ", "_")
    out.mkdir(exist_ok=True)
    try:
        from report_builder import (generate_executive_report, generate_remediation_plan,
                                    generate_pdf_report, generate_engagement_letter)
        html = generate_executive_report(audit, str(out))
        csvp = generate_remediation_plan(audit, str(out))
        pdf = generate_pdf_report(audit, str(out))
        letter = generate_engagement_letter(audit, str(out))
        console.print(f"[green]✓[/green] HTML: {Path(html).name}")
        console.print(f"[green]✓[/green] PDF:  {Path(pdf).name}" if pdf else "[yellow]⚠ PDF: pip install fpdf2[/yellow]")
        if letter: console.print(f"[green]✓[/green] Letter: {Path(letter).name}")
        console.print(f"[green]✓[/green] CSV:  {Path(csvp).name}")
        # Interactive dashboard
        try:
            from dashboard import generate_interactive_dashboard
            dash = generate_interactive_dashboard(audit, str(out), redacted=redacted)
            console.print(f"[green]✓[/green] Dashboard: {Path(dash).name}")
        except Exception as de:
            console.print(f"[yellow]⚠ Dashboard: {de}[/yellow]")
        summary = out / "audit_summary.json"
        if HAS_CRYPTO_UTILS: save_json_secure(summary, audit, passphrase=passphrase)
        else:
            with open(summary, "w") as f: json.dump(audit, f, indent=2, default=str)
        _sign_outputs([html, csvp, pdf, letter, str(summary)], passphrase=passphrase)
    except Exception as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    console.print(f"\n[bold]{out}[/bold]")

@app.command()
def pack(audit_file: str = typer.Option(..., "--file", "-f"),
         passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """Build client evidence pack ZIP."""
    header(); auth()
    audit = load_audit(audit_file, passphrase=passphrase)
    client = audit["audit_metadata"]["client_name"]
    out = OUTPUT / sanitize_client_name(client).replace(" ", "_")
    out.mkdir(exist_ok=True)
    try:
        from report_builder import (generate_executive_report, generate_remediation_plan,
                                    generate_pdf_report, generate_engagement_letter)
        html = generate_executive_report(audit, str(out))
        csvp = generate_remediation_plan(audit, str(out))
        pdf = generate_pdf_report(audit, str(out))
        letter = generate_engagement_letter(audit, str(out))
        summary = out / "audit_summary.json"
        if HAS_CRYPTO_UTILS: save_json_secure(summary, audit, passphrase=passphrase)
        else:
            with open(summary, "w") as f: json.dump(audit, f, indent=2, default=str)
        _sign_outputs([html, csvp, pdf, letter, str(summary)], passphrase=passphrase)
        from evidence_pack import build_evidence_pack
        zpath = build_evidence_pack(audit, str(out))
        console.print(f"[green]✓[/green] Evidence pack: {Path(zpath).name}")
        console.print(f"[bold]{out}[/bold]")
    except Exception as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)

@app.command()
def verify(file_path: str = typer.Option(..., "--file", "-f"),
           passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """Verify signature or encrypted audit."""
    header()
    path = Path(file_path)
    if not path.exists():
        for base in (OUTPUT, DATA, Path(".")):
            if (base/file_path).exists(): path = base/file_path; break
            if base == OUTPUT and base.exists():
                hits = list(base.rglob(Path(file_path).name))
                if hits: path = hits[0]; break
    if not path.exists():
        console.print("[red]✗ File not found[/red]"); raise typer.Exit(1)
    if HAS_CRYPTO_UTILS and is_encrypted_bytes(path.read_bytes()[:16]):
        console.print(f"[green]🔒[/green] {path.name} is encrypted")
        try:
            load_json_secure(path, passphrase=passphrase)
            console.print("[green]✓[/green] Decrypts successfully")
        except ValueError as e:
            console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
        return
    if not HAS_CRYPTO_UTILS:
        console.print("[yellow]crypto_utils missing[/yellow]"); raise typer.Exit(1)
    ok, msg = verify_file(path, passphrase=passphrase)
    console.print(f"[green]✓[/green] {msg}" if ok else f"[red]✗[/red] {msg}")
    if not ok: raise typer.Exit(1)

@app.command()
def compare(baseline: str = typer.Option(..., "--baseline", "-b"),
            current: str = typer.Option(..., "--current", "-c"),
            passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """Compare two audits."""
    header()
    a, b = load_audit(baseline, passphrase=passphrase), load_audit(current, passphrase=passphrase)
    from report_builder import _overall_risk, _build_findings
    ra, rb = _overall_risk(a), _overall_risk(b)
    fa, fb = _build_findings(a), _build_findings(b)
    ta, tb = {f["title"] for f in fa}, {f["title"] for f in fb}
    t = Table(title="Comparison", box=box.ROUNDED)
    t.add_column("Metric", style="cyan"); t.add_column("Baseline"); t.add_column("Current"); t.add_column("Delta")
    t.add_row("Risk", str(ra), str(rb), f"{rb-ra:+d}")
    t.add_row("Findings", str(len(fa)), str(len(fb)), f"{len(fb)-len(fa):+d}")
    console.print(t)
    if tb-ta:
        console.print("[bold]New:[/bold]")
        for x in list(tb-ta)[:10]: console.print(f"  • {x}")
    if ta-tb:
        console.print("[bold]Resolved:[/bold]")
        for x in list(ta-tb)[:10]: console.print(f"  • {x}")

@app.command()
def quick(domain: str = typer.Option(None, "--domain", "-d"),
          ip: str = typer.Option(None, "--ip", "-i"),
          targets: str = typer.Option(None, "--targets", "-t"),
          targets_file: str = typer.Option(None, "--targets-file"),
          industry: str = typer.Option("General", "--industry"),
          passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """One-shot external audit."""
    header(); auth()
    try: tlist = parse_targets(targets, targets_file, ip, domain)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]"); raise typer.Exit(1)
    client = "Quick_" + (domain or ip or tlist[0]).replace(".", "_")[:40]
    audit = load_schema()
    audit["audit_metadata"].update({"client_name": client, "domain": domain or "",
        "public_ip": ip or tlist[0], "industry": industry, "auditor": BRAND["name"],
        "date": datetime.datetime.now().isoformat(), "framework_version": BRAND["version"]})
    audit["scope"] = {"in_scope_targets": tlist, "out_of_scope": [],
        "roe_text": "Authorized security assessment only.",
        "authorized_by": "Quick scan", "authorization_date": datetime.datetime.now().strftime("%Y-%m-%d")}
    path = save_audit(audit, client, passphrase=passphrase)
    console.print(f"[green]✓[/green] Quick engagement created → running modules...")
    # Re-use run logic lightly
    try:
        from external_scan import run_scan as es; audit = es(audit)
        from vuln_probe import run_scan as vs; audit = vs(audit)
        from web_probe import run_scan as ws; audit = ws(audit)
        from saas_sentinel import run_scan as ss; audit = ss(audit)
    except Exception as e:
        console.print(f"[yellow]⚠ Partial: {e}[/yellow]")
    updated = save_audit(audit, f"{client}_updated", passphrase=passphrase)
    console.print(f"[dim]{updated.name}[/dim] → fortifyone report -f {updated.name}")

@app.command()
def info():
    header()
    console.print("[bold]Modules[/bold]: ReconVision · VulnProbe · WebProbe · InternalScan · LocalHardening")
    console.print("            Credentialed (SSH + WinRM readiness) · PolicyEngine · BreachVault · SaaS-Sentinel")
    console.print("            ReportGenius · EvidencePack · CryptoUtils")
    console.print("[dim]SSH: FORTIFYONE_SSH_HOST / _USER / _KEY  |  Crypto: FORTIFYONE_PASSPHRASE[/dim]")

@app.command()
def about():
    console.print(Panel.fit(
        f"[bold cyan]{BRAND['name']}[/bold cyan]\n{BRAND['tagline']}\n\nFortifyOne v{BRAND['version']} ({BRAND['build']})\n"
        "Primary audit engine · Engagement ROE · Discovery · OSINT · Credentialed depth · TLS · Dashboard · Evidence chain\n"
        "init → run → report → pack · Scoring + remediation roadmap · Redacted client outputs\n\n"
        f"{BRAND['url']}", title="About", border_style="cyan"))

@app.command()
def watch(audit_file: str = typer.Option(..., "--file", "-f"),
          passphrase: str = typer.Option(None, "--passphrase", "-p")):
    """Lightweight continuous external watch (external + TLS + web + delta)."""
    header(); auth()
    audit = load_audit(audit_file, passphrase=passphrase)
    client = audit["audit_metadata"]["client_name"]
    console.print(f"[bold]Watch target:[/bold] {client}\n")
    # Run safe external subset
    try:
        from external_scan import run_scan as ext
        audit = ext(audit)
    except Exception as e:
        console.print(f"[yellow]External: {e}[/yellow]")
    try:
        from tls_posture import run_scan as tls
        audit = tls(audit)
    except Exception as e:
        console.print(f"[yellow]TLS: {e}[/yellow]")
    try:
        from web_probe import run_scan as web
        audit = web(audit)
    except Exception as e:
        console.print(f"[yellow]Web: {e}[/yellow]")
    from watch_mode import run_watch
    audit = run_watch(audit, DATA)
    delta = audit.get("watch", {}).get("delta", {})
    console.print(f"[bold]Delta status:[/bold] {delta.get('status')} — {delta.get('message')}")
    if delta.get("new_ports"):
        console.print(f"[yellow]New ports:[/yellow] {', '.join(delta['new_ports'][:10])}")
    if delta.get("closed_ports"):
        console.print(f"[dim]Closed ports:[/dim] {', '.join(delta['closed_ports'][:10])}")
    updated = save_audit(audit, f"{client}_watch", passphrase=passphrase)
    console.print(f"[dim]{updated.name}[/dim]")


@app.command("plugins")
def plugins_cmd(list_only: bool = typer.Option(False, "--list", help="List available plugins only")):
    """List or show plugin system status."""
    header()
    from plugin_loader import list_plugins, discover_plugins
    plugs = list_plugins()
    if not plugs:
        console.print("[dim]No plugins found in modules/plugins/[/dim]")
        console.print("Drop a .py file with PLUGIN_NAME and run(audit_data) to extend FortifyOne.")
        return
    t = Table(title="FortifyOne Plugins", box=box.ROUNDED)
    t.add_column("Name", style="cyan")
    t.add_column("Version")
    t.add_column("Path", style="dim")
    for p in plugs:
        t.add_row(p["name"], p.get("version", ""), p.get("path", ""))
    console.print(t)



if __name__ == "__main__":
    app()
