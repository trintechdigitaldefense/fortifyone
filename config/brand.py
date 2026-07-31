#!/usr/bin/env python3
"""
TrinTech Digital Defense - Brand Assets
Consistent branding across all FortifyOne modules
"""

from rich.style import Style
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Brand Colors (Cyberpunk/Defense Theme)
TRINTECH_CYAN = "#00d4ff"
TRINTECH_DARK = "#0a0e27"  
TRINTECH_NAVY = "#1a1f3a"
TRINTECH_RED = "#ff4757"
TRINTECH_GREEN = "#2ed573"
TRINTECH_AMBER = "#ffa502"

BRAND_STYLES = {
    "primary": Style(color=TRINTECH_CYAN, bold=True),
    "secondary": Style(color="white"),
    "accent": Style(color=TRINTECH_GREEN),
    "danger": Style(color=TRINTECH_RED, bold=True),
    "warning": Style(color=TRINTECH_AMBER, bold=True),
    "muted": Style(color="#8892b0", dim=True),
    "highlight": Style(color=TRINTECH_CYAN, bold=True, reverse=True),
}

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║     ████████╗██████╗ ██╗███╗   ██╗████████╗███████╗ ██████╗██╗  ██╗   ║
║     ╚══██╔══╝██╔══██╗██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝██║  ██║   ║
║        ██║   ██████╔╝██║██╔██╗ ██║   ██║   █████╗  ██║     ███████║   ║
║        ██║   ██╔══██╗██║██║╚██╗██║   ██║   ██╔══╝  ██║     ██╔══██║   ║
║        ██║   ██║  ██║██║██║ ╚████║   ██║   ███████╗╚██████╗██║  ██║   ║
║        ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝   ║
║                                                                      ║
║                DIGITAL DEFENSE - FORTIFYONE v1.0                     ║
║              "Securing Your Digital World, One Audit at a Time"      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

BANNER_MINI = """
╔══════════════════════════════════════════════╗
║   🛡️  TRINTECH DIGITAL DEFENSE              ║
║   FortifyOne Audit Framework v1.0            ║
║   "Securing Your Digital World"              ║
╚══════════════════════════════════════════════╝
"""

def print_banner(console: Console = None, mini: bool = False):
    """Print the TrinTech branded banner."""
    if console is None:
        console = Console()
    
    text = BANNER_MINI if mini else BANNER
    
    panel = Panel.fit(
        Text(text, style=BRAND_STYLES["primary"]),
        border_style=TRINTECH_CYAN,
        padding=(1, 2)
    )
    console.print(panel)

def print_header(console: Console, title: str):
    """Print a branded section header."""
    console.print(Panel.fit(
        f"[bold cyan]{title}[/bold cyan]",
        border_style=TRINTECH_CYAN
    ))

def print_success(console: Console, message: str):
    """Print a success message in brand green."""
    console.print(f"[{TRINTECH_GREEN}]✓[/{TRINTECH_GREEN}] {message}")

def print_danger(console: Console, message: str):
    """Print a danger message in brand red."""
    console.print(f"[{TRINTECH_RED}]⚠[/{TRINTECH_RED}] {message}")

def print_info(console: Console, message: str):
    """Print an info message in muted style."""
    console.print(f"[#8892b0]  {message}[/#8892b0]")

def branded_metric(label: str, value: str, status: str = "info") -> str:
    """Format a metric with brand colors."""
    colors = {
        "critical": TRINTECH_RED,
        "warning": TRINTECH_AMBER,
        "good": TRINTECH_GREEN,
        "info": TRINTECH_CYAN,
    }
    color = colors.get(status, "white")
    return f"[{color}]{value}[/{color}]"

# Client Report Header
REPORT_HEADER = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortifyOne Audit Report | TrinTech Digital Defense</title>
    <style>
        :root {
            --trintech-cyan: #00d4ff;
            --trintech-dark: #0a0e27;
            --trintech-navy: #1a1f3a;
            --trintech-red: #ff4757;
            --trintech-green: #2ed573;
            --trintech-amber: #ffa502;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--trintech-dark);
            color: #e0e6ed;
            line-height: 1.6;
        }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
        .header {
            background: linear-gradient(135deg, var(--trintech-navy), #0d1126);
            border: 1px solid var(--trintech-cyan);
            border-radius: 12px;
            padding: 40px 30px;
            text-align: center;
            margin-bottom: 30px;
        }
        .header h1 { 
            color: var(--trintech-cyan); 
            font-size: 2.2em;
            margin-bottom: 5px;
            letter-spacing: 1px;
        }
        .header .subtitle {
            color: #8892b0;
            font-size: 1em;
            letter-spacing: 2px;
        }
        .header .tagline {
            color: var(--trintech-cyan);
            font-style: italic;
            margin-top: 10px;
            opacity: 0.8;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #8892b0;
            font-size: 0.85em;
            border-top: 1px solid #1a1f3a;
            margin-top: 40px;
        }
        .footer a { color: var(--trintech-cyan); text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ TRINTECH DIGITAL DEFENSE</h1>
            <div class="subtitle">FORTIFYONE SECURITY AUDIT REPORT</div>
            <div class="tagline">"Securing Your Digital World"</div>
        </div>
"""

REPORT_FOOTER = """
        <div class="footer">
            <p>Generated by <strong>FortifyOne v1.0</strong></p>
            <p>TrinTech Digital Defense | Professional Cybersecurity Services</p>
            <p>📧 contact@trintechdefense.com | 🌐 trintechdigitaldefense.github.io</p>
            <p style="margin-top: 10px; font-size: 0.75em;">
                This report contains confidential security findings. Handle accordingly.
            </p>
        </div>
    </div>
</body>
</html>
"""
