#!/usr/bin/env python3
"""ReportGenius v5.3 - PDF unicode/layout fixed."""
import base64, types
from _rb_part0 import PART as P0
from _rb_part1 import PART as P1
from _rb_part2 import PART as P2
from _rb_part3 import PART as P3
_src = base64.b64decode(P0 + P1 + P2 + P3).decode("utf-8")
_mod = types.ModuleType("report_builder_impl")
exec(compile(_src, "report_builder.py", "exec"), _mod.__dict__)
for _name in (
    "_build_findings", "_overall_risk",
    "generate_executive_report", "generate_pdf_report",
    "generate_engagement_letter", "generate_remediation_plan",
    "PORT_REMEDIATION", "_port_remediation", "HAS_FPDF",
):
    if hasattr(_mod, _name):
        globals()[_name] = getattr(_mod, _name)
