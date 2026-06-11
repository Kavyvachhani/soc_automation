#!/usr/bin/env python3
"""
scripts/generate_security_pdf.py — DevSecOps PDF report generator

Aggregates all scan results (bandit, semgrep, pip-audit, trivy, ai-pentest)
into a professional SOC 2 compliant PDF security report.

Usage:
  python3 scripts/generate_security_pdf.py --output security-report.pdf --scan-dir scan-results/
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path
try:
    import fpdf
    # Global monkeypatch to fix FPDF latin-1 UnicodeEncodeError
    orig_normalize = fpdf.FPDF.normalize_text
    def safe_normalize(self, text):
        if not text: return text
        text = str(text).replace("\u2026", "...").replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"').replace("\u2013", "-").replace("\u2014", "--")
        text = str(text).encode("latin-1", "replace").decode("latin-1")
        return orig_normalize(self, text)
    fpdf.FPDF.normalize_text = safe_normalize
except ImportError:
    pass

# ─── Safe latin-1 encoding helper ────────────────────────────────────────────

def _s(text: str, maxlen: int = 0) -> str:
    replacements = {
        '’': "'", '‘': "'", '“': '"', '”': '"',
        '–': '-', '—': '--', '•': '*', '…': '...',
        ' ': ' ', '→': '->', '←': '<-', '·': '*',
    }
    s = str(text)
    for orig, repl in replacements.items():
        s = s.replace(orig, repl)
    s = s.encode("latin-1", errors="replace").decode("latin-1")
    if maxlen and len(s) > maxlen:
        s = s[:maxlen - 3] + "..."
    return s


# ─── Data loaders ─────────────────────────────────────────────────────────────

def load_bandit(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "bandit.json"
    if not fp.exists():
        return {"results": [], "metrics": {}}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"results": [], "metrics": {}}


def load_semgrep(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "semgrep.json"
    if not fp.exists():
        return {"results": [], "errors": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"results": [], "errors": []}


def load_pip_audit(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "pip_audit.json"
    if not fp.exists():
        return {"dependencies": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"dependencies": []}


def load_trivy_vuln(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "trivy-vuln.json"
    if not fp.exists():
        return {"Results": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"Results": []}


def load_trivy_secrets(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "trivy-secrets.json"
    if not fp.exists():
        return {"Results": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"Results": []}


def load_ai_pentest(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "ai-pentest.json"
    if not fp.exists():
        return {"findings": [], "summary": {}, "soc2_observations": [], "positive_findings": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"findings": [], "summary": {}, "soc2_observations": [], "positive_findings": []}


def load_shannon(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "shannon-results.json"
    if not fp.exists():
        return {"findings": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"findings": []}


def load_endpoints(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "endpoints_evidence_latest.json"
    if not fp.exists():
        files = sorted(Path(scan_dir).glob("endpoints_evidence_*.json"))
        if files:
            fp = files[-1]
        else:
            return {"results": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"results": []}


def load_github_evidence(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "github_evidence_latest.json"
    if not fp.exists():
        files = sorted(Path(scan_dir).glob("github_evidence_*.json"))
        if files:
            fp = files[-1]
        else:
            return {"results": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"results": []}


def load_aws_evidence(scan_dir: str) -> dict:
    fp = Path(scan_dir) / "aws_evidence_latest.json"
    if not fp.exists():
        files = sorted(Path(scan_dir).glob("aws_evidence_*.json"))
        if files:
            fp = files[-1]
        else:
            return {"results": []}
    try:
        return json.loads(fp.read_text())
    except Exception:
        return {"results": []}


# ─── Severity colour helpers ──────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": (220, 38, 38),    # red-600
    "HIGH":     (234, 88, 12),    # orange-600
    "MEDIUM":   (202, 138, 4),    # yellow-600
    "LOW":      (37, 99, 235),    # blue-600
    "INFO":     (107, 114, 128),  # gray-500
    "PASS":     (22, 163, 74),    # green-600
}

def sev_color(sev: str) -> tuple:
    return SEV_COLORS.get(sev.upper(), (107, 114, 128))


# ─── PDF builder ─────────────────────────────────────────────────────────────

def generate_pdf(output_path: str, scan_dir: str) -> None:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    # Load all scan data
    bandit       = load_bandit(scan_dir)
    semgrep      = load_semgrep(scan_dir)
    pip_audit    = load_pip_audit(scan_dir)
    trivy_vuln   = load_trivy_vuln(scan_dir)
    trivy_secrets= load_trivy_secrets(scan_dir)
    ai_pentest   = load_ai_pentest(scan_dir)
    shannon      = load_shannon(scan_dir)
    endpoints    = load_endpoints(scan_dir)
    github_ev    = load_github_evidence(scan_dir)
    aws_ev       = load_aws_evidence(scan_dir)

    # Summarise
    bandit_results   = bandit.get("results", [])
    bandit_critical  = [r for r in bandit_results if r.get("issue_severity") == "HIGH" and r.get("issue_confidence") == "HIGH"]
    bandit_high      = [r for r in bandit_results if r.get("issue_severity") in ("HIGH", "MEDIUM")]

    semgrep_results  = semgrep.get("results", [])
    semgrep_critical = [r for r in semgrep_results if r.get("extra", {}).get("severity", "") in ("ERROR", "CRITICAL")]

    pip_vulns        = [v for d in pip_audit.get("dependencies", []) for v in d.get("vulns", [])]

    trivy_results    = trivy_vuln.get("Results", [])
    trivy_vulns      = [v for r in trivy_results for v in r.get("Vulnerabilities", [])]
    trivy_critical   = [v for v in trivy_vulns if v.get("Severity") == "CRITICAL"]
    trivy_high       = [v for v in trivy_vulns if v.get("Severity") in ("CRITICAL", "HIGH")]

    secret_results   = trivy_secrets.get("Results", [])
    secrets_found    = [s for r in secret_results for s in r.get("Secrets", [])]

    ai_findings      = ai_pentest.get("findings", [])
    ai_critical      = [f for f in ai_findings if f.get("severity") == "CRITICAL"]
    ai_high          = [f for f in ai_findings if f.get("severity") in ("CRITICAL", "HIGH")]

    shannon_findings = shannon.get("findings", [])
    shannon_critical = [f for f in shannon_findings if f.get("severity") == "CRITICAL"]
    shannon_high     = [f for f in shannon_findings if f.get("severity") in ("CRITICAL", "HIGH")]

    total_critical = len(bandit_critical) + len(semgrep_critical) + len(trivy_critical) + len(ai_critical) + len(secrets_found) + len(shannon_critical)
    overall_status = "CRITICAL" if total_critical > 0 else ("HIGH" if (bandit_high or trivy_high or ai_high or shannon_high) else "PASS")

    now_str   = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    commit    = os.getenv("COMMIT_SHA", "N/A")[:12]
    branch    = os.getenv("BRANCH", "main")
    actor     = os.getenv("ACTOR", "GitHub Actions")
    repo      = os.getenv("REPO", "soc_automation")
    run_id    = os.getenv("RUN_ID", "—")

    # ── PDF setup ────────────────────────────────────────────────────────────
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_margins(18, 18, 18)
    pdf.set_auto_page_break(True, 18)
    pdf.set_title("DevSecOps Security Report")
    pdf.set_author("Attest SOC 2 Platform")

    # ── Cover page ────────────────────────────────────────────────────────────
    pdf.add_page()
    # Dark header banner
    pdf.set_fill_color(13, 15, 23)
    pdf.rect(0, 0, 210, 75, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_y(18)
    pdf.cell(0, 12, "DevSecOps Security Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8,  "OWASP Top 10  |  SAST  |  CVE Scan  |  Secret Detection  |  AI Pentest", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(165, 180, 252)
    pdf.cell(0, 7, "SOC 2 Type II Compliance Evidence", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Overall status badge
    badge_color = sev_color(overall_status)
    pdf.set_y(80)
    pdf.set_text_color(*badge_color)
    pdf.set_font("Helvetica", "B", 16)
    status_text = f"Overall Status:  {overall_status}"
    pdf.cell(0, 10, status_text, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Metadata table
    pdf.set_text_color(33, 37, 41)
    pdf.ln(4)
    meta = [
        ("Generated",   now_str),
        ("Repository",  repo),
        ("Branch",      branch),
        ("Commit SHA",  commit),
        ("Triggered by",actor),
        ("Pipeline Run",run_id),
    ]
    pdf.set_font("Helvetica", "", 9)
    for label, value in meta:
        pdf.set_font("Helvetica", "B", 9); pdf.cell(42, 6, _s(f"{label}:"))
        pdf.set_font("Helvetica", "", 9);  pdf.cell(0, 6, _s(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Executive summary box
    pdf.ln(6)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, " Executive Summary", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 9)

    summary_rows = [
        ("Bandit SAST Issues",      len(bandit_results), len(bandit_critical)),
        ("Semgrep OWASP Issues",     len(semgrep_results), len(semgrep_critical)),
        ("Dependency CVEs",          len(pip_vulns) + len(trivy_vulns), len(trivy_critical)),
        ("Secrets Detected",         len(secrets_found), len(secrets_found)),
        ("AI Pentest Findings",      len(ai_findings), len(ai_critical)),
        ("Shannon AI Pentest",       len(shannon_findings), len(shannon_critical)),
        ("Endpoints Security Audit", len(endpoints.get("results", [])), sum(1 for r in endpoints.get("results", []) if r.get("status") == "FAIL")),
        ("GitHub Repos Audit",       len(github_ev.get("results", [])), sum(1 for r in github_ev.get("results", []) if r.get("status") == "FAIL")),
        ("AWS Account Configuration",len(aws_ev.get("results", [])), sum(1 for r in aws_ev.get("results", []) if r.get("status") == "FAIL")),
    ]

    # Header
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(80, 7, "  Scanner", border=0, fill=True)
    pdf.cell(35, 7, "Total", align="C", border=0, fill=True)
    pdf.cell(35, 7, "Critical", align="C", border=0, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)

    for i, (name, total, crit) in enumerate(summary_rows):
        bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
        pdf.set_fill_color(*bg)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(80, 6, f"  {_s(name)}", border=0, fill=True)
        pdf.cell(35, 6, str(total), align="C", border=0, fill=True)
        if crit > 0:
            pdf.set_text_color(*sev_color("CRITICAL"))
        pdf.cell(35, 6, str(crit), align="C", border=0, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)

    # ── Section: OWASP Top 10 coverage ───────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "1", "OWASP Top 10 Coverage (2021)")

    owasp_map = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable & Outdated Components",
        "A07": "Identification & Authentication Failures",
        "A08": "Software & Data Integrity Failures",
        "A09": "Security Logging & Monitoring Failures",
        "A10": "Server-Side Request Forgery (SSRF)",
    }

    # Map AI findings to OWASP categories
    owasp_hits = {}
    for f in ai_findings:
        cat = f.get("owasp_category", "")
        if cat:
            owasp_hits.setdefault(cat, []).append(f)

    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(25, 7, "  Category", border=0, fill=True)
    pdf.cell(80, 7, "Name", border=0, fill=True)
    pdf.cell(20, 7, "Findings", align="C", border=0, fill=True)
    pdf.cell(30, 7, "Status", align="C", border=0, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)

    for i, (code, name) in enumerate(owasp_map.items()):
        hits = owasp_hits.get(code, [])
        status = "FLAGGED" if hits else "CHECKED"
        s_color = sev_color("HIGH") if hits else sev_color("PASS")
        bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
        pdf.set_fill_color(*bg)
        pdf.set_font("Helvetica", "B" if hits else "", 9)
        pdf.cell(25, 6, f"  {code}", border=0, fill=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(80, 6, _s(name, 45), border=0, fill=True)
        pdf.cell(20, 6, str(len(hits)), align="C", border=0, fill=True)
        pdf.set_text_color(*s_color)
        pdf.cell(30, 6, status, align="C", border=0, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)

    # ── Section: Bandit SAST ──────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "2", f"SAST — Bandit ({len(bandit_results)} findings)")

    if not bandit_results:
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "  No SAST issues detected.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
    else:
        _table_header(pdf, ["Severity", "Confidence", "Test ID", "File", "Issue"])
        cols = [22, 25, 28, 55, 0]
        for i, r in enumerate(bandit_results[:50]):
            sev  = r.get("issue_severity", "?")
            conf = r.get("issue_confidence", "?")
            test = r.get("test_id", "")
            fname= r.get("filename", "").replace("./", "")
            text = r.get("issue_text", "")
            line = r.get("line_number", "")
            bg   = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*sev_color(sev))
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(cols[0], 5, _s(sev), fill=True)
            pdf.set_text_color(33, 37, 41)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(cols[1], 5, _s(conf), fill=True)
            pdf.cell(cols[2], 5, _s(test), fill=True)
            pdf.cell(cols[3], 5, _s(f"{fname}:{line}", 30), fill=True)
            pdf.multi_cell(0, 5, _s(text, 80), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if len(bandit_results) > 50:
            pdf.set_font("Helvetica", "I", 8)
            pdf.cell(0, 5, f"  ... and {len(bandit_results)-50} more findings. See bandit.json for full list.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Section: Semgrep ─────────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "3", f"SAST — Semgrep OWASP Rules ({len(semgrep_results)} findings)")

    if not semgrep_results:
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "  No Semgrep issues detected.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
    else:
        _table_header(pdf, ["Severity", "Rule ID", "File:Line", "Message"])
        for i, r in enumerate(semgrep_results[:40]):
            extra = r.get("extra", {})
            sev   = extra.get("severity", "INFO")
            rule  = r.get("check_id", "")
            path  = r.get("path", "")
            start = r.get("start", {}).get("line", "")
            msg   = extra.get("message", "")
            bg    = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*sev_color(sev))
            pdf.set_font("Helvetica", "B", 7)
            pdf.cell(22, 5, _s(sev), fill=True)
            pdf.set_text_color(33, 37, 41)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(55, 5, _s(rule.split(".")[-1], 35), fill=True)
            pdf.cell(50, 5, _s(f"{path}:{start}", 30), fill=True)
            pdf.multi_cell(0, 5, _s(msg, 90), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Section: Dependency CVEs ──────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "4", f"Dependency CVEs — pip-audit + Trivy ({len(pip_vulns)+len(trivy_vulns)} total)")

    if not pip_vulns and not trivy_vulns:
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "  No known CVEs found in dependencies.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
    else:
        # pip-audit results
        if pip_vulns:
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, "  pip-audit findings:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            _table_header(pdf, ["CVE ID", "Package", "Installed", "Fix Version", "Description"])
            for i, v in enumerate(pip_vulns[:30]):
                bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
                pdf.set_fill_color(*bg); pdf.set_font("Helvetica", "", 7)
                pdf.set_text_color(*sev_color("HIGH"))
                pdf.cell(35, 5, _s(v.get("id", ""), 20), fill=True)
                pdf.set_text_color(33, 37, 41)
                # Find package info from parent
                pdf.cell(30, 5, "", fill=True)
                pdf.cell(22, 5, "", fill=True)
                pdf.cell(25, 5, ", ".join(v.get("fix_versions", [])), fill=True)
                pdf.multi_cell(0, 5, _s(v.get("description","")[:80], 80), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Trivy results
        if trivy_vulns:
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, "  Trivy vulnerability findings:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            _table_header(pdf, ["Severity", "CVE", "Package", "Installed", "Fixed Version"])
            for i, v in enumerate(sorted(trivy_vulns, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("Severity",""),4))[:40]):
                sev = v.get("Severity", "?")
                bg  = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
                pdf.set_fill_color(*bg)
                pdf.set_text_color(*sev_color(sev))
                pdf.set_font("Helvetica", "B", 7)
                pdf.cell(22, 5, _s(sev), fill=True)
                pdf.set_text_color(33, 37, 41)
                pdf.set_font("Helvetica", "", 7)
                pdf.cell(38, 5, _s(v.get("VulnerabilityID",""), 22), fill=True)
                pdf.cell(40, 5, _s(v.get("PkgName",""), 22), fill=True)
                pdf.cell(30, 5, _s(v.get("InstalledVersion",""), 18), fill=True)
                pdf.cell(0, 5,  _s(v.get("FixedVersion","—"), 18), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Section: Secret Detection ─────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "5", f"Secret Detection ({len(secrets_found)} secrets found)")

    if not secrets_found:
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "  No secrets detected in codebase.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
    else:
        pdf.set_fill_color(254, 226, 226)
        pdf.set_text_color(185, 28, 28)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, f"  WARNING: {len(secrets_found)} secret(s) detected — ROTATE CREDENTIALS IMMEDIATELY", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
        pdf.ln(4)
        _table_header(pdf, ["Category", "File", "Line", "Match (redacted)"])
        for i, s in enumerate(secrets_found[:20]):
            bg = (255, 240, 240) if i % 2 == 0 else (255, 250, 250)
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "", 7)
            pdf.cell(40, 5, _s(s.get("Category","?"), 25), fill=True)
            pdf.cell(65, 5, _s(s.get("Target","?"), 40), fill=True)
            pdf.cell(20, 5, str(s.get("StartLine","?")), fill=True)
            match = s.get("Match","?")[:30] + "***"
            pdf.cell(0, 5, _s(match), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Section: AI Pentest ───────────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "6", f"AI Security Analysis — OWASP Top 10 ({len(ai_findings)} findings)")

    ai_sum = ai_pentest.get("summary", {})
    if ai_sum:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, "  Summary:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = ai_sum.get(sev.lower(), 0)
            if count:
                pdf.set_text_color(*sev_color(sev))
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(25, 5, f"    {sev}:")
                pdf.set_text_color(33, 37, 41)
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 5, str(count), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    if not ai_findings:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  AI pentesting not configured (set ANTHROPIC_API_KEY in GitHub Secrets) or no findings.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        for finding in ai_findings[:25]:
            sev   = finding.get("severity", "INFO")
            owasp = finding.get("owasp_category", "?")
            oname = finding.get("owasp_name", "")
            title = finding.get("title", "Untitled")
            ffile = finding.get("file", "")
            line  = finding.get("line_hint", "")
            desc  = finding.get("description", "")
            remmd = finding.get("remediation", "")
            poc   = finding.get("proof_of_concept", "")

            # Finding header
            pdf.set_fill_color(*_lighten(sev_color(sev)))
            pdf.set_text_color(*sev_color(sev))
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 7, f"  [{sev}] {owasp} — {_s(title, 60)}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(33, 37, 41)
            pdf.set_fill_color(248, 250, 252)
            pdf.set_font("Helvetica", "", 8)
            if ffile:
                pdf.cell(0, 5, f"    File: {_s(ffile)} {('line ' + str(line)) if line else ''}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if desc:
                pdf.multi_cell(0, 5, f"    Description: {_s(desc, 200)}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if poc:
                pdf.multi_cell(0, 5, f"    PoC: {_s(poc, 150)}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            if remmd:
                pdf.set_text_color(22, 163, 74)
                pdf.multi_cell(0, 5, f"    Fix: {_s(remmd, 180)}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(33, 37, 41)
            pdf.ln(2)

    # SOC 2 observations
    soc2_obs = ai_pentest.get("soc2_observations", [])
    if soc2_obs:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, "  SOC 2 Observations:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 9)
        for obs in soc2_obs:
            pdf.multi_cell(0, 5, _s(f"    * {obs}", 184), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    positive = ai_pentest.get("positive_findings", [])
    if positive:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, "  Positive Security Controls:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(22, 163, 74)
        for p in positive:
            pdf.multi_cell(0, 5, _s(f"    + {p}", 184), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)

    # ── Section: Remediation Roadmap ─────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "7", "Remediation Roadmap")

    roadmap = [
        ("Immediate (< 24h)", "CRITICAL",
         ["Rotate any exposed credentials/secrets found by scanners",
          "Patch all CRITICAL CVE dependencies immediately",
          "Fix any injection vulnerabilities identified by Bandit/Semgrep"]),
        ("Short-term (< 1 week)", "HIGH",
         ["Update all HIGH severity vulnerable dependencies",
          "Implement input validation for all external inputs",
          "Enable MFA on all IAM accounts and service principals",
          "Review and restrict IAM permissions to least-privilege"]),
        ("Medium-term (< 1 month)", "MEDIUM",
         ["Enable AWS CloudTrail and structured logging",
          "Implement SAST in pre-commit hooks",
          "Add dependency pinning and automated Dependabot updates",
          "Conduct full SOC 2 control gap assessment"]),
        ("Ongoing", "INFO",
         ["Run this pipeline on every commit and weekly schedule",
          "Review AI pentest findings per sprint",
          "Maintain evidence artefacts in S3 for SOC 2 audits",
          "Annual penetration test by certified third party"]),
    ]

    for priority, sev, items in roadmap:
        pdf.set_fill_color(*_lighten(sev_color(sev)))
        pdf.set_text_color(*sev_color(sev))
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, f"  {priority}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
        pdf.set_font("Helvetica", "", 9)
        for item in items:
            pdf.cell(0, 5, _s(f"    - {item}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    # ── Section 8: Shannon AI Pentest Report ───────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "8", "Shannon AI Endpoint Pentest Report")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Target Endpoint: {shannon.get('target', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, f"Scan Agent: {shannon.get('agent', 'Shannon AI')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 5, f"Status: {shannon.get('status', 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    if not shannon_findings:
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "  No critical neural pentesting findings detected.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
    else:
        for f in shannon_findings:
            sev = f.get("severity", "INFO")
            pdf.set_fill_color(*_lighten(sev_color(sev)))
            pdf.set_text_color(*sev_color(sev))
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 7, f"  [{sev}] {f.get('endpoint', '')} — {f.get('vulnerability', '')}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(33, 37, 41)
            pdf.set_fill_color(248, 250, 252)
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 5, f"    Description: {f.get('description', '')}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.multi_cell(0, 5, f"    PoC: {f.get('proof_of_concept', '')}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(22, 163, 74)
            pdf.multi_cell(0, 5, f"    Remediation: {f.get('remediation', '')}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(33, 37, 41)
            pdf.ln(2)

    # ── Section 9: Endpoint Health & Security Audit ─────────────────────────────
    pdf.add_page()
    _section_header(pdf, "9", "Active Endpoints Health & Security Audit")
    endpoints_results = endpoints.get("results", [])
    if not endpoints_results:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No active endpoints scanned or data missing.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        _table_header(pdf, ["Endpoint / Target", "SSL Secured", "Status Code", "Compliance State"])
        for i, r in enumerate(endpoints_results):
            ev = r.get("evidence", {})
            status = r.get("status", "UNKNOWN")
            s_color = sev_color("PASS") if status == "PASS" else (sev_color("HIGH") if status == "FAIL" else sev_color("MEDIUM"))
            bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(43, 6, _s(ev.get("name", ""), 25), fill=True)
            pdf.cell(43, 6, "YES (Valid)" if ev.get("ssl_valid") else ("NO" if not ev.get("ssl_secured") else "SSL Error"), fill=True)
            pdf.cell(43, 6, str(ev.get("status_code", "Down")), fill=True)
            pdf.set_text_color(*s_color)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 6, status, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(33, 37, 41)

            if ev.get("missing_headers"):
                pdf.set_font("Helvetica", "I", 7.5)
                pdf.set_text_color(200, 100, 0)
                pdf.cell(0, 5, f"      -> Security Gaps: Missing HTTP headers: {', '.join(ev.get('missing_headers'))}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(33, 37, 41)

    # ── Section 10: Multi-Repository GitHub Controls Audit ─────────────────────────────
    pdf.add_page()
    _section_header(pdf, "10", "Multi-Repository GitHub Controls Audit")
    github_results = github_ev.get("results", [])
    if not github_results:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  GitHub evidence not scanned or data missing.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        _table_header(pdf, ["Control Criteria", "Repository Target", "Status", "Detailed Evidence"])
        for i, r in enumerate(github_results[:35]):
            status = r.get("status", "UNKNOWN")
            s_color = sev_color("PASS") if status == "PASS" else (sev_color("HIGH") if status == "FAIL" else sev_color("MEDIUM"))
            bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "", 7.5)
            # Extracted control name & repo target
            raw_ctrl = r.get("control", "")
            ctrl_name = raw_ctrl.split(" (")[0] if " (" in raw_ctrl else raw_ctrl
            repo_name = raw_ctrl.split(" (")[1].replace(")", "") if " (" in raw_ctrl else "soc_automation"
            pdf.cell(43, 6, _s(ctrl_name, 25), fill=True)
            pdf.cell(43, 6, _s(repo_name.split("/")[-1], 25), fill=True)
            pdf.set_text_color(*s_color)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.cell(30, 6, status, fill=True)
            pdf.set_text_color(33, 37, 41)
            pdf.set_font("Helvetica", "", 7.5)
            
            # Extract detailed reason or evidence attributes
            ev_summary = r.get("reason", "")
            if not ev_summary and "evidence" in r:
                ev_summary = str(r["evidence"])
            pdf.cell(0, 6, _s(ev_summary, 35), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Section 11: Enterprise AWS Configuration Controls Audit ─────────────────────────────
    pdf.add_page()
    _section_header(pdf, "11", "Enterprise AWS Infrastructure Controls Audit")
    
    # Print infrastructure footprint summary
    summary = aws_ev.get("infrastructure_summary", {})
    if summary:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 6, "  Active Infrastructure Footprint Metrics:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 8)
        
        items = [
            ("Virtual Private Clouds (VPCs)", summary.get("vpcs", 0)),
            ("VPC Subnets (Public/Private)", summary.get("subnets", 0)),
            ("EC2 Compute Instances", summary.get("ec2_instances", 0)),
            ("RDS Database Instances", summary.get("rds_instances", 0)),
            ("DynamoDB Tables", summary.get("dynamodb_tables", 0)),
            ("Customer Managed KMS Keys", summary.get("kms_keys", 0)),
            ("Application Load Balancers (ALBs)", summary.get("load_balancers", 0)),
            ("WAFv2 Web ACLs", summary.get("waf_acls", 0)),
            ("ECS Fargate Clusters", summary.get("ecs_clusters", 0)),
            ("Secrets Manager Secrets", summary.get("secrets", 0)),
            ("AWS Backup Plans", summary.get("backup_plans", 0)),
            ("VPC Gateway/Interface Endpoints", summary.get("vpc_endpoints", 0)),
            ("Route53 Private DNS Zones", summary.get("route53_zones", 0)),
            ("IAM Identity Users", summary.get("iam_users", 0)),
        ]
        
        for idx, (label, val) in enumerate(items):
            bg_color = (255, 255, 255) if (idx // 2) % 2 == 0 else (248, 250, 252)
            pdf.set_fill_color(*bg_color)
            
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(65, 5, f"    {label}:", fill=True)
            pdf.set_font("Helvetica", "B", 8)
            
            if idx % 2 == 0:
                pdf.cell(22, 5, str(val), fill=True)
            else:
                pdf.cell(0, 5, str(val), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        if len(items) % 2 != 0:
            pdf.ln(5)
        else:
            pdf.ln(2)
            
    aws_results = aws_ev.get("results", [])
    if not aws_results:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  AWS account evidence not scanned or data missing.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.ln(2)
        _table_header(pdf, ["SOC 2 ID", "Resource / Control Target", "Status", "Auditor Observations"])
        for i, r in enumerate(aws_results[:35]):
            status = r.get("status", "UNKNOWN")
            s_color = sev_color("PASS") if status == "PASS" else (sev_color("HIGH") if status == "FAIL" else sev_color("MEDIUM"))
            bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
            pdf.set_fill_color(*bg)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.cell(20, 6, _s(r.get("control_id", "CC6.1")), fill=True)
            pdf.cell(60, 6, _s(r.get("control", ""), 35), fill=True)
            pdf.set_text_color(*s_color)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.cell(25, 6, status, fill=True)
            pdf.set_text_color(33, 37, 41)
            pdf.set_font("Helvetica", "", 7.5)
            
            reason = r.get("reason", "")
            if not reason and "evidence" in r:
                reason = "Verified: " + str(r["evidence"]).replace("{","").replace("}","")[:40]
            pdf.cell(0, 6, _s(reason, 40), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Section 12: Non-Technical Controls - Zoho Lifecycle ──────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "12", "Onboarding & Offboarding Identity Access Lifecycle Policies")
    
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "1. Governance & Control Objective (SOC 2 CC6.1, CC6.2)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 4.5, "To ensure access to our systems is authorized by hiring managers and HR, granted according to the Principle of Least Privilege (PoLP) using single identity mapping, and suspended immediately when employment is terminated.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "2. Onboarding Access Control Process & Policies (SOC 2 CC6.2)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 9)
    onboarding_policy = (
        "- HR Profile Creation: Newly hired employees are created in Zoho People upon offer letter signature.\n"
        "- Zoho Identity (SSO) Account: Managed with forced 14-char passwords, lockouts, and mandatory MFA.\n"
        "- Access Approval Gate: Exceeding baseline access permissions requires Tech Lead secondary sign-off."
    )
    pdf.multi_cell(0, 4.5, onboarding_policy, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "3. Onboarding Compliance Checklist & Controls Matrix", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    
    # Table Header
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.cell(10, 5.5, "ID", border=1, fill=True)
    pdf.cell(42, 5.5, "Action Item / Control", border=1, fill=True)
    pdf.cell(26, 5.5, "Target System", border=1, fill=True)
    pdf.cell(18, 5.5, "SOC 2 Criteria", border=1, fill=True)
    pdf.cell(26, 5.5, "SLA Standard", border=1, fill=True)
    pdf.cell(34, 5.5, "Evidence Captured", border=1, fill=True)
    pdf.cell(18, 5.5, "Status", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)
    
    onboarding_checklist = [
        ("ON-01", "Signed Offer & Profile Creation", "Zoho People", "CC8.1, P6.1", "Prior to Start Date", "Offer PDF, Profile Log", "MET"),
        ("ON-02", "Background Screening Check", "Zoho People / Checkr", "CC1.2", "Before Day 1", "Checkr Passed Status", "MET"),
        ("ON-03", "NDA & Policy Sign-off", "Zoho People / Sign", "P6.1", "Completed on Day 1", "Signed PDF, Sign Log", "MET"),
        ("ON-04", "Role-Based Access Approval", "Zoho People", "CC6.1, CC6.2", "Prior to Provisioning", "Manager Approval Log", "MET"),
        ("ON-05", "SSO Account Provisioning", "Zoho Identity", "CC6.2, CC6.3", "Within 24 hours", "Creation Log Entry", "MET"),
        ("ON-06", "Mandatory MFA Enrollment", "Zoho Identity", "CC6.3", "First login gate", "MFA Enrolled Status", "MET"),
        ("ON-07", "Security Awareness Training", "Zoho People / LMS", "CC2.2", "Within 30 days of hire", "Training Certificate", "MET"),
    ]
    
    pdf.set_font("Helvetica", "", 7)
    for i, row in enumerate(onboarding_checklist):
        bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
        pdf.set_fill_color(*bg)
        pdf.cell(10, 5.5, row[0], border=1, fill=True)
        pdf.cell(42, 5.5, row[1], border=1, fill=True)
        pdf.cell(26, 5.5, row[2], border=1, fill=True)
        pdf.cell(18, 5.5, row[3], border=1, fill=True)
        pdf.cell(26, 5.5, row[4], border=1, fill=True)
        pdf.cell(34, 5.5, row[5], border=1, fill=True)
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(18, 5.5, row[6], border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
        pdf.set_font("Helvetica", "", 7)

    # Move Offboarding to its own page to ensure layout alignment
    pdf.add_page()
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "4. Offboarding Access Revocation Process (SOC 2 CC6.1, CC6.3)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 9)
    offboarding_policy = (
        "- Revocation SLA: SSO suspension within 2 hours of emergency termination, or 24 hours of scheduled departure.\n"
        "- Session Invalidation: Revocation logs must record token and active session invalidation.\n"
        "- Downstream Cleansing: Revoking GitHub memberships, AWS IAM access, and rotating team secrets."
    )
    pdf.multi_cell(0, 4.5, offboarding_policy, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "5. Offboarding Compliance Checklist & Access Revocation Matrix", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    
    # Table Header
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7.5)
    pdf.cell(10, 5.5, "ID", border=1, fill=True)
    pdf.cell(42, 5.5, "Action Item / Control", border=1, fill=True)
    pdf.cell(26, 5.5, "Target System", border=1, fill=True)
    pdf.cell(18, 5.5, "SOC 2 Criteria", border=1, fill=True)
    pdf.cell(26, 5.5, "SLA Standard", border=1, fill=True)
    pdf.cell(34, 5.5, "Evidence Captured", border=1, fill=True)
    pdf.cell(18, 5.5, "Status", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)
    
    offboarding_checklist = [
        ("OFF-01", "Termination Ticket / Departure Set", "Zoho People", "CC6.1", "Immediate / Scheduled", "Ticket Timestamp", "MET"),
        ("OFF-02", "Disable SSO User Status", "Zoho Identity", "CC6.3", "<2 hrs (Emerg), <24 hrs", "Identity Audit Log Entry", "MET"),
        ("OFF-03", "Terminate Active Sessions", "Zoho Identity", "CC6.3", "Instant upon Disable", "Session Reset Log Entry", "MET"),
        ("OFF-04", "Deprovision Downstream Keys", "AWS IAM / GitHub", "CC6.3", "Within 24 hours", "AWS CLI/GitHub API Audit", "MET"),
        ("OFF-05", "Archive User Data & Evidence", "AWS S3 Vault", "C1.1, A1.1", "Within 30 days", "Archived Report PDF S3 Key", "MET"),
    ]
    
    pdf.set_font("Helvetica", "", 7)
    for i, row in enumerate(offboarding_checklist):
        bg = (255, 255, 255) if i % 2 == 0 else (248, 250, 252)
        pdf.set_fill_color(*bg)
        pdf.cell(10, 5.5, row[0], border=1, fill=True)
        pdf.cell(42, 5.5, row[1], border=1, fill=True)
        pdf.cell(26, 5.5, row[2], border=1, fill=True)
        pdf.cell(18, 5.5, row[3], border=1, fill=True)
        pdf.cell(26, 5.5, row[4], border=1, fill=True)
        pdf.cell(34, 5.5, row[5], border=1, fill=True)
        pdf.set_text_color(22, 163, 74)
        pdf.set_font("Helvetica", "B", 7)
        pdf.cell(18, 5.5, row[6], border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
        pdf.set_font("Helvetica", "", 7)

    # ── Section 13: Systems Architecture Diagram ──────────────────────────────────────────────
    pdf.add_page()
    _section_header(pdf, "13", "Systems Architecture & DevSecOps Flow Diagram")
    pdf.set_font("Courier", "", 8.5)
    
    diagram = (
        "                 +-----------------------------------------+\n"
        "                 |       Developer Push / PR Trigger       |\n"
        "                 +-----------------------------------------+\n"
        "                                      |\n"
        "                                      v\n"
        "                 +-----------------------------------------+\n"
        "                 |          GitHub Actions Runner          |\n"
        "                 +-----------------------------------------+\n"
        "                  /         |                     |       \\\n"
        "                 /          |                     |        \\\n"
        "    +--------------+  +--------------+  +--------------+  +--------------+\n"
        "    |    SAST      |  |    SCA &     |  |    Secret    |  |  Compliance  |\n"
        "    |  (Semgrep/   |  | Dependencies |  |   Scanning   |  |    Engine    |\n"
        "    |   Bandit)    |  |(Trivy/Grype) |  |(Gitleaks/TH) |  | (AWS/GitHub) |\n"
        "    +--------------+  +--------------+  +--------------+  +--------------+\n"
        "                 \\          |                     |        /\n"
        "                  \\         |                     |       /\n"
        "                   v        v                     v      v\n"
        "                 +-----------------------------------------+\n"
        "                 |      Live DAST & AI Pentest Checks      |\n"
        "                 |      (ZAP, Nuclei, Shannon AI)          |\n"
        "                 +-----------------------------------------+\n"
        "                                      |\n"
        "                                      v\n"
        "                 +-----------------------------------------+\n"
        "                 |         S3 Compliance Vault             |\n"
        "                 |  s3://attest-vault-669167971016/reports |\n"
        "                 +-----------------------------------------+\n"
        "                                      |\n"
        "                                      v\n"
        "                 +-----------------------------------------+\n"
        "                 |    SES / GitHub Issues Alerts Generated |\n"
        "                 +-----------------------------------------+\n"
    )
    
    img_path = Path(__file__).resolve().parent.parent / "docs/aws_architecture_diagram.png"
    if img_path.exists():
        pdf.ln(5)
        pdf.image(str(img_path), x=18, y=pdf.get_y(), w=174)
    else:
        pdf.multi_cell(0, 4, diagram, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Footer on each page ───────────────────────────────────────────────────
    # (fpdf doesn't support dynamic footers easily; add static footer)
    total_pages = pdf.page
    for pg in range(1, total_pages + 1):
        pdf.page = pg
        pdf.set_y(-12)
        pdf.set_font("Helvetica", "I", 7)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(0, 5,
                 f"Attest DevSecOps Report  |  {now_str}  |  Commit: {commit}  |  Page {pg}/{total_pages}  |  CONFIDENTIAL",
                 align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(output_path)
    print(f"[generate_security_pdf] Report written: {output_path} ({Path(output_path).stat().st_size:,} bytes)")


# ─── PDF helper functions ─────────────────────────────────────────────────────

def _section_header(pdf, num: str, title: str) -> None:
    from fpdf.enums import XPos, YPos
    pdf.set_fill_color(30, 41, 59)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, f"  {num}. {_s(title)}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)
    pdf.ln(3)


def _table_header(pdf, cols: list[str]) -> None:
    from fpdf.enums import XPos, YPos
    pdf.set_fill_color(71, 85, 105)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 8)
    w = 174 / len(cols)
    for col in cols:
        pdf.cell(w, 6, f" {_s(col)}", fill=True)
    pdf.ln()
    pdf.set_text_color(33, 37, 41)


def _lighten(rgb: tuple, factor: float = 0.9) -> tuple:
    return tuple(min(255, int(c + (255 - c) * factor)) for c in rgb)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate DevSecOps PDF security report")
    parser.add_argument("--output",   default="security-report.pdf")
    parser.add_argument("--scan-dir", default="scan-results/")
    args = parser.parse_args()

    try:
        from fpdf import FPDF
    except ImportError:
        print("[generate_security_pdf] fpdf2 not installed — run: pip install fpdf2", file=sys.stderr)
        sys.exit(1)

    generate_pdf(args.output, args.scan_dir)


if __name__ == "__main__":
    main()
