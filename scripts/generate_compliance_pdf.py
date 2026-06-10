#!/usr/bin/env python3
"""
scripts/generate_compliance_pdf.py — PDF Report Generator

Generates a professional, audit-ready PDF summary of the compliance posture.
"""

import argparse
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
try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
except ImportError:
    print("ERROR: fpdf2 is required. Run: pip install fpdf2")
    sys.exit(1)


def create_pdf(summary_data: dict, output_path: str):
    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    
    # ── Cover Page ──
    pdf.set_fill_color(15, 23, 42) # slate-900
    pdf.rect(0, 0, 210, 50, "F")
    
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_y(20)
    pdf.cell(0, 10, "SOC 2 COMPLIANCE REPORT", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 10, "Automated Evidence Collection & Validation", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Reset
    pdf.set_text_color(33, 37, 41)
    pdf.ln(20)
    
    # Executive Summary
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(50, 8, "Date Generated:")
    pdf.cell(0, 8, summary_data.get("generated_at", ""), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    score = summary_data.get("compliance_score_percent", 0.0)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(50, 8, "Compliance Score:")
    if score >= 90:
        pdf.set_text_color(0, 128, 0)
    elif score >= 70:
        pdf.set_text_color(200, 100, 0)
    else:
        pdf.set_text_color(200, 0, 0)
    pdf.cell(0, 8, f"{score}%", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)
    
    status = summary_data.get("overall_status", "UNKNOWN")
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(50, 8, "Overall Status:")
    if status == "PASS":
        pdf.set_text_color(0, 128, 0)
    else:
        pdf.set_text_color(200, 0, 0)
    pdf.cell(0, 8, status, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(33, 37, 41)
    
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(50, 8, "Total Controls Checked:")
    pdf.cell(0, 8, str(summary_data.get("total_controls_checked", 0)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.cell(50, 8, "Passed:")
    pdf.cell(0, 8, str(summary_data.get("pass_count", 0)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.cell(50, 8, "Failed:")
    pdf.cell(0, 8, str(summary_data.get("fail_count", 0)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.cell(50, 8, "Warnings:")
    pdf.cell(0, 8, str(summary_data.get("warn_count", 0)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    pdf.ln(10)
    
    # Evidence Sources
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Evidence Sources", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    for src, state in summary_data.get("evidence_sources", {}).items():
        pdf.cell(50, 8, f"• {src.upper()}:")
        pdf.cell(0, 8, state.capitalize(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
    pdf.ln(10)
    
    # Matrix
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Control Status Matrix", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Table Header
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(20, 8, "ID", border=1, fill=True)
    pdf.cell(100, 8, "Control Description", border=1, fill=True)
    pdf.cell(20, 8, "Status", border=1, fill=True)
    pdf.cell(30, 8, "Details", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Table Rows
    pdf.set_font("Helvetica", "", 9)
    for ctrl in summary_data.get("controls_matrix", []):
        pdf.cell(20, 8, str(ctrl.get("id", "")), border=1)
        pdf.cell(100, 8, str(ctrl.get("name", "")), border=1)
        
        status = ctrl.get("status", "")
        if status == "PASS":
            pdf.set_text_color(0, 128, 0)
        elif status == "FAIL":
            pdf.set_text_color(200, 0, 0)
        elif status == "WARN":
            pdf.set_text_color(200, 100, 0)
            
        pdf.cell(20, 8, status, border=1)
        pdf.set_text_color(33, 37, 41)
        
        reason = str(ctrl.get("reason", ""))[:30] + ("..." if len(str(ctrl.get("reason", ""))) > 30 else "")
        pdf.cell(30, 8, reason, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
    pdf.ln(10)
    
    # Architecture Diagram Page
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "System Architecture & Endpoints", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, "Visual representation of the SOC 2 Compliance Data Flow:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(10)
    
    # FPDF Drawing Primitives for Diagram
    
    # Box 1: GitHub Actions (Central)
    pdf.set_fill_color(241, 245, 249)
    pdf.rect(80, 60, 50, 20, "DF")
    pdf.set_font("Helvetica", "B", 10)
    pdf.text(85, 71, "GitHub Actions Pipeline")
    
    # Box 2: Zoho HR (Top Left)
    pdf.set_fill_color(224, 242, 254)
    pdf.rect(20, 30, 40, 15, "DF")
    pdf.text(25, 38, "Zoho HR System")
    
    # Box 3: Shannon AI (Top Right)
    pdf.set_fill_color(254, 226, 226)
    pdf.rect(150, 30, 40, 15, "DF")
    pdf.text(152, 38, "Shannon AI Pentest")
    
    # Box 4: AWS Environment (Bottom Block)
    pdf.set_fill_color(248, 250, 252)
    pdf.rect(20, 110, 170, 50, "DF")
    pdf.set_font("Helvetica", "B", 12)
    pdf.text(25, 120, "AWS Cloud Infrastructure")
    
    # Inside AWS
    pdf.set_fill_color(255, 255, 255)
    pdf.rect(30, 130, 35, 20, "DF")
    pdf.set_font("Helvetica", "", 9)
    pdf.text(35, 141, "IAM & Roles")
    
    pdf.rect(75, 130, 35, 20, "DF")
    pdf.text(78, 141, "CloudTrail/Watch")
    
    pdf.set_fill_color(209, 250, 229)
    pdf.rect(120, 130, 60, 20, "DF")
    pdf.set_font("Helvetica", "B", 9)
    pdf.text(125, 141, "S3 Evidence Vault (WORM)")
    
    # Lines & Arrows
    pdf.set_line_width(0.5)
    
    # Zoho to GitHub
    pdf.line(40, 45, 80, 65)
    pdf.text(50, 58, "Policies")
    
    # Shannon to GitHub
    pdf.line(170, 45, 130, 65)
    pdf.text(145, 58, "Vuln Reports")
    
    # GitHub to AWS Vault
    pdf.line(105, 80, 150, 130)
    pdf.text(130, 105, "Upload Evidence")
    
    # GitHub to AWS APIs
    pdf.line(105, 80, 50, 130)
    pdf.text(60, 105, "Audit Configurations")
    
    pdf.ln(120)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 10, "Diagram: Automated evidence collection routing technical and non-technical artifacts into the secure AWS Vault.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Footer function implicitly adds page numbers if we subclass, but simple generation here
    output_bytes = bytes(pdf.output())
    with open(output_path, "wb") as f:
        f.write(output_bytes)


def main():
    parser = argparse.ArgumentParser(description="Generate PDF report from compliance JSON")
    parser.add_argument("--summary", required=True, help="Path to compliance_summary_latest.json")
    parser.add_argument("--output", required=True, help="Output path for PDF")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--bucket", default=os.environ.get("S3_BUCKET", ""))
    args = parser.parse_args()

    summary_path = Path(args.summary)
    if not summary_path.exists():
        print(f"Warning: {summary_path} not found. Generating failure fallback PDF.")
        import datetime
        data = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "overall_status": "CRITICAL (COLLECTION FAILED)",
            "total_controls_checked": 0,
            "pass_count": 0,
            "fail_count": 1,
            "warn_count": 0,
            "evidence_sources": {
                "aws": "failed",
                "github": "failed",
                "zoho": "failed"
            },
            "controls_matrix": [
                {
                    "id": "SYS.1",
                    "name": "Audit Collection Pipeline",
                    "status": "FAIL",
                    "reason": "Pipeline crashed before JSON generation"
                }
            ]
        }
    else:
        data = json.loads(summary_path.read_text())
    
    create_pdf(data, args.output)
    print(f"[PDF Gen] Created {args.output}")
    
    if args.upload and args.bucket:
        import boto3
        s3 = boto3.client("s3")
        key = f"evidence/reports/{Path(args.output).name}"
        s3.upload_file(args.output, args.bucket, key,
                       ExtraArgs={"ContentType": "application/pdf"})
        print(f"[PDF Gen] Uploaded: s3://{args.bucket}/{key}")


if __name__ == "__main__":
    main()
