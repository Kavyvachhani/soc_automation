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
        
        reason = str(ctrl.get("reason", ""))[:20] + ("..." if len(str(ctrl.get("reason", ""))) > 20 else "")
        pdf.cell(30, 8, reason, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
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
        print(f"Error: {summary_path} not found.")
        sys.exit(1)
        
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
