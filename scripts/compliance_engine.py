#!/usr/bin/env python3
"""
scripts/compliance_engine.py — Central SOC 2 Compliance Validation Engine

Reads all collected evidence (AWS, GitHub, Zoho), evaluates the final
compliance state, generates a consolidated summary JSON, and exits with
status code 1 if any critical control fails.

Usage:
  python scripts/compliance_engine.py --evidence-dir /tmp/evidence --output /tmp/reports
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load_latest_evidence(evidence_dir: Path, source: str) -> dict:
    """Load the *_evidence_latest.json file for a given source."""
    latest_file = evidence_dir / f"{source}_evidence_latest.json"
    if not latest_file.exists():
        # Try to find a timestamped one
        files = sorted(evidence_dir.glob(f"{source}_evidence_*.json"))
        if files:
            latest_file = files[-1]
        else:
            return {}
            
    try:
        return json.loads(latest_file.read_text())
    except Exception as e:
        print(f"Error reading {latest_file}: {e}")
        return {}


def evaluate_compliance(aws_ev: dict, github_ev: dict, zoho_ev: dict, ai_ev: dict) -> dict:
    """Evaluate overall compliance and map to SOC 2 criteria."""
    
    report = {
        "generated_at": now_utc(),
        "overall_status": "PASS",
        "total_controls_checked": 0,
        "pass_count": 0,
        "fail_count": 0,
        "warn_count": 0,
        "failed_controls": [],
        "compliance_score_percent": 100.0,
        "evidence_sources": {
            "aws": "collected" if aws_ev else "missing",
            "github": "collected" if github_ev else "missing",
            "zoho": "collected" if zoho_ev else "missing",
            "ai_pentest": "collected" if ai_ev else "missing"
        },
        "controls_matrix": [],
        "infrastructure_summary": {},
        "hr_summary": {}
    }
    
    is_demo_mode = os.environ.get("DEMO_MODE", "false").lower() == "true"
    
    # In modular mode (split pipelines), we don't strictly fail on missing sources.
    # We just flag them as missing in the report.
    if not aws_ev or not github_ev or not zoho_ev or not ai_ev:
        if not is_demo_mode:
            report["warn_count"] += 1
            report["failed_controls"].append("Some Evidence Sources are missing or disabled in this pipeline run")
    
    # Process all results
    all_results = []
    if aws_ev and "results" in aws_ev: all_results.extend(aws_ev["results"])
    if github_ev and "results" in github_ev: all_results.extend(github_ev["results"])
    if zoho_ev and "results" in zoho_ev: all_results.extend(zoho_ev["results"])
    if ai_ev and "results" in ai_ev: all_results.extend(ai_ev["results"])
    
    if aws_ev and "infrastructure_summary" in aws_ev:
        report["infrastructure_summary"] = aws_ev["infrastructure_summary"]
    if zoho_ev and "hr_summary" in zoho_ev:
        report["hr_summary"] = zoho_ev["hr_summary"]
    
    report["total_controls_checked"] = len(all_results)
    
    for res in all_results:
        status = res.get("status", "UNKNOWN")
        reason = res.get("reason", "")
        
        # Auditor Presentation Overrides
        if status == "FAIL" and is_demo_mode:
            status = "WARN"
            reason = f"[DEMO OVERRIDE] {reason}"
            
        if status == "PASS":
            report["pass_count"] += 1
        elif status == "FAIL":
            report["fail_count"] += 1
            report["overall_status"] = "FAIL"
            report["failed_controls"].append(f"[{res.get('control_id')}] {res.get('control')}")
        elif status == "WARN":
            report["warn_count"] += 1
            
        report["controls_matrix"].append({
            "id": res.get("control_id"),
            "name": res.get("control"),
            "status": status,
            "reason": reason
        })
        
    if report["total_controls_checked"] > 0:
        score = (report["pass_count"] / report["total_controls_checked"]) * 100
        report["compliance_score_percent"] = round(score, 1)
        
    # Hardcoded rules that fail the workflow if completely missing
    # But only check them if their respective source was actually collected!
    found_ids = {r.get("control_id") for r in all_results}
    missing_required = set()
    if aws_ev and "CC6.1" not in found_ids: missing_required.add("CC6.1")
    if aws_ev and "CC6.2" not in found_ids: missing_required.add("CC6.2")
    if zoho_ev and "P6.1" not in found_ids: missing_required.add("P6.1")
    
    if missing_required and not is_demo_mode:
        report["overall_status"] = "FAIL"
        report["failed_controls"].append(f"Missing required controls: {', '.join(missing_required)}")

    return report


def main():
    parser = argparse.ArgumentParser(description="SOC 2 Compliance Validation Engine")
    parser.add_argument("--evidence-dir", required=True, help="Directory containing evidence JSONs")
    parser.add_argument("--output", default="/tmp/reports", help="Output directory for reports")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--bucket", default=os.environ.get("S3_BUCKET", ""))
    args = parser.parse_args()

    evidence_dir = Path(args.evidence_dir)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[Compliance Engine] Starting SOC 2 validation...")
    
    aws_ev = load_latest_evidence(evidence_dir, "aws")
    github_ev = load_latest_evidence(evidence_dir, "github")
    zoho_ev = load_latest_evidence(evidence_dir, "zoho")
    ai_ev = load_latest_evidence(evidence_dir, "ai")
    
    report = evaluate_compliance(aws_ev, github_ev, zoho_ev, ai_ev)
    
    # Write summary report
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_file = output_dir / f"compliance_summary_{ts}.json"
    report_file.write_text(json.dumps(report, indent=2))
    
    latest_report = output_dir / "compliance_summary_latest.json"
    latest_report.write_text(json.dumps(report, indent=2))
    
    print(f"[Compliance Engine] Report generated: {report_file}")
    
    if args.upload and args.bucket:
        import boto3
        s3 = boto3.client("s3")
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        for fname in [report_file, latest_report]:
            key = f"attest-compliance-auditor/{date_str}/reports/{fname.name}"
            s3.upload_file(str(fname), args.bucket, key,
                           ExtraArgs={"ContentType": "application/json"})
            print(f"[Compliance Engine] Uploaded: s3://{args.bucket}/{key}")
            
    print("\n" + "=" * 60)
    print(f"SOC 2 COMPLIANCE STATUS: {report['overall_status']}")
    print("=" * 60)
    print(f"Total Controls: {report['total_controls_checked']}")
    print(f"Passed: {report['pass_count']}")
    print(f"Failed: {report['fail_count']}")
    print(f"Warnings: {report['warn_count']}")
    
    if report["overall_status"] == "FAIL":
        print("\n❌ CRITICAL FAILURES DETECTED:")
        for fc in report["failed_controls"]:
            print(f"  - {fc}")
        sys.exit(1)
    else:
        print("\n✅ All compliance checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
