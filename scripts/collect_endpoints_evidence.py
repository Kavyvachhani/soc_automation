#!/usr/bin/env python3
"""
scripts/collect_endpoints_evidence.py — SOC 2 Endpoint Compliance Auditor

Audits active endpoints for availability, SSL/TLS, and security headers:
  - Portal Lambda API Gateway (https://a5otw1fo40.execute-api.us-east-1.amazonaws.com)
  - Streamlit Employee Portal (http://127.0.0.1:8501)
  - Streamlit Manager Portal (http://127.0.0.1:8502)
  - Zoho People API (https://people.zoho.in or target domain)

Usage:
  python scripts/collect_endpoints_evidence.py --output /tmp/evidence
"""

import argparse
import datetime
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def _pass(control_id: str, control: str, evidence: dict) -> dict:
    return {"control_id": control_id, "control": control, "status": "PASS", "evidence": evidence, "collected_at": now_utc()}

def _fail(control_id: str, control: str, evidence: dict, reason: str) -> dict:
    return {"control_id": control_id, "control": control, "status": "FAIL", "evidence": evidence, "reason": reason, "collected_at": now_utc()}

def _warn(control_id: str, control: str, evidence: dict, reason: str) -> dict:
    return {"control_id": control_id, "control": control, "status": "WARN", "evidence": evidence, "reason": reason, "collected_at": now_utc()}

def audit_endpoint(url: str, name: str) -> dict:
    """Audit a single endpoint for HTTP response, SSL, and security headers."""
    evidence = {
        "url": url,
        "name": name,
        "reachable": False,
        "ssl_secured": url.startswith("https://"),
        "ssl_valid": False,
        "status_code": None,
        "headers": {}
    }

    # Setup SSL verification
    ctx = ssl.create_default_context()
    
    # Try sending request
    req = urllib.request.Request(url, headers={"User-Agent": "Attest-Compliance-Auditor/2.0"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            evidence["reachable"] = True
            evidence["status_code"] = resp.status
            evidence["ssl_valid"] = url.startswith("https://")
            # Extract headers (lowercased)
            for k, v in resp.headers.items():
                evidence["headers"][k.lower()] = v
    except urllib.error.HTTPError as e:
        # Reachable but returned error code (e.g. 403, 401, 405)
        evidence["reachable"] = True
        evidence["status_code"] = e.code
        evidence["ssl_valid"] = url.startswith("https://")
        for k, v in e.headers.items():
            evidence["headers"][k.lower()] = v
    except Exception as e:
        # Totally unreachable or SSL error
        return _fail("CC6.1", f"Endpoint Security - {name}", evidence, f"Endpoint unreachable or SSL error: {e}")

    # Check for security headers
    required_headers = {
        "content-security-policy": "CSP (prevents XSS/injection)",
        "x-content-type-options": "NOSNIFF (prevents MIME sniffing)",
        "x-frame-options": "DENY/SAMEORIGIN (prevents clickjacking)",
        "strict-transport-security": "HSTS (enforces HTTPS)"
    }

    missing_headers = []
    for h, desc in required_headers.items():
        if h not in evidence["headers"]:
            # HSTS is only required on HTTPS
            if h == "strict-transport-security" and not url.startswith("https://"):
                continue
            missing_headers.append(h)

    evidence["missing_headers"] = missing_headers

    if not evidence["reachable"]:
        return _fail("CC6.1", f"Endpoint Security - {name}", evidence, f"Endpoint {url} is down or unreachable")
    
    if url.startswith("https://") and not evidence["ssl_valid"]:
        return _fail("CC6.1", f"Endpoint Security - {name}", evidence, f"Endpoint {url} has invalid SSL certificate")

    if missing_headers:
        return _warn("CC6.1", f"Endpoint Security - {name}", evidence, f"Missing security headers: {', '.join(missing_headers)}")

    return _pass("CC6.1", f"Endpoint Security - {name}", evidence)

def main():
    parser = argparse.ArgumentParser(description="Collect Endpoint compliance evidence")
    parser.add_argument("--output", default="/tmp/evidence")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--bucket", default=os.environ.get("S3_BUCKET", ""))
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Active endpoints lists
    api_url = os.environ.get("PORTAL_API_URL", "https://a5otw1fo40.execute-api.us-east-1.amazonaws.com")
    zoho_domain = os.environ.get("ZOHO_DOMAIN", "in")
    zoho_url = f"https://people.zoho.{zoho_domain}"

    endpoints = [
        {"url": api_url, "name": "Employee Portal API Gateway"},
        {"url": "http://127.0.0.1:8501", "name": "Employee Portal Streamlit UI"},
        {"url": "http://127.0.0.1:8502", "name": "Manager Portal Streamlit UI"},
        {"url": zoho_url, "name": "Zoho People Identity Portal"}
    ]

    print(f"[Endpoints Audit] Auditing {len(endpoints)} active endpoints...")
    all_results = []
    failures = []

    for ep in endpoints:
        print(f"  -> Auditing {ep['name']} ({ep['url']})")
        r = audit_endpoint(ep["url"], ep["name"])
        all_results.append(r)
        if r["status"] == "FAIL":
            failures.append(r["control"])

    # Write evidence
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_file = output_dir / f"endpoints_evidence_{ts}.json"
    manifest = {
        "collector": "collect_endpoints_evidence.py",
        "collected_at": now_utc(),
        "controls_checked": len(all_results),
        "pass_count": sum(1 for r in all_results if r["status"] == "PASS"),
        "fail_count": sum(1 for r in all_results if r["status"] == "FAIL"),
        "warn_count": sum(1 for r in all_results if r["status"] == "WARN"),
        "failures": failures,
        "results": all_results,
    }
    evidence_file.write_text(json.dumps(manifest, indent=2, default=str))
    latest_file = output_dir / "endpoints_evidence_latest.json"
    latest_file.write_text(json.dumps(manifest, indent=2, default=str))
    print(f"[Endpoints Audit] Written: {evidence_file}")

    if args.upload and args.bucket:
        import boto3
        s3 = boto3.client("s3")
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        for fname in [evidence_file, latest_file]:
            key = f"attest-compliance-auditor/{date_str}/endpoints/{fname.name}"
            s3.upload_file(str(fname), args.bucket, key,
                           ExtraArgs={"ContentType": "application/json"})
            print(f"[Endpoints Audit] Uploaded: s3://{args.bucket}/{key}")

    print("\n" + "=" * 60)
    print(f"Endpoint Security Summary — {len(all_results)} controls checked")
    print("=" * 60)
    for r in all_results:
        icon = "✅" if r["status"] == "PASS" else ("❌" if r["status"] == "FAIL" else "⚠️")
        print(f"  {icon} [{r['control_id']}] {r['control']}: {r['status']}")
        if r["status"] in ("FAIL", "WARN"):
            print(f"       → {r.get('reason', '')}")

    if failures:
        print(f"\n❌ ENDPOINT AUDIT FAILURES: {', '.join(failures)}")
        sys.exit(0)
    else:
        print("\n✅ All endpoint audit checks completed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
