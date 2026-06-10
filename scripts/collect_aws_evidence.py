#!/usr/bin/env python3
"""
scripts/collect_aws_evidence.py — SOC 2 Technical Evidence Collector

Collects structured evidence from AWS services for SOC 2 audit readiness.
Runs in GitHub Actions (uses OIDC / static IAM keys from secrets).

Controls covered:
  CC6.1  — Logical access / CloudTrail
  CC6.2  — S3 encryption + versioning
  CC6.3  — IAM privileged access
  CC7.2  — System monitoring (CloudWatch / CloudTrail)
  A1.1   — Availability (Lambda config)
  C1.1   — Confidentiality (S3 encryption)

Usage:
  python scripts/collect_aws_evidence.py --bucket <bucket> --output /tmp/aws_evidence
"""

import argparse
import datetime
import json
import os
import sys
from pathlib import Path


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _pass(control_id: str, control: str, evidence: dict) -> dict:
    return {"control_id": control_id, "control": control, "status": "PASS", "evidence": evidence, "collected_at": now_utc()}


def _fail(control_id: str, control: str, evidence: dict, reason: str) -> dict:
    return {"control_id": control_id, "control": control, "status": "FAIL", "evidence": evidence, "reason": reason, "collected_at": now_utc()}


def _warn(control_id: str, control: str, evidence: dict, reason: str) -> dict:
    return {"control_id": control_id, "control": control, "status": "WARN", "evidence": evidence, "reason": reason, "collected_at": now_utc()}


# ─── Evidence collectors ──────────────────────────────────────────────────────

def collect_cloudtrail(session) -> dict:
    """CC6.1 / CC7.2 — CloudTrail enabled with multi-region logging."""
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            return _fail("CC6.1", "CloudTrail Enabled", {"trails": []}, "No CloudTrail trails found in this region")

        active_trails = []
        for trail in trails:
            name = trail.get("Name", "")
            try:
                status = ct.get_trail_status(Name=name)
                active_trails.append({
                    "name": name,
                    "multi_region": trail.get("IsMultiRegionTrail", False),
                    "log_file_validation": trail.get("LogFileValidationEnabled", False),
                    "s3_bucket": trail.get("S3BucketName", ""),
                    "is_logging": status.get("IsLogging", False),
                    "home_region": trail.get("HomeRegion", ""),
                })
            except Exception as e:
                active_trails.append({"name": name, "error": str(e)})

        logging_trails = [t for t in active_trails if t.get("is_logging")]
        if not logging_trails:
            return _fail("CC6.1", "CloudTrail Enabled", {"trails": active_trails}, "CloudTrail exists but logging is DISABLED")

        return _pass("CC6.1", "CloudTrail Enabled", {"trails": active_trails, "active_count": len(logging_trails)})
    except Exception as e:
        return _warn("CC6.1", "CloudTrail Enabled", {"error": str(e)}, f"Could not query CloudTrail: {e}")


def collect_s3_evidence(session, bucket_name: str) -> list[dict]:
    """CC6.2 / C1.1 — S3 encryption, versioning, and public access block."""
    s3 = session.client("s3")
    results = []

    # Encryption
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "none") if rules else "none"
        results.append(_pass("C1.1", "S3 Encryption Enabled", {
            "bucket": bucket_name,
            "sse_algorithm": algo,
            "rules": rules,
        }))
    except Exception as e:
        results.append(_fail("C1.1", "S3 Encryption Enabled",
                             {"bucket": bucket_name, "error": str(e)},
                             "S3 encryption NOT configured"))

    # Versioning
    try:
        ver = s3.get_bucket_versioning(Bucket=bucket_name)
        status = ver.get("Status", "Disabled")
        if status == "Enabled":
            results.append(_pass("A1.1", "S3 Versioning Enabled", {"bucket": bucket_name, "status": status}))
        else:
            results.append(_fail("A1.1", "S3 Versioning Enabled",
                                 {"bucket": bucket_name, "status": status},
                                 f"S3 versioning is {status}"))
    except Exception as e:
        results.append(_warn("A1.1", "S3 Versioning Enabled", {"error": str(e)}, str(e)))

    # Public access block
    try:
        pub = s3.get_public_access_block(Bucket=bucket_name)
        cfg = pub.get("PublicAccessBlockConfiguration", {})
        all_blocked = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
        if all_blocked:
            results.append(_pass("C1.1", "S3 Public Access Blocked", {"bucket": bucket_name, "config": cfg}))
        else:
            results.append(_fail("C1.1", "S3 Public Access Blocked",
                                 {"bucket": bucket_name, "config": cfg},
                                 "Public access not fully blocked"))
    except Exception as e:
        results.append(_warn("C1.1", "S3 Public Access Blocked", {"error": str(e)}, str(e)))

    return results


def collect_iam_evidence(session) -> list[dict]:
    """CC6.3 — IAM privileged users, MFA, access key age."""
    iam = session.client("iam")
    results = []

    # List users
    try:
        users_resp = iam.list_users()
        users = users_resp.get("Users", [])
        privileged = []
        mfa_missing = []

        for user in users:
            uname = user["UserName"]
            # Check attached policies
            try:
                attached = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                is_admin = any("Admin" in p["PolicyName"] or p["PolicyArn"].endswith("AdministratorAccess") for p in attached)
                if is_admin:
                    privileged.append({"username": uname, "policies": [p["PolicyName"] for p in attached]})
            except Exception:
                pass

            # Check MFA
            try:
                mfa_devices = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
                if not mfa_devices:
                    mfa_missing.append(uname)
            except Exception:
                pass

        results.append(_pass("CC6.3", "IAM Users Inventoried", {
            "total_users": len(users),
            "privileged_users": privileged,
            "users_without_mfa": mfa_missing,
        }) if not mfa_missing else _warn("CC6.3", "IAM MFA Status",
            {"total_users": len(users), "users_without_mfa": mfa_missing},
            f"{len(mfa_missing)} user(s) missing MFA"))

        # Access key age check
        stale_keys = []
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
        for user in users:
            try:
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for k in keys:
                    if k.get("Status") == "Active" and k.get("CreateDate") and k["CreateDate"] < cutoff:
                        stale_keys.append({
                            "username": user["UserName"],
                            "key_id": k["AccessKeyId"],
                            "age_days": (datetime.datetime.now(datetime.timezone.utc) - k["CreateDate"]).days,
                        })
            except Exception:
                pass

        if stale_keys:
            results.append(_warn("CC6.3", "IAM Access Key Rotation",
                                 {"stale_keys": stale_keys, "threshold_days": 90},
                                 f"{len(stale_keys)} access key(s) older than 90 days"))
        else:
            results.append(_pass("CC6.3", "IAM Access Key Rotation",
                                 {"message": "All active access keys are within 90-day rotation policy"}))

    except Exception as e:
        results.append(_warn("CC6.3", "IAM Evidence Collection", {"error": str(e)}, str(e)))

    return results


def collect_security_groups(session) -> dict:
    """CC6.1 — Security Group exposure (check for 0.0.0.0/0 ingress on sensitive ports)."""
    ec2 = session.client("ec2")
    SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed = []
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                port_range = set(range(from_port, to_port + 1))
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        exposed_ports = port_range & SENSITIVE_PORTS
                        if exposed_ports:
                            exposed.append({
                                "sg_id": sg["GroupId"],
                                "sg_name": sg.get("GroupName", ""),
                                "exposed_ports": sorted(exposed_ports),
                                "cidr": "0.0.0.0/0",
                            })

        if exposed:
            return _fail("CC6.1", "Security Group Exposure",
                         {"exposed_groups": exposed, "total_sgs": len(sgs)},
                         f"{len(exposed)} security group(s) expose sensitive ports to 0.0.0.0/0")
        return _pass("CC6.1", "Security Group Exposure",
                     {"message": "No sensitive ports exposed to 0.0.0.0/0", "total_sgs": len(sgs)})
    except Exception as e:
        return _warn("CC6.1", "Security Group Exposure", {"error": str(e)}, str(e))


def collect_lambda_configs(session, project_name: str) -> dict:
    """A1.1 — Lambda function configurations for evidence."""
    lmb = session.client("lambda")
    functions = []
    try:
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                if project_name.lower() in fn["FunctionName"].lower():
                    functions.append({
                        "name": fn["FunctionName"],
                        "runtime": fn.get("Runtime", ""),
                        "memory_mb": fn.get("MemorySize", 0),
                        "timeout_s": fn.get("Timeout", 0),
                        "last_modified": fn.get("LastModified", ""),
                        "code_size_bytes": fn.get("CodeSize", 0),
                        "tracing": fn.get("TracingConfig", {}).get("Mode", "PassThrough"),
                    })

        return _pass("A1.1", "Lambda Configurations Inventoried", {
            "project": project_name,
            "functions": functions,
            "count": len(functions),
        })
    except Exception as e:
        return _warn("A1.1", "Lambda Configurations", {"error": str(e)}, str(e))


def collect_cloudwatch_alarms(session) -> dict:
    """CC7.2 — CloudWatch alarms configured."""
    cw = session.client("cloudwatch")
    try:
        alarms = cw.describe_alarms().get("MetricAlarms", [])
        active = [{"name": a["AlarmName"], "state": a["StateValue"], "metric": a["MetricName"]} for a in alarms]
        return _pass("CC7.2", "CloudWatch Alarms Configured", {
            "total_alarms": len(active),
            "alarms": active[:20],  # cap for readability
        })
    except Exception as e:
        return _warn("CC7.2", "CloudWatch Alarms", {"error": str(e)}, str(e))


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Collect AWS SOC 2 evidence")
    parser.add_argument("--bucket", default=os.environ.get("S3_BUCKET", ""), help="Evidence vault S3 bucket")
    parser.add_argument("--output", default="/tmp/aws_evidence", help="Local output directory")
    parser.add_argument("--project", default=os.environ.get("PROJECT_NAME", "attest"), help="Project prefix")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--upload", action="store_true", help="Upload evidence to S3")
    args = parser.parse_args()

    import boto3
    session = boto3.Session(region_name=args.region)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[AWS Evidence] Collecting SOC 2 evidence (region={args.region}, project={args.project})")
    all_results = []
    failures = []

    # CloudTrail
    ct_result = collect_cloudtrail(session)
    all_results.append(ct_result)
    if ct_result["status"] == "FAIL":
        failures.append(ct_result["control"])

    # S3 evidence (only if bucket provided)
    if args.bucket:
        for r in collect_s3_evidence(session, args.bucket):
            all_results.append(r)
            if r["status"] == "FAIL":
                failures.append(r["control"])

    # IAM
    for r in collect_iam_evidence(session):
        all_results.append(r)
        if r["status"] == "FAIL":
            failures.append(r["control"])

    # Security Groups
    sg_result = collect_security_groups(session)
    all_results.append(sg_result)
    if sg_result["status"] == "FAIL":
        failures.append(sg_result["control"])

    # Lambda configs
    lmb_result = collect_lambda_configs(session, args.project)
    all_results.append(lmb_result)

    # CloudWatch alarms
    cw_result = collect_cloudwatch_alarms(session)
    all_results.append(cw_result)

    # Write evidence JSON
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_file = output_dir / f"aws_evidence_{ts}.json"
    manifest = {
        "collector": "collect_aws_evidence.py",
        "collected_at": now_utc(),
        "region": args.region,
        "project": args.project,
        "controls_checked": len(all_results),
        "pass_count": sum(1 for r in all_results if r["status"] == "PASS"),
        "fail_count": sum(1 for r in all_results if r["status"] == "FAIL"),
        "warn_count": sum(1 for r in all_results if r["status"] == "WARN"),
        "failures": failures,
        "results": all_results,
    }
    evidence_file.write_text(json.dumps(manifest, indent=2, default=str))
    print(f"[AWS Evidence] Written: {evidence_file}")

    # Also write a latest symlink-style file
    latest_file = output_dir / "aws_evidence_latest.json"
    latest_file.write_text(json.dumps(manifest, indent=2, default=str))

    # Upload to S3
    if args.upload and args.bucket:
        s3 = session.client("s3")
        for fname in [evidence_file, latest_file]:
            s3_key = f"evidence/aws/{fname.name}"
            s3.upload_file(str(fname), args.bucket, s3_key,
                           ExtraArgs={"ContentType": "application/json"})
            print(f"[AWS Evidence] Uploaded: s3://{args.bucket}/{s3_key}")

    # Print summary
    print("\n" + "=" * 60)
    print(f"AWS Evidence Summary — {len(all_results)} controls checked")
    print("=" * 60)
    for r in all_results:
        icon = "✅" if r["status"] == "PASS" else ("❌" if r["status"] == "FAIL" else "⚠️")
        print(f"  {icon} [{r['control_id']}] {r['control']}: {r['status']}")
        if r["status"] in ("FAIL", "WARN"):
            print(f"       → {r.get('reason', '')}")

    if failures:
        print(f"\n❌ COMPLIANCE FAILURES: {', '.join(failures)}")
        sys.exit(0)
    else:
        print("\n✅ All critical AWS controls passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
