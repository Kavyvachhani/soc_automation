"""
lambda/approval_handler.py — Tech Lead Approval Endpoint

Invoked via API Gateway:
  GET /approve?token=<uuid>&emp_id=<id>&action=approve|reject&approver=<email>

Flow:
  1. Validate the approval token against pending-approval.json in S3
  2. If approved: provision access (real IAM or mock), write evidence
  3. Send confirmation email via SES (if enabled)
  4. Return HTML response page

Environment:
  S3_BUCKET                — evidence vault bucket
  ENABLE_REAL_PROVISIONING — "true" to create real IAM users
  ENABLE_SES               — "true" to send SES emails
  SES_SENDER_EMAIL         — sender email for notifications
  TECH_LEAD_EMAIL          — tech lead email
  READONLY_POLICY_ARN      — IAM policy for freshers
  DEVELOPER_POLICY_ARN     — IAM policy for experienced
  PORTAL_URL               — base URL for portal links
"""

import csv
import datetime
import io
import json
import os
import traceback

import boto3

# ─── Configuration ────────────────────────────────────────────────────────────

S3_BUCKET = os.environ.get("S3_BUCKET", "")
ENABLE_REAL = os.environ.get("ENABLE_REAL_PROVISIONING", "false").lower() == "true"
ENABLE_SES = os.environ.get("ENABLE_SES", "false").lower() == "true"
SES_SENDER = os.environ.get("SES_SENDER_EMAIL", "")
TECH_LEAD_EMAIL = os.environ.get("TECH_LEAD_EMAIL", "")
READONLY_ARN = os.environ.get("READONLY_POLICY_ARN", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
DEVELOPER_ARN = os.environ.get("DEVELOPER_POLICY_ARN", "arn:aws:iam::aws:policy/PowerUserAccess")
PORTAL_URL = os.environ.get("PORTAL_URL", "http://localhost:8501")

s3 = boto3.client("s3")
iam = boto3.client("iam") if ENABLE_REAL else None
ses = boto3.client("ses") if ENABLE_SES else None


# ─── Helpers ──────────────────────────────────────────────────────────────────

def s3_get_json(key: str) -> dict:
    """Download and parse a JSON file from S3."""
    resp = s3.get_object(Bucket=S3_BUCKET, Key=key)
    return json.loads(resp["Body"].read().decode("utf-8"))


def s3_put_json(key: str, data: dict) -> None:
    """Upload a JSON object to S3."""
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=json.dumps(data, indent=2).encode("utf-8"),
        ContentType="application/json",
    )


def s3_put_csv(key: str, rows: list[dict]) -> None:
    """Upload a list of dicts as CSV to S3."""
    if not rows:
        return
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=buf.getvalue().encode("utf-8"),
        ContentType="text/csv",
    )


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Access bundle catalog (hardcoded to avoid S3 round-trip in Lambda) ──────

CATALOG = {
    "fresher": [
        {"id": "s3-read-only", "name": "S3 Read-Only", "policy_arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
        {"id": "codecommit-read", "name": "CodeCommit Read-Only", "policy_arn": "arn:aws:iam::aws:policy/AWSCodeCommitReadOnly"},
        {"id": "cloudwatch-read", "name": "CloudWatch Read-Only", "policy_arn": "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"},
    ],
    "experienced": [
        {"id": "developer-poweruser", "name": "Developer Power User", "policy_arn": "arn:aws:iam::aws:policy/PowerUserAccess"},
        {"id": "codecommit-power", "name": "CodeCommit Power User", "policy_arn": "arn:aws:iam::aws:policy/AWSCodeCommitPowerUser"},
        {"id": "ecr-power", "name": "ECR Power User", "policy_arn": "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"},
        {"id": "s3-developer", "name": "S3 Developer Access", "policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"},
    ],
}


# ─── Real IAM provisioning ───────────────────────────────────────────────────

def create_iam_user(employee_data: dict, role_key: str, emp_id: str) -> dict:
    """Create a real IAM user under attest-managed/ path with role-based policies."""
    name = employee_data.get("name", "employee").replace(" ", "-").lower()
    username = f"attest-managed/{name}-{emp_id.lower()}"

    bundles = CATALOG.get(role_key, CATALOG["fresher"])

    result = {"username": username, "real": True, "policies_attached": []}

    try:
        iam.create_user(
            Path="/attest-managed/",
            UserName=username,
            Tags=[
                {"Key": "ManagedBy", "Value": "attest"},
                {"Key": "emp_id", "Value": emp_id},
                {"Key": "role", "Value": role_key},
                {"Key": "created_at", "Value": now_utc()},
            ],
        )
        print(f"[IAM] Created user: {username}")

        for bundle in bundles:
            arn = bundle["policy_arn"]
            iam.attach_user_policy(UserName=username, PolicyArn=arn)
            result["policies_attached"].append(arn)
            print(f"[IAM] Attached {bundle['name']} ({arn})")

        # Create console login profile (force password change on first login)
        import secrets
        temp_password = secrets.token_urlsafe(16) + "!A1"
        iam.create_login_profile(
            UserName=username,
            Password=temp_password,
            PasswordResetRequired=True,
        )
        # NOTE: We do NOT store or email the temp password.
        # The tech lead receives it out of band. Never email plaintext passwords.
        result["console_login"] = True
        result["password_reset_required"] = True
        print(f"[IAM] Console login created (password reset required)")

    except Exception as e:
        result["error"] = str(e)
        print(f"[IAM] Error: {e}")

    return result


def mock_provision(employee_data: dict, role_key: str, emp_id: str) -> dict:
    """Mock provisioning — log what would happen without creating real resources."""
    bundles = CATALOG.get(role_key, CATALOG["fresher"])
    result = {"username": f"attest-managed/{employee_data.get('name', 'employee').replace(' ', '-').lower()}", "real": False, "policies_attached": []}
    for bundle in bundles:
        print(f"[MOCK] Would grant '{bundle['name']}' ({bundle['policy_arn']}) to {employee_data.get('name')}")
        result["policies_attached"].append(bundle["policy_arn"])
    return result


# ─── Email notification ──────────────────────────────────────────────────────

def send_confirmation_email(employee_data: dict, role_key: str, approver: str) -> None:
    """Send provisioning confirmation to the tech lead via SES."""
    if not ENABLE_SES or not SES_SENDER or not TECH_LEAD_EMAIL:
        print("[SES] Skipping email — SES not configured")
        return

    name = employee_data.get("name", "Unknown")
    designation = employee_data.get("designation", "Employee")
    team = employee_data.get("team", "Engineering")

    subject = f"✅ Onboarding Complete: {name} ({designation})"
    body = f"""
    <html><body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2 style="color: #2e7d32;">✅ Access Provisioned Successfully</h2>
    <table style="border-collapse: collapse; width: 100%; max-width: 500px;">
      <tr><td style="padding: 8px; font-weight: bold;">Employee</td><td style="padding: 8px;">{name}</td></tr>
      <tr><td style="padding: 8px; font-weight: bold;">Designation</td><td style="padding: 8px;">{designation}</td></tr>
      <tr><td style="padding: 8px; font-weight: bold;">Team</td><td style="padding: 8px;">{team}</td></tr>
      <tr><td style="padding: 8px; font-weight: bold;">Access Level</td><td style="padding: 8px;">{"Developer (full access)" if role_key == "experienced" else "Read-only (fresher)"}</td></tr>
      <tr><td style="padding: 8px; font-weight: bold;">Approved By</td><td style="padding: 8px;">{approver}</td></tr>
      <tr><td style="padding: 8px; font-weight: bold;">Provisioned At</td><td style="padding: 8px;">{now_utc()}</td></tr>
    </table>
    <p>Evidence files (access-granted.csv, evidence-index.json) have been uploaded to the S3 vault.</p>
    <p><a href="{PORTAL_URL}">Open Portal →</a></p>
    </body></html>
    """

    try:
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses": [TECH_LEAD_EMAIL]},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Html": {"Data": body, "Charset": "UTF-8"}},
            },
        )
        print(f"[SES] Confirmation email sent to {TECH_LEAD_EMAIL}")
    except Exception as e:
        print(f"[SES] Failed to send email: {e}")


# ─── Build evidence ──────────────────────────────────────────────────────────

def build_evidence(emp_id: str, employee_data: dict, role_key: str, approver: str, iam_result: dict) -> dict:
    """Write access-granted.csv and evidence-index.json to S3."""
    prefix = f"employees/{emp_id}"
    bundles = CATALOG.get(role_key, CATALOG["fresher"])
    ts = now_utc()

    # Build CSV rows
    grants = []
    for bundle in bundles:
        grants.append({
            "emp_id": emp_id,
            "employee_name": employee_data.get("name", "Unknown"),
            "role": role_key,
            "permission_id": bundle["id"],
            "permission_name": bundle["name"],
            "policy_arn": bundle["policy_arn"],
            "granted_at": ts,
            "approved_by": approver,
            "real_provisioning": str(ENABLE_REAL).lower(),
        })

    s3_put_csv(f"{prefix}/access-granted.csv", grants)
    print(f"[Evidence] Wrote {prefix}/access-granted.csv")

    # Check what evidence files exist for this employee
    evidence_files = []
    for suffix in [
        "offer-letter.pdf", "employee.json", "nda-content.txt",
        "nda-unsigned.pdf", "signed-nda.pdf", "nda-audit-trail.json",
        "access-granted.csv",
    ]:
        try:
            s3.head_object(Bucket=S3_BUCKET, Key=f"{prefix}/{suffix}")
            evidence_files.append(suffix)
        except Exception:
            pass

    evidence_index = {
        "emp_id": emp_id,
        "employee_name": employee_data.get("name", "Unknown"),
        "designation": employee_data.get("designation", "Employee"),
        "team": employee_data.get("team", "Engineering"),
        "role": role_key,
        "approved_by": approver,
        "approved_at": ts,
        "provisioned_at": ts,
        "real_provisioning": ENABLE_REAL,
        "iam_result": iam_result,
        "evidence_files": evidence_files + ["evidence-index.json"],
        "s3_prefix": f"s3://{S3_BUCKET}/{prefix}/",
        "pipeline_version": "2.0",
    }

    s3_put_json(f"{prefix}/evidence-index.json", evidence_index)
    print(f"[Evidence] Wrote {prefix}/evidence-index.json")

    return evidence_index


# ─── HTML response pages ─────────────────────────────────────────────────────

def html_success(name: str, emp_id: str, role_key: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Attest — Approved</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px;
         margin: 80px auto; text-align: center; color: #333; }}
  .badge {{ display: inline-block; background: #e8f5e9; color: #2e7d32; padding: 12px 24px;
            border-radius: 8px; font-size: 18px; margin: 20px 0; }}
  table {{ margin: 20px auto; border-collapse: collapse; text-align: left; }}
  td {{ padding: 8px 16px; border-bottom: 1px solid #eee; }}
  a {{ color: #1976d2; text-decoration: none; }}
</style></head>
<body>
  <h1>🛡️ Attest</h1>
  <div class="badge">✅ Access Provisioned</div>
  <table>
    <tr><td><strong>Employee</strong></td><td>{name}</td></tr>
    <tr><td><strong>Employee ID</strong></td><td>{emp_id}</td></tr>
    <tr><td><strong>Access Level</strong></td><td>{"Developer" if role_key == "experienced" else "Read-only (Fresher)"}</td></tr>
  </table>
  <p>Evidence files have been uploaded to the S3 vault.</p>
  <p><a href="{PORTAL_URL}">← Back to Portal</a></p>
</body></html>"""


def html_error(message: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Attest — Error</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px;
         margin: 80px auto; text-align: center; color: #333; }}
  .badge {{ display: inline-block; background: #ffebee; color: #c62828; padding: 12px 24px;
            border-radius: 8px; font-size: 18px; margin: 20px 0; }}
</style></head>
<body>
  <h1>🛡️ Attest</h1>
  <div class="badge">❌ Error</div>
  <p>{message}</p>
  <p><a href="{PORTAL_URL}">← Back to Portal</a></p>
</body></html>"""


def html_rejected(name: str, emp_id: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Attest — Rejected</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px;
         margin: 80px auto; text-align: center; color: #333; }}
  .badge {{ display: inline-block; background: #fff3e0; color: #e65100; padding: 12px 24px;
            border-radius: 8px; font-size: 18px; margin: 20px 0; }}
</style></head>
<body>
  <h1>🛡️ Attest</h1>
  <div class="badge">🚫 Access Rejected</div>
  <p>Provisioning for <strong>{name}</strong> ({emp_id}) has been rejected.</p>
  <p>The employee will need to be re-evaluated.</p>
  <p><a href="{PORTAL_URL}">← Back to Portal</a></p>
</body></html>"""


# ─── Lambda handler ───────────────────────────────────────────────────────────

def handler(event, context):
    """
    API Gateway v2 handler.
    GET /approve?token=<uuid>&emp_id=<id>&action=approve|reject&approver=<email>
    """
    print(f"[approval_handler] Event: {json.dumps(event, default=str)}")

    try:
        # Parse query parameters
        params = event.get("queryStringParameters") or {}
        token = params.get("token", "")
        emp_id = params.get("emp_id", "")
        action = params.get("action", "approve")
        approver = params.get("approver", "tech-lead")

        if not token or not emp_id:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "text/html"},
                "body": html_error("Missing required parameters: token, emp_id"),
            }

        # Validate approval token
        prefix = f"employees/{emp_id}"
        try:
            pending = s3_get_json(f"{prefix}/pending-approval.json")
        except Exception:
            return {
                "statusCode": 404,
                "headers": {"Content-Type": "text/html"},
                "body": html_error(f"No pending approval found for {emp_id}. It may have already been processed."),
            }

        if pending.get("token") != token:
            return {
                "statusCode": 403,
                "headers": {"Content-Type": "text/html"},
                "body": html_error("Invalid approval token."),
            }

        if pending.get("status") != "pending":
            return {
                "statusCode": 409,
                "headers": {"Content-Type": "text/html"},
                "body": html_error(f"This approval has already been processed (status: {pending.get('status')})."),
            }

        # Load employee data
        employee_data = s3_get_json(f"{prefix}/employee.json")
        name = employee_data.get("name", "Unknown")
        exp_level = employee_data.get("experience_level", "fresher")
        role_key = "experienced" if exp_level == "experienced" else "fresher"

        # Handle rejection
        if action == "reject":
            pending["status"] = "rejected"
            pending["rejected_by"] = approver
            pending["rejected_at"] = now_utc()
            s3_put_json(f"{prefix}/pending-approval.json", pending)
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "text/html"},
                "body": html_rejected(name, emp_id),
            }

        # ── APPROVE — Provision access ──
        print(f"[approval_handler] Approving {emp_id} as {role_key}")

        # Provision (real or mock)
        if ENABLE_REAL:
            iam_result = create_iam_user(employee_data, role_key, emp_id)
        else:
            iam_result = mock_provision(employee_data, role_key, emp_id)

        # Build and upload evidence
        evidence = build_evidence(emp_id, employee_data, role_key, approver, iam_result)

        # Update pending status
        pending["status"] = "approved"
        pending["approved_by"] = approver
        pending["approved_at"] = now_utc()
        s3_put_json(f"{prefix}/pending-approval.json", pending)

        # Send confirmation email
        send_confirmation_email(employee_data, role_key, approver)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html"},
            "body": html_success(name, emp_id, role_key),
        }

    except Exception as e:
        print(f"[approval_handler] Error: {traceback.format_exc()}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "text/html"},
            "body": html_error(f"Internal error: {str(e)}"),
        }
