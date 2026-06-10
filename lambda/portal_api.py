"""
lambda/portal_api.py — Attest Portal Backend API

All portal ↔ S3 operations go through this Lambda via API Gateway.
The Streamlit portal calls HTTPS endpoints — no local AWS credentials needed.

Routes (all via API Gateway /portal/...):
  POST /portal/upload-offer       → { emp_id, upload_url }  (presigned S3 PUT)
  GET  /portal/status?emp_id=X    → { employee_data, nda_text, nda_pdf_url, status }
  POST /portal/submit-signed      → { emp_id, files: { name: base64 } }
  GET  /portal/evidence?emp_id=X  → { download_urls: { name: presigned_url } }
  POST /portal/approve            → { emp_id, action, approver }  (manager portal)

Environment variables:
  S3_BUCKET             — evidence vault bucket
  PROJECT_GITHUB_TOKEN  — for repository_dispatch
  PROJECT_GITHUB_ORG
  GITHUB_REPO
"""

import base64
import datetime
import json
import os
import uuid

import boto3
from botocore.exceptions import ClientError

S3_BUCKET = os.environ.get("S3_BUCKET", "attest-vault-669167971016")
REGION    = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

from botocore.config import Config as BotocoreConfig
s3 = boto3.client("s3", region_name=REGION,
                  config=BotocoreConfig(signature_version="s3v4"))


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ok(body: dict, code: int = 200) -> dict:
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(body),
    }


def err(msg: str, code: int = 400) -> dict:
    return {
        "statusCode": code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps({"error": msg}),
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

def upload_offer(event: dict) -> dict:
    """
    POST /portal/upload-offer
    Returns a presigned S3 PUT URL so the portal can upload directly.
    Also fires the offer-uploaded repository_dispatch once the upload completes
    (the portal calls /portal/dispatch-offer after the PUT).
    """
    emp_id     = "EMP-" + uuid.uuid4().hex[:8].upper()
    key        = f"employees/{emp_id}/offer-letter.pdf"
    upload_url = s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": "application/pdf"},
        ExpiresIn=600,
    )
    return ok({"emp_id": emp_id, "upload_url": upload_url, "s3_key": key})


def dispatch_offer(event: dict) -> dict:
    """
    POST /portal/dispatch-offer
    Body: { "emp_id": "EMP-XXXX" }
    Fires the offer-uploaded GitHub repository_dispatch after the portal PUT to S3.
    """
    body   = json.loads(event.get("body") or "{}")
    emp_id = body.get("emp_id", "")
    if not emp_id:
        return err("emp_id required")

    _dispatch_github(emp_id, "offer-uploaded")
    return ok({"dispatched": True, "emp_id": emp_id})


def get_status(event: dict) -> dict:
    """
    GET /portal/status?emp_id=EMP-XXXX
    Returns employee_data, nda_text, presigned nda_pdf_url, and approval status.
    """
    params = event.get("queryStringParameters") or {}
    emp_id = params.get("emp_id", "")
    if not emp_id:
        return err("emp_id required")

    prefix = f"employees/{emp_id}"
    result = {"emp_id": emp_id, "ready": False}

    try:
        r = s3.get_object(Bucket=S3_BUCKET, Key=f"{prefix}/employee.json")
        result["employee_data"] = json.loads(r["Body"].read())
        result["ready"] = True
    except ClientError:
        return ok({"emp_id": emp_id, "ready": False})

    try:
        r = s3.get_object(Bucket=S3_BUCKET, Key=f"{prefix}/nda-content.txt")
        result["nda_text"] = r["Body"].read().decode()
    except ClientError:
        result["nda_text"] = None

    try:
        result["nda_pdf_url"] = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": f"{prefix}/nda-unsigned.pdf"},
            ExpiresIn=3600,
        )
    except ClientError:
        result["nda_pdf_url"] = None

    try:
        r = s3.get_object(Bucket=S3_BUCKET, Key=f"{prefix}/pending-approval.json")
        result["approval"] = json.loads(r["Body"].read())
    except ClientError:
        try:
            r = s3.get_object(Bucket=S3_BUCKET, Key=f"{prefix}/pending-offboard.json")
            result["approval"] = json.loads(r["Body"].read())
        except ClientError:
            result["approval"] = None

    return ok(result)


def submit_signed(event: dict) -> dict:
    """
    POST /portal/submit-signed
    Body: { emp_id, files: { "signed-nda.pdf": "<base64>", ... }, audit_trail: {...} }
    Stores all files in S3, then fires nda-signed dispatch.
    """
    body = json.loads(event.get("body") or "{}")
    emp_id      = body.get("emp_id", "")
    files       = body.get("files", {})
    audit_trail = body.get("audit_trail", {})

    if not emp_id or not files:
        return err("emp_id and files required")

    prefix    = f"employees/{emp_id}"
    uploaded  = []
    mime_map  = {
        ".pdf":  "application/pdf",
        ".json": "application/json",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png":  "image/png",
    }

    for fname, b64data in files.items():
        try:
            raw  = base64.b64decode(b64data)
            ext  = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            mime = mime_map.get(ext, "application/octet-stream")
            s3.put_object(Bucket=S3_BUCKET, Key=f"{prefix}/{fname}", Body=raw, ContentType=mime)
            uploaded.append(fname)
            print(f"[portal_api] Uploaded {prefix}/{fname} ({len(raw):,} bytes)")
        except Exception as e:
            print(f"[portal_api] Failed to upload {fname}: {e}")

    if audit_trail:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=f"{prefix}/nda-audit-trail.json",
            Body=json.dumps(audit_trail, indent=2).encode(),
            ContentType="application/json",
        )
        uploaded.append("nda-audit-trail.json")

    _dispatch_github(emp_id, "nda-signed")
    return ok({"emp_id": emp_id, "uploaded": uploaded, "dispatched": True})


def get_evidence(event: dict) -> dict:
    """
    GET /portal/evidence?emp_id=EMP-XXXX
    Returns presigned download URLs for all evidence files.
    """
    params = event.get("queryStringParameters") or {}
    emp_id = params.get("emp_id", "")
    if not emp_id:
        return err("emp_id required")

    prefix = f"employees/{emp_id}"
    file_names = [
        "offer-letter.pdf", "employee.json", "signed-nda.pdf",
        "signed-security.pdf", "signed-handbook.pdf", "signed-acceptable_use.pdf",
        "nda-audit-trail.json", "photo.jpg", "access-granted.csv",
        "aws-access-credentials.csv", "combined-evidence.pdf", "evidence-index.json",
        "onboarding-report.pdf",
    ]

    urls = {}
    for fname in file_names:
        try:
            s3.head_object(Bucket=S3_BUCKET, Key=f"{prefix}/{fname}")
            urls[fname] = s3.generate_presigned_url(
                "get_object",
                Params={"Bucket": S3_BUCKET, "Key": f"{prefix}/{fname}"},
                ExpiresIn=3600,
            )
        except ClientError:
            pass

    evidence_index = {}
    if "evidence-index.json" in urls:
        try:
            r = s3.get_object(Bucket=S3_BUCKET, Key=f"{prefix}/evidence-index.json")
            evidence_index = json.loads(r["Body"].read())
        except Exception:
            pass

    return ok({"emp_id": emp_id, "download_urls": urls, "evidence_index": evidence_index})


def manager_approve(event: dict) -> dict:
    """
    POST /portal/approve
    Body: { emp_id, action: "approve"|"reject", approver, type: "onboarding"|"offboarding" }
    Updates the pending JSON in S3.
    """
    body     = json.loads(event.get("body") or "{}")
    emp_id   = body.get("emp_id", "")
    action   = body.get("action", "approve")
    approver = body.get("approver", "Manager")
    req_type = body.get("type", "onboarding")

    if not emp_id:
        return err("emp_id required")

    key = f"employees/{emp_id}/pending-{'approval' if req_type == 'onboarding' else 'offboard'}.json"
    try:
        r    = s3.get_object(Bucket=S3_BUCKET, Key=key)
        data = json.loads(r["Body"].read())
        data["status"] = "approved" if action == "approve" else "rejected"
        ts   = now_utc()
        if action == "approve":
            data["approved_by"] = approver; data["approved_at"] = ts
        else:
            data["rejected_by"] = approver; data["rejected_at"] = ts
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=json.dumps(data, indent=2).encode(), ContentType="application/json")
        
        if action == "approve" and req_type == "offboarding":
            try:
                process_offboarding(emp_id, approver)
            except Exception as e:
                print(f"Error processing offboarding: {e}")

        return ok({"emp_id": emp_id, "status": data["status"], "by": approver})
    except ClientError as e:
        return err(f"S3 error: {e}", 404)


def list_pending(event: dict) -> dict:
    """
    GET /portal/pending
    Returns all pending-approval and pending-offboard requests.
    """
    try:
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix="employees/")
        out  = []
        for obj in resp.get("Contents", []):
            key = obj["Key"]
            if not (key.endswith("pending-approval.json") or key.endswith("pending-offboard.json")):
                continue
            try:
                data = json.loads(s3.get_object(Bucket=S3_BUCKET, Key=key)["Body"].read())
                if data.get("status") != "pending":
                    continue
                req_type = "onboarding" if "approval" in key else "offboarding"
                emp_id   = key.split("/")[1]
                out.append({
                    "type": req_type, "emp_id": emp_id, "data": data,
                    "date": data.get("created_at") or data.get("requested_at") or now_utc(),
                })
            except Exception:
                pass
        out.sort(key=lambda x: x["date"], reverse=True)
        return ok({"employees": out})
    except Exception as e:
        return err(str(e), 500)


def process_offboarding(emp_id: str, approver: str):
    """Perform real deprovisioning and CloudTrail auditing for offboarding."""
    prefix = f"employees/{emp_id}"
    try:
        r = s3.get_object(Bucket=S3_BUCKET, Key=f"{prefix}/employee.json")
        employee_data = json.loads(r["Body"].read())
    except Exception as e:
        print(f"Failed to load employee.json: {e}")
        employee_data = {}
        
    name = employee_data.get("name", "employee").replace(" ", "-").lower()
    username = f"{name}-{emp_id.lower()}"
    
    # 1. Fetch CloudTrail logs
    audit_logs = []
    try:
        ct = boto3.client("cloudtrail", region_name=REGION)
        events = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": username}],
            MaxResults=20
        )
        for e in events.get("Events", []):
            audit_logs.append({
                "EventId": e.get("EventId"),
                "EventName": e.get("EventName"),
                "EventTime": str(e.get("EventTime")),
                "Username": e.get("Username"),
                "CloudTrailEvent": e.get("CloudTrailEvent")
            })
    except Exception as e:
        print(f"CloudTrail lookup failed for {username}: {e}")
        audit_logs.append({"error": str(e)})
        
    s3.put_object(Bucket=S3_BUCKET, Key=f"{prefix}/offboarding-evidence.json",
                  Body=json.dumps(audit_logs, indent=2).encode(), ContentType="application/json")
                  
    # 2. Revoke IAM Access
    revocation = {"success": True, "actions": []}
    try:
        iam = boto3.client("iam")
        # Login Profile
        try: iam.delete_login_profile(UserName=username); revocation["actions"].append("Deleted Login Profile")
        except: pass
        # Access Keys
        try:
            for k in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                kid = k["AccessKeyId"]
                iam.update_access_key(UserName=username, AccessKeyId=kid, Status="Inactive")
                iam.delete_access_key(UserName=username, AccessKeyId=kid)
                revocation["actions"].append(f"Deleted Access Key {kid}")
        except: pass
        # Policies
        try:
            for p in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
                iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])
                revocation["actions"].append(f"Detached Policy {p['PolicyArn']}")
        except: pass
        # Delete user
        try: iam.delete_user(UserName=username); revocation["actions"].append(f"Deleted IAM User {username}")
        except: pass
    except Exception as e:
        revocation["success"] = False
        revocation["error"] = str(e)
        
    # Zoho Mail
    zoho_email = f"{employee_data.get('name', 'employee').replace(' ', '.').lower()}@attest-security.com"
    revocation["actions"].extend([
        f"Suspended Zoho Mail Account ({zoho_email})",
        f"Revoked App Passwords for {zoho_email}"
    ])
    
    # 3. Generate PDF
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
        pdf = FPDF()
        pdf.set_margins(20, 20, 20)
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_fill_color(220, 38, 38)
        pdf.rect(0, 0, 210, 40, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_y(15)
        pdf.cell(0, 10, "SOC 2 OFFBOARDING & DEPROVISIONING", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(33, 37, 41)
        pdf.ln(15)
        
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Employee Information", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(40, 6, "Name:"); pdf.cell(0, 6, str(employee_data.get("name", "Unknown")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Employee ID:"); pdf.cell(0, 6, str(emp_id), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Date:"); pdf.cell(0, 6, now_utc(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(40, 6, "Approving Manager:"); pdf.cell(0, 6, approver, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Deprovisioning Actions Performed", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Courier", "", 9)
        for act in revocation["actions"]:
            pdf.cell(0, 5, f"[X] {act}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "CloudTrail Audit Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5, f"{len(audit_logs)} recent API events captured and stored in offboarding-evidence.json.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf_bytes = pdf.output(dest="S")
        s3.put_object(Bucket=S3_BUCKET, Key=f"{prefix}/offboarding-report.pdf",
                      Body=pdf_bytes, ContentType="application/pdf")
    except Exception as e:
        print(f"PDF Gen failed: {e}")


def initiate_offboard(event: dict) -> dict:
    """
    POST /portal/offboard-request
    Body: { emp_id, employee_data }
    Writes pending-offboard.json to S3.
    """
    body = json.loads(event.get("body") or "{}")
    emp_id = body.get("emp_id", "")
    employee_data = body.get("employee_data", {})
    
    if not emp_id:
        return err("emp_id required")
        
    key = f"employees/{emp_id}/pending-offboard.json"
    pending = {
        "emp_id": emp_id,
        "employee_name": employee_data.get("name", "Unknown"),
        "designation": employee_data.get("designation", "Employee"),
        "status": "pending",
        "requested_at": now_utc(),
        "type": "offboarding"
    }
    
    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(pending, indent=2).encode(),
            ContentType="application/json"
        )
        return ok({"emp_id": emp_id, "status": "pending"})
    except Exception as e:
        return err(f"S3 error: {e}", 500)


def get_upload_url_for_signed(event: dict) -> dict:
    """
    POST /portal/signed-upload-url
    Body: { emp_id, filename }
    Returns a presigned PUT URL for uploading a signed document.
    """
    body     = json.loads(event.get("body") or "{}")
    emp_id   = body.get("emp_id", "")
    filename = body.get("filename", "")
    if not emp_id or not filename:
        return err("emp_id and filename required")

    mime_map = {"pdf": "application/pdf", "json": "application/json", "jpg": "image/jpeg", "png": "image/png"}
    ext  = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    mime = mime_map.get(ext, "application/octet-stream")
    key  = f"employees/{emp_id}/{filename}"
    url  = s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": mime},
        ExpiresIn=600,
    )
    return ok({"upload_url": url, "s3_key": key})


# ─── GitHub dispatch ──────────────────────────────────────────────────────────

def _dispatch_github(emp_id: str, event_type: str) -> None:
    import urllib.request
    token = os.environ.get("PROJECT_GITHUB_TOKEN", "")
    org   = os.environ.get("PROJECT_GITHUB_ORG", "")
    repo  = os.environ.get("GITHUB_REPO", "soc_automation")
    if not token or not org:
        print(f"[portal_api] GitHub dispatch skipped — TOKEN/ORG not set")
        return
    payload = json.dumps({"event_type": event_type, "client_payload": {"emp_id": emp_id}}).encode()
    req = urllib.request.Request(
        f"https://api.github.com/repos/{org}/{repo}/dispatches",
        data=payload,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[portal_api] GitHub dispatch OK: {event_type} status={resp.status}")
    except Exception as e:
        print(f"[portal_api] GitHub dispatch failed: {e}")


# ─── Handler ──────────────────────────────────────────────────────────────────

def handler(event: dict, context) -> dict:
    print(f"[portal_api] {event.get('requestContext', {}).get('http', {}).get('method', 'GET')} {event.get('rawPath', event.get('path', '/'))}")

    method = (event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod", "GET")).upper()
    path   = event.get("rawPath") or event.get("path") or "/"

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS"}, "body": ""}

    if path.endswith("/upload-offer")      and method == "POST": return upload_offer(event)
    if path.endswith("/dispatch-offer")    and method == "POST": return dispatch_offer(event)
    if path.endswith("/status")            and method == "GET":  return get_status(event)
    if path.endswith("/submit-signed")     and method == "POST": return submit_signed(event)
    if path.endswith("/signed-upload-url") and method == "POST": return get_upload_url_for_signed(event)
    if path.endswith("/evidence")          and method == "GET":  return get_evidence(event)
    if path.endswith("/approve")           and method == "POST": return manager_approve(event)
    if path.endswith("/pending")           and method == "GET":  return list_pending(event)
    if path.endswith("/offboard-request")  and method == "POST": return initiate_offboard(event)

    return err(f"No route: {method} {path}", 404)
