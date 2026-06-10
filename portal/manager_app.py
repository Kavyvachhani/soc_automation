"""
portal/manager_app.py — SOC 2 Manager Portal (Port 8002)

Simulates the manager's mailbox and approval dashboard.
Handles both Onboarding and Offboarding approvals.
"""

import datetime
import json
import os
import urllib.request
import urllib.parse
from pathlib import Path

import streamlit as st

# ─── Configuration ────────────────────────────────────────────────────────────

MOCK_MODE: bool = os.getenv("MOCK_MODE", "true").lower() == "true"
BASE_DIR = Path(os.getenv("DATA_DIR", "./data"))
BUCKET_NAME: str = os.getenv("S3_BUCKET", "attest-vault")
API_URL = os.getenv("API_URL", "http://localhost:8501") # Mock API url or lambda

st.set_page_config(
    page_title="Manager Portal — Attest",
    page_icon="📬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Data Access Helpers ──────────────────────────────────────────────────────

def get_pending_requests():
    """Scan local MOCK directory or S3 for pending approvals."""
    requests = []
    
    if MOCK_MODE:
        employees_dir = BASE_DIR / "employees"
        if not employees_dir.exists():
            return requests
            
        for emp_dir in employees_dir.iterdir():
            if emp_dir.is_dir():
                emp_id = emp_dir.name
                
                # Check for Onboarding Approval
                pending_file = emp_dir / "pending-approval.json"
                if pending_file.exists():
                    try:
                        data = json.loads(pending_file.read_text())
                        if data.get("status") == "pending":
                            requests.append({
                                "type": "onboarding",
                                "emp_id": emp_id,
                                "data": data,
                                "date": data.get("created_at", datetime.datetime.now().isoformat())
                            })
                    except Exception:
                        pass
                
                # Check for Offboarding Approval
                offboard_file = emp_dir / "pending-offboard.json"
                if offboard_file.exists():
                    try:
                        data = json.loads(offboard_file.read_text())
                        if data.get("status") == "pending":
                            requests.append({
                                "type": "offboarding",
                                "emp_id": emp_id,
                                "data": data,
                                "date": data.get("requested_at", datetime.datetime.now().isoformat())
                            })
                    except Exception:
                        pass
    else:
        import boto3
        s3 = boto3.client("s3")
        try:
            # Look for pending-approval.json and pending-offboard.json
            resp = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix="employees/")
            if "Contents" in resp:
                for obj in resp["Contents"]:
                    key = obj["Key"]
                    if key.endswith("pending-approval.json") or key.endswith("pending-offboard.json"):
                        try:
                            file_resp = s3.get_object(Bucket=BUCKET_NAME, Key=key)
                            data = json.loads(file_resp["Body"].read())
                            if data.get("status") == "pending":
                                req_type = "onboarding" if "approval" in key else "offboarding"
                                emp_id = key.split("/")[1]
                                requests.append({
                                    "type": req_type,
                                    "emp_id": emp_id,
                                    "data": data,
                                    "date": data.get("created_at") or data.get("requested_at") or datetime.datetime.now().isoformat()
                                })
                        except Exception as e:
                            print(f"Error reading {key}: {e}")
        except Exception as e:
            st.error(f"Failed to fetch S3 data: {e}")
            
    # Sort by date descending
    requests.sort(key=lambda x: x["date"], reverse=True)
    return requests

# ─── Actions ──────────────────────────────────────────────────────────────────

def handle_onboarding(emp_id: str, token: str, action: str):
    """Mock API call to lambda or local logic"""
    if MOCK_MODE:
        # For mock mode, we just update the pending file and let the user process it in the main portal
        emp_dir = BASE_DIR / "employees" / emp_id
        pending_file = emp_dir / "pending-approval.json"
        if pending_file.exists():
            data = json.loads(pending_file.read_text())
            data["status"] = "approved" if action == "approve" else "rejected"
            data["approved_by" if action == "approve" else "rejected_by"] = "Manager"
            data["approved_at" if action == "approve" else "rejected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            pending_file.write_text(json.dumps(data, indent=2))
            st.success(f"Successfully {data['status']} onboarding for {emp_id}")
            return True
    else:
        # In live mode, we hit the lambda endpoint
        api_url = os.environ.get("APPROVAL_API_URL")
        if not api_url:
            st.error("APPROVAL_API_URL not set in live mode.")
            return False
            
        url = f"{api_url}/approve?token={token}&emp_id={emp_id}&action={action}&approver=Manager"
        try:
            with urllib.request.urlopen(url) as response:
                if response.status == 200:
                    st.success(f"Successfully sent {action} to Lambda.")
                    return True
        except Exception as e:
            st.error(f"API Error: {e}")
            return False
    return False

def handle_offboarding(emp_id: str, action: str):
    """Process offboarding approval"""
    if MOCK_MODE:
        emp_dir = BASE_DIR / "employees" / emp_id
        pending_file = emp_dir / "pending-offboard.json"
        if pending_file.exists():
            data = json.loads(pending_file.read_text())
            data["status"] = "approved" if action == "approve" else "rejected"
            data["approved_by" if action == "approve" else "rejected_by"] = "Manager"
            data["approved_at" if action == "approve" else "rejected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            pending_file.write_text(json.dumps(data, indent=2))
            st.success(f"Successfully {data['status']} offboarding for {emp_id}")
            return True
    else:
        # For live mode offboarding, update S3 directly
        import boto3
        s3 = boto3.client("s3")
        try:
            key = f"employees/{emp_id}/pending-offboard.json"
            resp = s3.get_object(Bucket=BUCKET_NAME, Key=key)
            data = json.loads(resp["Body"].read())
            data["status"] = "approved" if action == "approve" else "rejected"
            data["approved_by" if action == "approve" else "rejected_by"] = "Manager"
            data["approved_at" if action == "approve" else "rejected_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=key,
                Body=json.dumps(data, indent=2).encode(),
                ContentType="application/json"
            )
            st.success(f"Successfully {data['status']} offboarding for {emp_id}")
            return True
        except Exception as e:
            st.error(f"S3 Error: {e}")
            return False
    return False

# ─── UI ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
    html, body, [class*="css"], .stMarkdown, .stText, p, span, label {
        font-family: 'Outfit', sans-serif !important;
    }
    .main {
        background-color: #0f172a !important;
        background-image: radial-gradient(circle at top right, rgba(99, 102, 241, 0.15), transparent 400px) !important;
    }
    div.stAlert, div.element-container:has(div.stCard) {
        background: rgba(30, 41, 59, 0.7) !important;
        backdrop-filter: blur(10px) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 12px !important;
    }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("📬 Manager Mailbox")
    st.caption("Review & Approve Access Requests")
    st.divider()
    badge = "🟡 MOCK MODE" if MOCK_MODE else "🟢 LIVE MODE"
    st.info(f"**{badge}**")
    if st.button("🔄 Refresh Mailbox", use_container_width=True):
        st.rerun()

st.title("Pending Approvals")

requests = get_pending_requests()

if not requests:
    st.info("No pending requests to approve at this time. 🎉")
else:
    for req in requests:
        emp_id = req["emp_id"]
        req_type = req["type"]
        data = req["data"]
        
        with st.container():
            st.markdown(f"### {'🚀 Onboarding' if req_type == 'onboarding' else '🛑 Offboarding'} — `{emp_id}`")
            
            col1, col2 = st.columns([3, 1])
            with col1:
                if req_type == "onboarding":
                    st.write(f"**Employee:** {data.get('employee_name', 'Unknown')}")
                    st.write(f"**Designation:** {data.get('designation', 'Unknown')}")
                    st.write(f"**Requested Level:** {data.get('experience_level', 'Unknown').capitalize()}")
                else:
                    st.write(f"**Employee:** {data.get('employee_name', 'Unknown')}")
                    st.write(f"**Revocation Request:** Immediate Wipe & SOC 2 Archival")
                
                st.caption(f"Requested at: {req['date'][:19].replace('T', ' ')}")
            
            with col2:
                if st.button("✅ Approve", key=f"app_{emp_id}_{req_type}", type="primary"):
                    if req_type == "onboarding":
                        if handle_onboarding(emp_id, data.get("token", ""), "approve"):
                            st.rerun()
                    else:
                        if handle_offboarding(emp_id, "approve"):
                            st.rerun()
                            
                if st.button("❌ Reject", key=f"rej_{emp_id}_{req_type}"):
                    if req_type == "onboarding":
                        if handle_onboarding(emp_id, data.get("token", ""), "reject"):
                            st.rerun()
                    else:
                        if handle_offboarding(emp_id, "reject"):
                            st.rerun()
            st.divider()
