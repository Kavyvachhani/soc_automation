"""
portal/manager_app.py — Attest Manager Portal (Port 8502)

Cloud-only approval dashboard for SOC 2 onboarding and offboarding.
Reads pending-approval.json / pending-offboard.json from S3.

Run:
  streamlit run portal/manager_app.py --server.port 8502
"""

import datetime
import json
import os
import urllib.request
from pathlib import Path

import streamlit as st

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env", override=False)
except ImportError:
    pass

BUCKET_NAME:    str = os.getenv("S3_BUCKET", "attest-vault-669167971016")
PORTAL_API_URL: str = os.getenv("PORTAL_API_URL", "").rstrip("/")

st.set_page_config(
    page_title="Manager Portal — Attest",
    page_icon="📬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════════
# CSS
# ═══════════════════════════════════════════════════════════════════════════════

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html, body, [class*="css"], .stMarkdown, p, span, label, div {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"],
[data-testid="stStatusWidget"] { display: none !important; }

[data-testid="stAppViewContainer"], [data-testid="stMain"], .main .block-container {
    background-color: #0d0f17 !important;
}
[data-testid="stAppViewContainer"] {
    background-image: radial-gradient(ellipse 60% 40% at 85% 0%, rgba(99,102,241,0.15) 0%, transparent 60%) !important;
}
.block-container { padding-top: 2.5rem !important; max-width: 900px !important; }
[data-testid="stSidebar"] {
    background: #080a10 !important;
    border-right: 1px solid rgba(255,255,255,0.06) !important;
}
[data-testid="stSidebar"] * { color: #c9cfe0 !important; }
h1, h2, h3, h4 { color: #f0f2ff !important; font-weight: 700 !important; letter-spacing: -0.02em !important; }
p, .stMarkdown p { color: #a8b0c8 !important; }
.stMarkdown strong { color: #e2e5f0 !important; }
[data-testid="stAlert"] { border-radius: 10px !important; border-width: 1px !important; }
[data-testid="stVerticalBlockBorderWrapper"] {
    background: rgba(17,19,31,0.85) !important;
    border: 1px solid rgba(255,255,255,0.09) !important;
    border-radius: 14px !important;
}
.stButton > button {
    background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%) !important;
    color: #fff !important; border: none !important; border-radius: 9px !important;
    font-weight: 600 !important; font-size: 0.88rem !important;
    box-shadow: 0 4px 14px rgba(79,70,229,0.35) !important;
    transition: all 0.2s ease !important;
}
.stButton > button:hover { transform: translateY(-2px) !important; box-shadow: 0 6px 20px rgba(79,70,229,0.5) !important; }
hr { border-color: rgba(255,255,255,0.07) !important; }
[data-testid="stMetric"] { background: rgba(15,17,28,0.9) !important; border: 1px solid rgba(255,255,255,0.08) !important; border-radius:10px !important; padding:14px 16px !important; }
[data-testid="stMetricLabel"] { color: #8b92a8 !important; font-size: 0.76rem !important; text-transform:uppercase; letter-spacing:0.05em; }
[data-testid="stMetricValue"] { color: #f0f2ff !important; font-size: 1.05rem !important; font-weight:600 !important; }
</style>
"""

st.markdown(_CSS, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# AWS helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _s3():
    import boto3
    return boto3.client("s3", region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))


def _check_creds() -> bool:
    try:
        import boto3
        creds = boto3.Session().get_credentials()
        if creds is None:
            return False
        creds.get_frozen_credentials()
        return True
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Data access
# ═══════════════════════════════════════════════════════════════════════════════

def get_pending_requests() -> list[dict]:
    # Prefer portal API (no local creds)
    if PORTAL_API_URL:
        try:
            r = _portal_api("GET", "/portal/pending")
            return r.get("requests", [])
        except Exception as e:
            st.warning(f"Portal API unavailable, trying direct S3: {e}")

    from botocore.exceptions import NoCredentialsError, ClientError
    try:
        s3   = _s3()
        resp = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix="employees/")
        if "Contents" not in resp:
            return []
        out = []
        for obj in resp["Contents"]:
            key = obj["Key"]
            if not (key.endswith("pending-approval.json") or key.endswith("pending-offboard.json")):
                continue
            try:
                data = json.loads(s3.get_object(Bucket=BUCKET_NAME, Key=key)["Body"].read())
                if data.get("status") != "pending":
                    continue
                req_type = "onboarding" if "approval" in key else "offboarding"
                emp_id   = key.split("/")[1]
                out.append({
                    "type":   req_type,
                    "emp_id": emp_id,
                    "data":   data,
                    "date":   data.get("created_at") or data.get("requested_at") or datetime.datetime.now().isoformat(),
                })
            except Exception as e:
                print(f"[manager] skip {key}: {e}")
        out.sort(key=lambda x: x["date"], reverse=True)
        return out
    except NoCredentialsError:
        st.warning(
            "**AWS credentials not configured.**  \n"
            "Add your keys to a `.env` file in the project root and restart.  \n"
            "`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`"
        )
        return []
    except ClientError as e:
        st.error(f"AWS error: {e.response['Error']['Message']}")
        return []
    except Exception as e:
        st.error(f"S3 connection failed: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# Approval actions
# ═══════════════════════════════════════════════════════════════════════════════

def _manager_name() -> str:
    return os.getenv("MANAGER_NAME", "Manager")


def _portal_api(method: str, path: str, body: dict | None = None) -> dict:
    """Call portal API Lambda — no local AWS credentials needed."""
    import urllib.request, urllib.error
    url  = f"{PORTAL_API_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"API {method} {path} → {e.code}: {e.read().decode(errors='replace')[:200]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"API unreachable: {e.reason}")


def handle_onboarding(emp_id: str, token: str, action: str) -> bool:
    # Try portal API first (no local creds needed)
    if PORTAL_API_URL:
        try:
            r = _portal_api("POST", "/portal/approve", {"emp_id": emp_id, "action": action, "approver": _manager_name(), "type": "onboarding"})
            st.success(f"✅ Onboarding **{action}d** for `{emp_id}`.")
            return True
        except Exception as e:
            st.warning(f"Portal API failed, falling back to direct S3: {e}")

    api_url = os.environ.get("APPROVAL_API_URL", "").rstrip("/")
    if api_url:
        url = f"{api_url}/approve?token={token}&emp_id={emp_id}&action={action}&approver={_manager_name()}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                if resp.status == 200:
                    st.success(f"✅ Sent **{action}** to Lambda for `{emp_id}`.")
                    return True
        except Exception as e:
            st.error(f"Lambda API error: {e}")
            return False

    # Fallback: write directly to S3
    try:
        s3  = _s3()
        key = f"employees/{emp_id}/pending-approval.json"
        data = json.loads(s3.get_object(Bucket=BUCKET_NAME, Key=key)["Body"].read())
        now  = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data["status"] = "approved" if action == "approve" else "rejected"
        if action == "approve":
            data["approved_by"] = _manager_name(); data["approved_at"] = now
        else:
            data["rejected_by"] = _manager_name(); data["rejected_at"] = now
        s3.put_object(Bucket=BUCKET_NAME, Key=key, Body=json.dumps(data, indent=2).encode(), ContentType="application/json")
        st.success(f"✅ Onboarding **{action}d** for `{emp_id}`.")
        return True
    except Exception as e:
        st.error(f"S3 error: {e}")
        return False


def handle_offboarding(emp_id: str, action: str) -> bool:
    if PORTAL_API_URL:
        try:
            _portal_api("POST", "/portal/approve", {"emp_id": emp_id, "action": action, "approver": _manager_name(), "type": "offboarding"})
            st.success(f"✅ Offboarding **{action}d** for `{emp_id}`.")
            return True
        except Exception as e:
            st.warning(f"Portal API failed, falling back to direct S3: {e}")
    try:
        s3  = _s3()
        key = f"employees/{emp_id}/pending-offboard.json"
        data = json.loads(s3.get_object(Bucket=BUCKET_NAME, Key=key)["Body"].read())
        now  = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data["status"] = "approved" if action == "approve" else "rejected"
        if action == "approve":
            data["approved_by"] = _manager_name(); data["approved_at"] = now
        else:
            data["rejected_by"] = _manager_name(); data["rejected_at"] = now
        s3.put_object(Bucket=BUCKET_NAME, Key=key, Body=json.dumps(data, indent=2).encode(), ContentType="application/json")
        st.success(f"✅ Offboarding **{action}d** for `{emp_id}`.")
        return True
    except Exception as e:
        st.error(f"S3 error: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Sidebar
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown(
        '<div style="padding:10px 0 6px;display:flex;align-items:center;gap:10px;">'
        '<span style="font-size:1.7rem;">📬</span>'
        '<div><div style="font-size:1.15rem;font-weight:700;color:#f0f2ff;">Manager Portal</div>'
        '<div style="font-size:0.72rem;color:#4a5170;margin-top:1px;">Access Request Approvals</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.divider()
    st.markdown(
        '<div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.22);'
        'border-radius:8px;padding:10px 12px;">'
        '<div style="color:#60a5fa;font-weight:600;font-size:0.82rem;">☁️ AWS Cloud Mode</div>'
        '<div style="color:#4a5170;font-size:0.76rem;margin-top:2px;">S3 · Lambda · GitHub Actions</div>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.divider()
    if st.button("🔄 Refresh Mailbox", use_container_width=True):
        st.rerun()
    st.divider()

    # Credential status
    if _check_creds():
        st.markdown(
            '<div style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.22);'
            'border-radius:8px;padding:8px 12px;">'
            '<div style="color:#4ade80;font-size:0.8rem;font-weight:600;">✓ AWS Connected</div>'
            '<div style="color:#4a5170;font-size:0.72rem;margin-top:2px;">Bucket: attest-vault-…</div>'
            '</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);'
            'border-radius:8px;padding:8px 12px;">'
            '<div style="color:#f87171;font-size:0.8rem;font-weight:600;">⚠ No AWS Credentials</div>'
            '<div style="color:#4a5170;font-size:0.72rem;margin-top:2px;">Add .env and restart</div>'
            '</div>',
            unsafe_allow_html=True,
        )

# ═══════════════════════════════════════════════════════════════════════════════
# Main header
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown(
    '<div style="display:flex;align-items:center;gap:14px;margin-bottom:1.5rem;padding-bottom:1rem;'
    'border-bottom:1px solid rgba(255,255,255,0.07);">'
    '<div style="display:flex;align-items:center;justify-content:center;width:44px;height:44px;'
    'border-radius:50%;background:linear-gradient(135deg,#4f46e5,#3b82f6);font-size:18px;'
    'box-shadow:0 0 18px rgba(79,70,229,0.5);">📋</div>'
    '<div><div style="color:#f0f2ff;font-size:1.5rem;font-weight:700;line-height:1.2;">Pending Approvals</div>'
    '<div style="color:#8b92a8;font-size:0.85rem;margin-top:2px;">Review and act on access requests</div>'
    '</div></div>',
    unsafe_allow_html=True,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Request list
# ═══════════════════════════════════════════════════════════════════════════════

requests = get_pending_requests()

if not requests:
    st.markdown(
        '<div style="text-align:center;padding:70px 20px;">'
        '<div style="font-size:3.5rem;margin-bottom:16px;">🎉</div>'
        '<div style="color:#f0f2ff;font-size:1.15rem;font-weight:600;">All clear!</div>'
        '<div style="color:#5a6380;font-size:0.9rem;margin-top:6px;">No pending access requests to approve.</div>'
        '</div>',
        unsafe_allow_html=True,
    )
else:
    pending_ob  = sum(1 for r in requests if r["type"] == "onboarding")
    pending_off = sum(1 for r in requests if r["type"] == "offboarding")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Pending",   len(requests))
    c2.metric("Onboarding",      pending_ob)
    c3.metric("Offboarding",     pending_off)
    st.divider()

    for req in requests:
        emp_id       = req["emp_id"]
        req_type     = req["type"]
        data         = req["data"]
        is_onboarding = req_type == "onboarding"

        with st.container(border=True):
            tag_color  = "#4ade80" if is_onboarding else "#f87171"
            tag_bg     = "rgba(74,222,128,0.08)"  if is_onboarding else "rgba(248,113,113,0.08)"
            tag_border = "rgba(74,222,128,0.25)"  if is_onboarding else "rgba(248,113,113,0.25)"
            tag_label  = "🚀 Onboarding"          if is_onboarding else "🛑 Offboarding"

            st.markdown(
                f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">'
                f'<span style="background:{tag_bg};border:1px solid {tag_border};color:{tag_color};'
                f'font-size:0.78rem;font-weight:700;padding:3px 10px;border-radius:20px;">{tag_label}</span>'
                f'<span style="color:#a5b4fc;font-family:monospace;font-size:0.9rem;font-weight:600;">{emp_id}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

            col_info, col_act = st.columns([3, 1])

            with col_info:
                emp_name = data.get("employee_name", "Unknown")
                role     = data.get("designation", data.get("experience_level", "—"))
                req_time = req["date"][:19].replace("T", " ") + " UTC"
                policies = data.get("policies_signed", [])

                info_items = [
                    ("Employee",    emp_name),
                    ("Role",        role if is_onboarding else "Full Access Wipe"),
                    ("Requested",   req_time),
                ]
                if policies and is_onboarding:
                    info_items.append(("Docs Signed", ", ".join(policies)))

                rows_html = "".join(
                    f'<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(255,255,255,0.04);">'
                    f'<div style="color:#5a6380;font-size:0.75rem;text-transform:uppercase;letter-spacing:0.06em;width:80px;flex-shrink:0;padding-top:1px;">{lbl}</div>'
                    f'<div style="color:#e2e5f0;font-size:0.88rem;font-weight:500;">{val}</div>'
                    f'</div>'
                    for lbl, val in info_items
                )
                st.markdown(
                    f'<div style="background:rgba(15,17,28,0.7);border:1px solid rgba(255,255,255,0.06);'
                    f'border-radius:8px;padding:12px 14px;">{rows_html}</div>',
                    unsafe_allow_html=True,
                )

            with col_act:
                st.markdown('<div style="height:10px;"></div>', unsafe_allow_html=True)
                approve_key = f"app_{emp_id}_{req_type}"
                reject_key  = f"rej_{emp_id}_{req_type}"

                if st.button("✅ Approve", key=approve_key, type="primary", use_container_width=True):
                    ok = handle_onboarding(emp_id, data.get("token", ""), "approve") if is_onboarding else handle_offboarding(emp_id, "approve")
                    if ok: st.rerun()

                st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)
                if st.button("❌ Reject", key=reject_key, use_container_width=True):
                    ok = handle_onboarding(emp_id, data.get("token", ""), "reject") if is_onboarding else handle_offboarding(emp_id, "reject")
                    if ok: st.rerun()

            # Evidence download links for completed onboarding
            if is_onboarding and data.get("status") == "approved":
                st.divider()
                st.markdown('<div style="color:#8b92a8;font-size:0.8rem;margin-bottom:6px;">Evidence in vault:</div>', unsafe_allow_html=True)
                dl_cols = st.columns(3)
                for i, fname in enumerate(["signed-nda.pdf", "nda-audit-trail.json", "combined-evidence.pdf"]):
                    try:
                        obj = _s3().get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/{fname}")
                        with dl_cols[i % 3]:
                            st.download_button(f"📄 {fname}", obj["Body"].read(), file_name=fname, use_container_width=True)
                    except Exception:
                        pass

# ═══════════════════════════════════════════════════════════════════════════════
# Footer
# ═══════════════════════════════════════════════════════════════════════════════

st.divider()
st.markdown(
    '<div style="text-align:center;color:#3d4460;font-size:0.75rem;">'
    'Attest Manager Portal · SOC 2 Compliance · All actions are logged and immutable in S3'
    '</div>',
    unsafe_allow_html=True,
)
