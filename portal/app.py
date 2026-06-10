"""
portal/app.py — Attest SOC 2 Onboarding Portal
Streamlit application that drives the full employee onboarding evidence pipeline.

MOCK_MODE=true  → everything runs locally; no cloud needed; approval is an "Approve" button.
MOCK_MODE=false → uses real S3 + Lambda + GitHub Actions; approval comes from GitHub env.

Run:
  MOCK_MODE=true streamlit run portal/app.py
"""

import datetime
import hashlib
import io
import json
import os
import re
import sys
import uuid
from pathlib import Path

import streamlit as st
import yaml

# ─── Configuration ────────────────────────────────────────────────────────────

MOCK_MODE: bool = os.getenv("MOCK_MODE", "true").lower() == "true"
BASE_DIR = Path(os.getenv("DATA_DIR", "./data"))
REPO_ROOT = Path(__file__).parent.parent
POLICIES_DIR = Path(os.getenv("POLICIES_DIR", str(REPO_ROOT / "policies")))
CATALOG_FILE = Path(os.getenv("CATALOG_FILE", str(REPO_ROOT / "catalog.yaml")))
BUCKET_NAME: str = os.getenv("S3_BUCKET", "attest-vault")

BASE_DIR.mkdir(parents=True, exist_ok=True)

# ─── Page config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Attest — SOC 2 Onboarding",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Session state bootstrap ──────────────────────────────────────────────────

_DEFAULTS = {
    "flow": "onboarding",
    "step": "upload",
    "emp_id": None,
    "employee_data": None,
    "nda_text": None,
    "nda_pdf_path": None,
    "signed_nda_path": None,
    "audit_trail": None,
    "evidence": None,
    # Policy acknowledgement tracking
    "policy_sigs": {},          # {policy_id: {"signed_at": ..., "sig_name": ...}}
    "policy_signed_paths": {},  # {policy_id: local path}
    # Live-mode upload state
    "_waiting_for_lambda": False,
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline helpers (used by both MOCK_MODE inline and accessible by Lambda)
# ═══════════════════════════════════════════════════════════════════════════════

def _safe(s: str) -> str:
    """Encode string to latin-1 safely for fpdf core fonts.
    Replaces common unicode punctuation with ASCII equivalents before encoding.
    """
    replacements = {
        '\u2019': "'",    # right single quotation mark
        '\u2018': "'",    # left single quotation mark
        '\u201c': '"',    # left double quotation mark
        '\u201d': '"',    # right double quotation mark
        '\u2013': '-',    # en dash
        '\u2014': '--',   # em dash
        '\u2022': '*',    # bullet
        '\u2026': '...',  # ellipsis
        '\u00a0': ' ',    # non-breaking space
    }
    s = str(s)
    for orig, repl in replacements.items():
        s = s.replace(orig, repl)
    return s.encode("latin-1", errors="replace").decode("latin-1")


def get_emp_dir(emp_id: str) -> Path:
    d = BASE_DIR / "employees" / emp_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_approval_api_url() -> str:
    try:
        import boto3
        apigw = boto3.client("apigatewayv2", region_name="us-east-1")
        apis = apigw.get_apis()
        for api in apis.get("Items", []):
            if api.get("Name") == "attest-approval-api":
                return api.get("ApiEndpoint")
    except Exception:
        pass
    return ""


def dispatch_to_github(emp_id: str, event_type: str) -> None:
    import urllib.request
    import urllib.error
    github_token = os.environ.get("PROJECT_GITHUB_TOKEN", "")
    github_org = os.environ.get("PROJECT_GITHUB_ORG", "")
    github_repo = os.environ.get("GITHUB_REPO", "soc_automation")

    if not github_token or not github_org:
        print(f"[dispatch] PROJECT_GITHUB_TOKEN or PROJECT_GITHUB_ORG not set; skipping dispatch for {event_type}")
        return

    url = f"https://api.github.com/repos/{github_org}/{github_repo}/dispatches"
    payload = json.dumps({
        "event_type": event_type,
        "client_payload": {"emp_id": emp_id}
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {github_token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[dispatch] GitHub dispatch OK: status={resp.status} event_type={event_type}")
    except Exception as exc:
        print(f"[dispatch] GitHub dispatch failed: {exc}")


# ── PDF text extraction ────────────────────────────────────────────────────────

def extract_pdf_text(pdf_bytes: bytes) -> str:
    import pypdf
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# ── Employee data extraction — AI path ────────────────────────────────────────

def _extract_ai(text: str) -> dict | None:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        prompt = (
            "Extract employee onboarding data from this offer letter.\n"
            "Return ONLY a valid JSON object with exactly these fields:\n"
            '  "name": full employee name (string)\n'
            '  "designation": job title (string)\n'
            '  "team": team or department name (string)\n'
            '  "employment_type": "full-time", "part-time", or "contract" (string)\n'
            '  "experience_level": "fresher" (0-2 yrs) or "experienced" (2+ yrs) (string)\n'
            '  "start_date": ISO-8601 YYYY-MM-DD (string)\n'
            '  "confidence": float 0.0-1.0\n\n'
            f"Offer letter text:\n{text[:3500]}"
        )
        msg = client.messages.create(
            model="claude-3-5-sonnet-latest",
            max_tokens=512,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = msg.content[0].text.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```[^\n]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        return json.loads(raw)
    except Exception as exc:
        print(f"[portal] AI extraction failed: {exc}")
        return None


def _extract_regex(text: str) -> dict:
    data: dict = {
        "name": "Unknown Employee",
        "designation": "Employee",
        "team": "Engineering",
        "employment_type": "full-time",
        "experience_level": "fresher",
        "start_date": datetime.date.today().isoformat(),
        "confidence": 0.4,
    }
    for pat in [
        r"Dear\s+([A-Z][a-zA-Z]*(?:\s+[A-Z][a-zA-Z]*)*)",
        r"offer\s+to\s+([A-Z][a-zA-Z]*(?:\s+[A-Z][a-zA-Z]*)*)",
    ]:
        m = re.search(pat, text)
        if m:
            data["name"] = m.group(1).strip()
            break
    for pat in [
        r"position\s+of\s+([\w\s]+?)(?:\s+in\s+|\s+at\s+|,|\n|\.)",
        r"role\s+of\s+([\w\s]+?)(?:\s+in\s+|\s+at\s+|,|\n|\.)",
        r"joining\s+as\s+(?:a\s+|an\s+)?([\w\s]+?)(?:,|\s+in\s+|\s+at\s+|\n|\.)",
        r"[Pp]osition[:\s]+([\w\s]+?)(?:,|\n|\.)",
        r"[Dd]esignation[:\s]+([\w\s]+?)(?:,|\n|\.)",
    ]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            c = m.group(1).strip()
            if 2 < len(c) < 60:
                data["designation"] = c
                break
    for pat in [
        r"[Tt]eam[:\s]+([\w\s]+?)(?:,|\n|\.)",
        r"([\w]+)\s+[Tt]eam",
        r"[Dd]epartment[:\s]+([\w\s]+?)(?:,|\n|\.)",
    ]:
        m = re.search(pat, text)
        if m:
            data["team"] = m.group(1).strip()
            break
    for pat in [
        r"[Ss]tart\s+[Dd]ate[:\s]+(\d{4}-\d{2}-\d{2})",
        r"effective\s+([A-Za-z]+\s+\d{1,2},?\s*\d{4})",
        r"commencing\s+(?:on\s+)?([A-Za-z]+\s+\d{1,2},?\s*\d{4})",
        r"joining\s+(?:on\s+)?([A-Za-z]+\s+\d{1,2},?\s*\d{4})",
        r"[Ss]tart\s+[Dd]ate[:\s]+([A-Za-z]+\s+\d{1,2},?\s*\d{4})",
        r"(\d{4}-\d{2}-\d{2})",
    ]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
            try:
                from dateutil.parser import parse as dtparse
                data["start_date"] = dtparse(raw).strftime("%Y-%m-%d")
            except Exception:
                data["start_date"] = raw
            break
    senior_kws = {"senior", "lead", "principal", "staff", "director", "manager", "vp", "head"}
    if any(kw in data["designation"].lower() for kw in senior_kws):
        data["experience_level"] = "experienced"
    m2 = re.search(r"(\d+)\s+years?\s+(?:of\s+)?(?:industry\s+)?experience", text, re.IGNORECASE)
    if m2 and int(m2.group(1)) >= 2:
        data["experience_level"] = "experienced"
    return data


def extract_employee_data(text: str) -> dict:
    data = _extract_ai(text) or _extract_regex(text)
    defaults = {
        "name": "Unknown Employee",
        "designation": "Employee",
        "team": "Engineering",
        "employment_type": "full-time",
        "experience_level": "fresher",
        "start_date": datetime.date.today().isoformat(),
        "confidence": 0.5,
    }
    for k, v in defaults.items():
        data.setdefault(k, v)
    return data


# ── NDA template filling ───────────────────────────────────────────────────────

def fill_nda_template(employee_data: dict, emp_id: str) -> str:
    template_path = POLICIES_DIR / "nda_template.txt"
    if not template_path.exists():
        template_path = REPO_ROOT / "policies" / "nda_template.txt"
    if not template_path.exists():
        return f"NDA template not found. Please ensure policies/nda_template.txt exists.\n\nEmployee: {employee_data.get('name')} | ID: {emp_id}"

    template = template_path.read_text()
    replacements = {
        "{{name}}": employee_data.get("name", "Employee"),
        "{{designation}}": employee_data.get("designation", "Employee"),
        "{{team}}": employee_data.get("team", "Engineering"),
        "{{start_date}}": employee_data.get("start_date", "TBD"),
        "{{emp_id}}": emp_id,
        "{{date}}": datetime.date.today().strftime("%B %d, %Y"),
    }
    for k, v in replacements.items():
        template = template.replace(k, str(v))
    return template


# ── PDF rendering ──────────────────────────────────────────────────────────────

def render_nda_pdf(nda_text: str, output_path: Path) -> None:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 12, text=_safe("NON-DISCLOSURE AGREEMENT"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    pdf.set_font("Helvetica", size=10)

    for line in nda_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 9, text=_safe(stripped[3:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=10)
        elif stripped == "":
            pdf.ln(3)
        else:
            pdf.multi_cell(0, 6, text=_safe(line), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(str(output_path))


def render_signed_nda_pdf(
    nda_text: str,
    signature_name: str,
    audit_trail: dict,
    output_path: Path,
) -> None:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 12, text=_safe("NON-DISCLOSURE AGREEMENT"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 7, text=_safe("[ELECTRONICALLY SIGNED COPY]"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)
    pdf.set_font("Helvetica", size=10)

    for line in nda_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 9, text=_safe(stripped[3:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=10)
        elif stripped == "":
            pdf.ln(3)
        else:
            pdf.multi_cell(0, 6, text=_safe(line), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Signature block
    pdf.ln(8)
    pdf.set_line_width(0.5)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 9, text=_safe("ELECTRONIC SIGNATURE RECORD"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Courier", size=9)

    sig_rows = [
        ("Signer Name",             audit_trail.get("signer_name", "")),
        ("Timestamp (UTC)",         audit_trail.get("timestamp_utc", "")),
        ("IP Address",              audit_trail.get("source_ip", "")),
        ("User Agent",              audit_trail.get("user_agent", "")),
        ("Consent Given",           str(audit_trail.get("consent", False))),
        ("Signature Method",        audit_trail.get("signature_method", "typed-name")),
        ("Doc Hash (pre-sign)",     (audit_trail.get("document_hash_before") or "")[:64]),
        ("Doc Hash (post-sign)",    (audit_trail.get("document_hash_after") or "")[:64]),
    ]
    for label, value in sig_rows:
        pdf.cell(55, 7, text=_safe(f"{label}:"))
        pdf.multi_cell(0, 7, text=_safe(str(value)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(str(output_path))


# ── Mock provisioning (inline) ─────────────────────────────────────────────────

def run_provisioning(emp_id: str, approver: str = "mock-tech-lead") -> dict:
    import csv

    # Import the provision logic from scripts/
    scripts_dir = REPO_ROOT / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    from provision import provision
    return provision(emp_id, approver, BASE_DIR)


# ─── Process offer letter (MOCK_MODE) ─────────────────────────────────────────

def process_offer_letter_mock(pdf_bytes: bytes, emp_id: str) -> tuple[dict, str, Path]:
    d = get_emp_dir(emp_id)

    # 1. Save raw offer letter
    (d / "offer-letter.pdf").write_bytes(pdf_bytes)

    # 2. Extract text and employee data
    text = extract_pdf_text(pdf_bytes)
    employee_data = extract_employee_data(text)
    employee_data.update({
        "emp_id": emp_id,
        "source_file": "offer-letter.pdf",
        "extracted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    (d / "employee.json").write_text(json.dumps(employee_data, indent=2))

    # 3. Fill NDA template
    nda_text = fill_nda_template(employee_data, emp_id)
    (d / "nda-content.txt").write_text(nda_text)

    # 4. Render unsigned NDA PDF
    nda_pdf_path = d / "nda-unsigned.pdf"
    render_nda_pdf(nda_text, nda_pdf_path)

    return employee_data, nda_text, nda_pdf_path


# ─── Process signing (MOCK_MODE) ──────────────────────────────────────────────

def get_client_ip() -> str:
    try:
        headers = st.context.headers
        return headers.get(
            "X-Forwarded-For",
            headers.get("X-Real-Ip", "127.0.0.1"),
        )
    except Exception:
        return "127.0.0.1"


def process_signing_mock(
    emp_id: str,
    nda_text: str,
    nda_pdf_path: Path,
    signature_name: str,
) -> tuple[dict, Path]:
    d = get_emp_dir(emp_id)

    hash_before = sha256_file(nda_pdf_path)

    audit_trail = {
        "emp_id": emp_id,
        "signer_name": signature_name,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_ip": get_client_ip(),
        "user_agent": "Attest-Streamlit-Portal/1.0",
        "consent": True,
        "signature_method": "typed-name",
        "document_hash_before": hash_before,
        "document_hash_after": None,
    }

    signed_path = d / "signed-nda.pdf"
    render_signed_nda_pdf(nda_text, signature_name, audit_trail, signed_path)
    audit_trail["document_hash_after"] = sha256_file(signed_path)

    (d / "nda-audit-trail.json").write_text(json.dumps(audit_trail, indent=2))

    return audit_trail, signed_path


# ═══════════════════════════════════════════════════════════════════════════════
# UI — Sidebar
# ═══════════════════════════════════════════════════════════════════════════════

def render_sidebar() -> None:
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
        
        /* Apply Outfit Font globally */
        html, body, [class*="css"], .stMarkdown, .stText, p, span, label {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }
        
        /* Main background */
        .main {
            background-color: #0a0b10 !important;
            background-image: 
                radial-gradient(circle at 80% 10%, rgba(99, 102, 241, 0.12) 0%, transparent 50%),
                radial-gradient(circle at 10% 90%, rgba(59, 130, 246, 0.08) 0%, transparent 50%) !important;
        }
        
        /* Sidebar styling */
        [data-testid="stSidebar"] {
            background-color: #0f1016 !important;
            border-right: 1px solid rgba(255, 255, 255, 0.05) !important;
        }
        
        /* Glassmorphism Cards */
        div.stAlert, div.element-container:has(div.stCard), .stDeployInfo {
            background: rgba(20, 22, 34, 0.6) !important;
            backdrop-filter: blur(12px) !important;
            -webkit-backdrop-filter: blur(12px) !important;
            border: 1px solid rgba(255, 255, 255, 0.07) !important;
            border-radius: 14px !important;
            padding: 18px !important;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2) !important;
            margin-bottom: 15px !important;
        }
        
        /* Custom buttons styling */
        .stButton>button {
            background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%) !important;
            color: #ffffff !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 8px 20px !important;
            font-weight: 600 !important;
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3) !important;
            transition: all 0.25s ease !important;
        }
        .stButton>button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(79, 70, 229, 0.5) !important;
            background: linear-gradient(135deg, #4338ca 0%, #2563eb 100%) !important;
            color: #ffffff !important;
        }
        .stButton>button:active {
            transform: translateY(0) !important;
        }
        
        /* Headings customization */
        h1, h2, h3, h4, h5, h6 {
            color: #ffffff !important;
            font-weight: 700 !important;
            letter-spacing: -0.02em !important;
        }
        
        /* Badge decoration styling */
        .custom-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 12px;
            margin-bottom: 10px;
            border: 1px solid;
        }
        .badge-fresher {
            background: rgba(56, 189, 248, 0.1) !important;
            color: #38bdf8 !important;
            border-color: rgba(56, 189, 248, 0.2) !important;
        }
        .badge-experienced {
            background: rgba(168, 85, 247, 0.1) !important;
            color: #a855f7 !important;
            border-color: rgba(168, 85, 247, 0.2) !important;
        }
    </style>
    """, unsafe_allow_html=True)

    with st.sidebar:
        st.title("🛡️ Attest")
        st.caption("SOC 2 Onboarding Evidence Platform")
        st.divider()

        flow = st.radio("Workflow", ["Onboarding", "Offboarding"], index=0 if st.session_state.flow == "onboarding" else 1)
        if flow.lower() != st.session_state.flow:
            for k in list(st.session_state.keys()):
                if k != "flow": del st.session_state[k]
            st.session_state.flow = flow.lower()
            st.session_state.step = "upload" if flow == "Onboarding" else "offboard_init"
            st.rerun()

        if st.session_state.flow == "onboarding":
            steps = [
                ("upload",  "Upload Offer Letter"),
                ("sign",    "Sign NDA & Policies"),
                ("approve", "Tech Lead Approval"),
                ("done",    "Evidence Collected"),
            ]
        else:
            steps = [
                ("offboard_init", "Initiate Offboarding"),
                ("offboard_audit", "Audit & Backup"),
                ("offboard_approve", "Manager Verification"),
                ("offboard_done", "Access Revoked"),
            ]
            
        current = st.session_state.step

        for key, label in steps:
            step_keys = [s[0] for s in steps]
            idx_current = step_keys.index(current) if current in step_keys else 0
            idx_this = step_keys.index(key)
            if idx_this < idx_current:
                st.markdown(f"✅ {label}")
            elif idx_this == idx_current:
                st.markdown(f"**▶ {label}**")
            else:
                st.markdown(f"◻ {label}")

        st.divider()
        badge = "🟡 MOCK MODE" if MOCK_MODE else "🟢 LIVE MODE"
        detail = "Local filesystem · no cloud required" if MOCK_MODE else "S3 · Lambda · GitHub Actions"
        st.info(f"**{badge}**\n\n{detail}")

        if st.session_state.emp_id:
            st.caption(f"Employee ID\n`{st.session_state.emp_id}`")

        st.divider()
        if st.button("↩ Reset / New Employee", use_container_width=True):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# UI — Step 1: Upload
# ═══════════════════════════════════════════════════════════════════════════════

def step_upload() -> None:
    st.header("Step 1 — Upload Offer Letter")
    st.write(
        "Upload the employee's signed offer letter (PDF). "
        "The system will extract their data and auto-generate a personalised NDA."
    )

    # ── Live mode: show check-status widget if waiting for Lambda ─────────────
    if not MOCK_MODE and st.session_state.get("_waiting_for_lambda") and st.session_state.emp_id:
        emp_id = st.session_state.emp_id
        st.info(
            f"⏳ Processing offer letter for `{emp_id}` …\n\n"
            "The Lambda function is extracting employee data and generating the NDA. "
            "This usually takes 20–40 seconds."
        )
        if st.button("🔄 Check Status", type="primary"):
            try:
                import boto3
                s3 = boto3.client("s3")
                r = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/employee.json")
                data = json.loads(r["Body"].read())
                r2 = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/nda-content.txt")
                nda_text = r2["Body"].read().decode()
                tmp = Path(f"/tmp/{emp_id}")
                tmp.mkdir(exist_ok=True)
                r3 = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/nda-unsigned.pdf")
                nda_pdf_path = tmp / "nda-unsigned.pdf"
                nda_pdf_path.write_bytes(r3["Body"].read())

                st.session_state.employee_data = data
                st.session_state.nda_text = nda_text
                st.session_state.nda_pdf_path = str(nda_pdf_path)
                st.session_state._waiting_for_lambda = False
                st.session_state.step = "sign"
                st.rerun()
            except Exception:
                st.warning("Not ready yet — Lambda is still processing. Try again in a few seconds.")
        st.stop()
        return

    # Quick tip: use the pre-generated sample
    sample = REPO_ROOT / "sample_data" / "offer-letter.pdf"
    if sample.exists():
        with open(sample, "rb") as fh:
            st.download_button(
                "📥 Download sample offer letter (Priya Sharma)",
                fh,
                file_name="offer-letter.pdf",
                mime="application/pdf",
                help="Use this to demo the full pipeline without a real PDF.",
            )
        st.caption("Upload the sample above — or any offer letter PDF.")

    uploaded = st.file_uploader(
        "Offer Letter PDF",
        type=["pdf"],
        key="offer_upload",
        label_visibility="collapsed",
    )

    if uploaded:
        col_info, col_btn = st.columns([3, 1])
        with col_info:
            st.success(f"**{uploaded.name}** — {len(uploaded.getvalue()):,} bytes ready.")
        with col_btn:
            process = st.button("Process →", type="primary", use_container_width=True)

        if process:
            emp_id = "EMP-" + uuid.uuid4().hex[:8].upper()
            pdf_bytes = uploaded.getvalue()

            with st.spinner("Extracting employee data and generating NDA…"):
                try:
                    if MOCK_MODE:
                        data, nda_text, nda_pdf_path = process_offer_letter_mock(pdf_bytes, emp_id)
                    else:
                        # Real mode: push to S3 and trigger Lambda via GitHub workflow
                        import boto3
                        s3 = boto3.client("s3")
                        s3.put_object(
                            Bucket=BUCKET_NAME,
                            Key=f"employees/{emp_id}/offer-letter.pdf",
                            Body=pdf_bytes,
                        )
                        st.info(
                            f"✅ Offer letter uploaded to vault (`{emp_id}`).\n\n"
                            "GitHub Actions workflow triggered — Lambda is extracting data and generating the NDA.\n\n"
                            "Click **Check Status** after ~30 seconds."
                        )
                        # Store emp_id so the check-status widget can poll
                        st.session_state.emp_id = emp_id
                        st.session_state._waiting_for_lambda = True
                        dispatch_to_github(emp_id, "offer-uploaded")
                        st.rerun()
                        return  # exit — polling handled below

                    st.session_state.emp_id = emp_id
                    st.session_state.employee_data = data
                    st.session_state.nda_text = nda_text
                    st.session_state.nda_pdf_path = str(nda_pdf_path)
                    st.session_state.step = "sign"
                    st.rerun()

                except Exception as exc:
                    st.error(f"Processing failed: {exc}")
                    st.exception(exc)


# ═══════════════════════════════════════════════════════════════════════════════
# Policy helpers — render and sign policy acknowledgement PDFs
# ═══════════════════════════════════════════════════════════════════════════════

POLICIES = [
    {
        "id":    "nda",
        "label": "Non-Disclosure Agreement (NDA)",
        "file":  None,   # uses nda_text from session state
        "icon":  "🔐",
    },
    {
        "id":    "security",
        "label": "Information Security Policy",
        "file":  "security_policy.md",
        "icon":  "🔒",
    },
    {
        "id":    "handbook",
        "label": "Employee Handbook",
        "file":  "employee_handbook.md",
        "icon":  "📖",
    },
    {
        "id":    "acceptable_use",
        "label": "Acceptable Use Policy",
        "file":  "acceptable_use.md",
        "icon":  "💻",
    },
]


def load_policy_text(policy: dict, nda_text: str | None = None) -> str:
    """Load the full text for a policy."""
    if policy["id"] == "nda":
        return nda_text or "NDA text not available."
    fpath = POLICIES_DIR / policy["file"]
    if fpath.exists():
        return fpath.read_text()
    return f"Policy document '{policy['file']}' not found in policies directory."


def render_policy_ack_pdf(
    policy_label: str,
    policy_text: str,
    signature_name: str,
    audit_trail: dict,
    output_path: Path,
) -> None:
    """Render a policy acknowledgement PDF with signature block."""
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 12, text=_safe(policy_label.upper()), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "I", 9)
    pdf.cell(0, 6, text=_safe("[ELECTRONICALLY ACKNOWLEDGED]"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Policy body
    pdf.set_font("Helvetica", size=9)
    for line in policy_text.split("\n"):
        stripped = line.strip()
        # Markdown heading detection
        if stripped.startswith("# ") and not stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 9, text=_safe(stripped[2:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=9)
        elif stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, text=_safe(stripped[3:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=9)
        elif stripped.startswith("### "):
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, text=_safe(stripped[4:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=9)
        elif stripped.startswith("---"):
            pdf.set_draw_color(200, 200, 200)
            pdf.line(20, pdf.get_y(), 190, pdf.get_y())
            pdf.ln(3)
        elif stripped.startswith("| ") and "|" in stripped[2:]:
            # Render table rows as plain text
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            row_text = "  |  ".join(cells)
            pdf.set_font("Courier", size=8)
            pdf.multi_cell(0, 5, text=_safe(row_text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=9)
        elif stripped == "":
            pdf.ln(3)
        else:
            # Strip markdown bold/italic markers for clean output
            clean = re.sub(r'\*{1,2}([^*]+)\*{1,2}', r'\1', stripped)
            clean = re.sub(r'_{1,2}([^_]+)_{1,2}', r'\1', clean)
            pdf.multi_cell(0, 5, text=_safe(clean), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Signature block
    pdf.ln(8)
    pdf.set_draw_color(100, 100, 100)
    pdf.set_line_width(0.5)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, text=_safe("ACKNOWLEDGEMENT & ELECTRONIC SIGNATURE"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=9)

    sig_rows = [
        ("Policy",              policy_label),
        ("Signer Name",         audit_trail.get("signer_name", "")),
        ("Signed At (UTC)",     audit_trail.get("timestamp_utc", "")),
        ("Signature Method",    "Typed Legal Name (Electronic Consent)"),
        ("Consent Statement",   "I have read, understood, and agree to comply with this policy."),
    ]
    for label, value in sig_rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(50, 6, text=_safe(f"{label}:"))
        pdf.set_font("Helvetica", size=9)
        pdf.multi_cell(0, 6, text=_safe(str(value)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(str(output_path))


def generate_combined_evidence_pdf(
    emp_id: str,
    employee_data: dict,
    audit_trail: dict,
    policy_sigs: dict,
    photo_path: Path | None,
    output_path: Path,
) -> None:
    """Generate a single combined PDF containing all evidence: photo, NDA, policies, credentials info."""
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)

    # ── Cover page ──
    pdf.add_page()
    pdf.set_fill_color(15, 23, 42)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_y(80)
    pdf.cell(0, 14, text="SOC 2 ONBOARDING", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 14, text="EVIDENCE BUNDLE", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(10)
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, text=_safe(f"Employee: {employee_data.get('name', 'Unknown')}"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, text=_safe(f"Employee ID: {emp_id}"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, text=_safe(f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "I", 10)
    pdf.ln(20)
    pdf.cell(0, 6, text="Confidential — SOC 2 Compliance Evidence", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Employee info + selfie page ──
    pdf.add_page()
    pdf.set_text_color(33, 37, 41)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, text="Section 1: Employee Verification", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(4)

    y_info = pdf.get_y()
    # Photo on right
    if photo_path and photo_path.exists():
        try:
            pdf.image(str(photo_path), x=140, y=y_info, w=45, h=45)
        except Exception as e:
            print(f"[evidence-pdf] Could not embed photo: {e}")

    pdf.set_font("Helvetica", size=10)
    info_rows = [
        ("Full Name",          employee_data.get("name", "Unknown")),
        ("Employee ID",        emp_id),
        ("Designation",        employee_data.get("designation", "Employee")),
        ("Team",               employee_data.get("team", "Engineering")),
        ("Employment Type",    employee_data.get("employment_type", "full-time")),
        ("Experience Level",   employee_data.get("experience_level", "fresher").capitalize()),
        ("Start Date",         employee_data.get("start_date", "TBD")),
        ("Photo Captured",     "Yes" if (photo_path and photo_path.exists()) else "Not captured"),
    ]
    for label, value in info_rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(45, 6, text=_safe(f"{label}:"))
        pdf.set_font("Helvetica", size=9)
        pdf.cell(80, 6, text=_safe(str(value)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if photo_path and photo_path.exists():
        pdf.set_y(max(pdf.get_y(), y_info + 50))

    # ── Signature audit trail ──
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 9, text="NDA Signature Audit Trail", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=9)
    trail_rows = [
        ("Signer Name",         audit_trail.get("signer_name", "")),
        ("Signed At (UTC)",     audit_trail.get("timestamp_utc", "")),
        ("IP Address",          audit_trail.get("source_ip", "")),
        ("Consent Given",       "Yes" if audit_trail.get("consent") else "No"),
        ("Signature Method",    "Typed Legal Name"),
        ("Doc Hash (pre-sign)", str(audit_trail.get("document_hash_before", ""))[:48]),
        ("Doc Hash (post-sign)", str(audit_trail.get("document_hash_after", ""))[:48]),
    ]
    for label, value in trail_rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(50, 5, text=_safe(f"{label}:"))
        pdf.set_font("Courier", size=8)
        pdf.multi_cell(0, 5, text=_safe(str(value)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Policy acknowledgements summary ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, text="Section 2: Policy Acknowledgements", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(241, 245, 249)
    pdf.cell(70, 7, "Policy", border=1, fill=True)
    pdf.cell(45, 7, "Signed At (UTC)", border=1, fill=True)
    pdf.cell(55, 7, "Signer Name", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", size=8)
    for p in POLICIES:
        sig = policy_sigs.get(p["id"], {})
        signed_at = sig.get("signed_at", "NOT SIGNED")
        sig_name = sig.get("sig_name", "—")
        row_fill = (255, 255, 255) if sig else (254, 226, 226)
        pdf.set_fill_color(*row_fill)
        pdf.cell(70, 7, _safe(p["label"]), border=1, fill=True)
        pdf.cell(45, 7, _safe(signed_at[:19] if len(signed_at) > 19 else signed_at), border=1, fill=True)
        pdf.cell(55, 7, _safe(sig_name), border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(str(output_path))


# ═══════════════════════════════════════════════════════════════════════════════
# UI — Step 2: Sign NDA & all policies
# ═══════════════════════════════════════════════════════════════════════════════

def step_sign() -> None:
    st.header("Step 2 — Review & Sign NDA + Policies")

    data = st.session_state.employee_data or {}
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Name", data.get("name", "—"))
    col2.metric("Role", data.get("designation", "—"))
    col3.metric("Team", data.get("team", "—"))
    col4.metric(
        "Experience",
        data.get("experience_level", "—").capitalize(),
        help="Determines access bundle (fresher → read-only, experienced → developer)",
    )

    # Confidence indicator
    conf = float(data.get("confidence", 0))
    if conf < 0.6:
        st.warning(
            f"Extraction confidence: **{conf:.0%}** (regex fallback). "
            "Please verify the details above before signing."
        )
    else:
        st.success(f"Extraction confidence: **{conf:.0%}** (AI extraction).")

    emp_id = st.session_state.emp_id
    nda_text = st.session_state.nda_text or ""
    nda_pdf_path = st.session_state.nda_pdf_path

    # ── Photo Verification (required once for all) ───────────────────────────
    st.divider()
    st.subheader("📷 Live Photo Verification (Required)")
    st.caption(
        "SOC 2 requirement: capture a live selfie to verify your identity before signing. "
        "This photo will be embedded in your compliance evidence bundle."
    )

    col_cam, col_upload = st.columns([3, 1])
    with col_cam:
        photo = st.camera_input("📸 Capture live photo", label_visibility="visible", key="webcam_photo")
    with col_upload:
        st.caption("No webcam?")
        photo_upload = st.file_uploader(
            "Upload photo",
            type=["png", "jpg", "jpeg"],
            key="photo_upload",
            label_visibility="visible",
        )

    captured_photo = photo or photo_upload
    photo_ok = captured_photo is not None

    if not photo_ok:
        st.info("Capture or upload a photo to enable signing.")

    # ── Policy tabs — each policy must be signed individually ────────────────
    st.divider()
    st.subheader("📋 Review & Sign All Required Documents")
    st.info(
        "You must read and sign **all 4 documents** before proceeding. "
        "Each document requires your typed name as an electronic signature."
    )

    policy_sigs: dict = st.session_state.policy_sigs or {}
    policy_signed_paths: dict = st.session_state.policy_signed_paths or {}

    tabs = st.tabs([f"{p['icon']} {p['label']}" for p in POLICIES])

    for tab, policy in zip(tabs, POLICIES):
        with tab:
            pid = policy["id"]
            p_text = load_policy_text(policy, nda_text)
            already_signed = pid in policy_sigs

            if already_signed:
                sig_info = policy_sigs[pid]
                st.success(
                    f"✅ Signed by **{sig_info['sig_name']}** "
                    f"at {sig_info['signed_at'][:19]} UTC"
                )
                # Download signed copy
                signed_p = policy_signed_paths.get(pid)
                if signed_p and Path(signed_p).exists():
                    with open(signed_p, "rb") as fh:
                        st.download_button(
                            f"📥 Download Signed {policy['label']}",
                            fh,
                            file_name=f"signed-{pid}.pdf",
                            mime="application/pdf",
                            key=f"dl_{pid}",
                        )
                continue

            # Show policy text
            with st.expander(f"📄 Read {policy['label']} (required before signing)", expanded=False):
                st.text_area(
                    policy["label"],
                    p_text,
                    height=400,
                    disabled=True,
                    label_visibility="collapsed",
                    key=f"text_{pid}",
                )

            # Download unsigned PDF if NDA
            if pid == "nda" and nda_pdf_path and Path(nda_pdf_path).exists():
                with open(nda_pdf_path, "rb") as fh:
                    st.download_button(
                        "📥 Download NDA PDF (unsigned)",
                        fh,
                        file_name="nda-unsigned.pdf",
                        mime="application/pdf",
                        key=f"dl_unsigned_{pid}",
                    )

            consent = st.checkbox(
                f"I have read and understood the **{policy['label']}** and agree to its terms. "
                "I consent to sign electronically.",
                key=f"consent_{pid}",
            )
            sig_name = st.text_input(
                "Type your full legal name as your signature:",
                placeholder="e.g. Priya Sharma",
                key=f"sig_{pid}",
            )

            can_sign = consent and sig_name.strip() and photo_ok
            if not photo_ok:
                st.warning("Capture your photo above first.")
            elif not consent:
                st.info("Check the consent box to enable signing.")
            elif not sig_name.strip():
                st.info("Type your full legal name to sign.")

            if can_sign and st.button(
                f"✍️ Sign {policy['label']}",
                type="primary",
                key=f"sign_btn_{pid}",
            ):
                with st.spinner(f"Signing {policy['label']}…"):
                    try:
                        d = get_emp_dir(emp_id)
                        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

                        p_audit = {
                            "emp_id": emp_id,
                            "policy_id": pid,
                            "policy_label": policy["label"],
                            "signer_name": sig_name.strip(),
                            "timestamp_utc": now_ts,
                            "source_ip": get_client_ip(),
                            "consent": True,
                            "signature_method": "typed-name",
                        }

                        out_path = d / f"signed-{pid}.pdf"
                        render_policy_ack_pdf(
                            policy_label=policy["label"],
                            policy_text=p_text,
                            signature_name=sig_name.strip(),
                            audit_trail=p_audit,
                            output_path=out_path,
                        )

                        # Upload to S3 in live mode
                        if not MOCK_MODE:
                            import boto3
                            s3 = boto3.client("s3")
                            s3.put_object(
                                Bucket=BUCKET_NAME,
                                Key=f"employees/{emp_id}/signed-{pid}.pdf",
                                Body=out_path.read_bytes(),
                                ContentType="application/pdf",
                            )

                        policy_sigs[pid] = {
                            "signed_at": now_ts,
                            "sig_name": sig_name.strip(),
                        }
                        policy_signed_paths[pid] = str(out_path)
                        st.session_state.policy_sigs = policy_sigs
                        st.session_state.policy_signed_paths = policy_signed_paths
                        st.success(f"✅ {policy['label']} signed!")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Signing failed: {exc}")
                        st.exception(exc)

    # ── Check all policies signed ─────────────────────────────────────────────
    all_policy_ids = {p["id"] for p in POLICIES}
    signed_ids = set(policy_sigs.keys())
    remaining = all_policy_ids - signed_ids

    st.divider()
    if remaining:
        still_needed = [p["label"] for p in POLICIES if p["id"] in remaining]
        st.warning(f"Still needs signing: **{', '.join(still_needed)}**")
    else:
        st.success("✅ All documents signed! You can now proceed.")

        if st.button("✅ Submit All Signatures & Proceed to Approval", type="primary"):
            # The NDA is the primary document — save it as signed-nda.pdf
            signed_nda = policy_signed_paths.get("nda")
            if not signed_nda:
                st.error("Signed NDA path not found. Please re-sign the NDA.")
                return

            # Build the main audit trail from the NDA signing
            nda_sig = policy_sigs.get("nda", {})
            nda_pdf_p = Path(nda_pdf_path) if nda_pdf_path else None

            audit_trail = {
                "emp_id": emp_id,
                "signer_name": nda_sig.get("sig_name", ""),
                "timestamp_utc": nda_sig.get("signed_at", ""),
                "source_ip": get_client_ip(),
                "user_agent": "Attest-Streamlit-Portal/2.0",
                "consent": True,
                "signature_method": "typed-name",
                "document_hash_before": sha256_file(nda_pdf_p) if (nda_pdf_p and nda_pdf_p.exists()) else "",
                "document_hash_after": sha256_file(signed_nda) if Path(signed_nda).exists() else "",
                "policies_signed": list(signed_ids),
            }

            d = get_emp_dir(emp_id)

            # Save photo
            if captured_photo:
                photo_bytes = captured_photo.getvalue()
                (d / "photo.jpg").write_bytes(photo_bytes)
                if not MOCK_MODE:
                    import boto3
                    s3 = boto3.client("s3")
                    s3.put_object(
                        Bucket=BUCKET_NAME,
                        Key=f"employees/{emp_id}/photo.jpg",
                        Body=photo_bytes,
                        ContentType="image/jpeg",
                    )

            # Copy signed-nda.pdf into the expected location
            import shutil
            target_nda = str(d / "signed-nda.pdf")
            if str(signed_nda) != target_nda:
                shutil.copy(signed_nda, target_nda)

            # Save audit trail
            (d / "nda-audit-trail.json").write_text(json.dumps(audit_trail, indent=2))

            # Generate combined evidence PDF
            combined_path = d / "combined-evidence.pdf"
            try:
                generate_combined_evidence_pdf(
                    emp_id=emp_id,
                    employee_data=data,
                    audit_trail=audit_trail,
                    policy_sigs=policy_sigs,
                    photo_path=d / "photo.jpg" if (d / "photo.jpg").exists() else None,
                    output_path=combined_path,
                )
            except Exception as e:
                print(f"[portal] combined-evidence.pdf generation failed: {e}")

            # Live mode: upload to S3 and dispatch nda-signed
            if not MOCK_MODE:
                import boto3
                s3 = boto3.client("s3")
                s3.put_object(
                    Bucket=BUCKET_NAME,
                    Key=f"employees/{emp_id}/signed-nda.pdf",
                    Body=(d / "signed-nda.pdf").read_bytes(),
                    ContentType="application/pdf",
                )
                s3.put_object(
                    Bucket=BUCKET_NAME,
                    Key=f"employees/{emp_id}/nda-audit-trail.json",
                    Body=json.dumps(audit_trail, indent=2).encode(),
                    ContentType="application/json",
                )
                if combined_path.exists():
                    s3.put_object(
                        Bucket=BUCKET_NAME,
                        Key=f"employees/{emp_id}/combined-evidence.pdf",
                        Body=combined_path.read_bytes(),
                        ContentType="application/pdf",
                    )
                # Dispatch to GitHub Actions provisioning workflow
                dispatch_to_github(emp_id, "nda-signed")

            st.session_state.audit_trail = audit_trail
            st.session_state.signed_nda_path = str(d / "signed-nda.pdf")
            st.session_state.step = "approve"
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# UI — Step 3: Pending Approval
# ═══════════════════════════════════════════════════════════════════════════════

def step_approve() -> None:
    st.header("Step 3 — Tech Lead Approval")

    audit = st.session_state.audit_trail or {}
    st.success(
        f"NDA signed by **{audit.get('signer_name', '—')}** "
        f"at {audit.get('timestamp_utc', '—')} UTC."
    )

    st.info(
        "The signed NDA has been stored in the evidence vault. "
        "An authorised **Tech Lead** must now approve access provisioning before "
        "any systems are modified. In the live pipeline, this is an approval gate "
        "in a GitHub Actions `provisioning` Environment."
    )

    with st.expander("📋 Signature Audit Trail"):
        st.json(audit)

    # Download signed NDA
    signed_path = st.session_state.signed_nda_path
    if signed_path and Path(signed_path).exists():
        with open(signed_path, "rb") as fh:
            st.download_button(
                "📥 Download Signed NDA",
                fh,
                file_name="signed-nda.pdf",
                mime="application/pdf",
            )

    st.divider()

    if MOCK_MODE:
        st.subheader("Simulate Tech Lead Approval")
        st.warning(
            "**MOCK MODE**: In production, a designated Tech Lead approves the GitHub "
            "`provisioning` Environment in the GitHub Actions UI. Click below to simulate."
        )
        approver = st.text_input(
            "Approver name (recorded in audit trail):",
            value="alice-tech-lead",
            key="approver_name",
        )
        if st.button("✅ Approve & Provision Access", type="primary"):
            with st.spinner("Mock-provisioning access and collecting evidence…"):
                try:
                    result = run_provisioning(
                        st.session_state.emp_id,
                        approver=(approver or "mock-tech-lead").strip(),
                    )
                    # Generate combined evidence PDF if not already done
                    emp_id = st.session_state.emp_id
                    d = get_emp_dir(emp_id)
                    combined_path = d / "combined-evidence.pdf"
                    if not combined_path.exists():
                        try:
                            generate_combined_evidence_pdf(
                                emp_id=emp_id,
                                employee_data=st.session_state.employee_data or {},
                                audit_trail=st.session_state.audit_trail or {},
                                policy_sigs=st.session_state.policy_sigs or {},
                                photo_path=d / "photo.jpg" if (d / "photo.jpg").exists() else None,
                                output_path=combined_path,
                            )
                        except Exception as e:
                            print(f"[portal] combined-evidence.pdf generation failed: {e}")
                    st.session_state.evidence = result
                    st.session_state.step = "done"
                    st.rerun()
                except Exception as exc:
                    st.error(f"Provisioning failed: {exc}")
                    st.exception(exc)
    else:
        st.subheader("⏳ Waiting for Tech Lead Approval")
        st.info(
            "An **approval email** has been sent to the Tech Lead with ✅ Approve and ❌ Reject buttons.\n\n"
            "The signed NDA also triggered a GitHub Actions `repository_dispatch` as a backup approval path.\n\n"
            "Once the Tech Lead approves, access will be provisioned automatically."
        )

        # Poll S3 for approval status
        import boto3, time
        s3 = boto3.client("s3")
        emp_id = st.session_state.emp_id
        prefix = f"employees/{emp_id}"

        # Check pending-approval status
        try:
            r = s3.get_object(Bucket=BUCKET_NAME, Key=f"{prefix}/pending-approval.json")
            pending = json.loads(r["Body"].read())
            status = pending.get("status", "pending")

            if status == "approved":
                st.success(f"✅ **Approved** by {pending.get('approved_by', 'tech lead')} at {pending.get('approved_at', '—')}")
                # Load evidence
                try:
                    r2 = s3.get_object(Bucket=BUCKET_NAME, Key=f"{prefix}/evidence-index.json")
                    evidence = json.loads(r2["Body"].read())
                    st.session_state.evidence = evidence
                    st.session_state.step = "done"
                    st.rerun()
                except Exception:
                    st.info("Evidence is being generated. Refresh in a moment.")
            elif status == "rejected":
                st.error(f"❌ **Rejected** by {pending.get('rejected_by', 'tech lead')} at {pending.get('rejected_at', '—')}")
                st.warning("The employee's access request was rejected. Contact the tech lead for details.")
            else:
                st.warning(f"Status: **{status}** — waiting for tech lead to click the approval link in their email.")
                token = pending.get("token")
                if token:
                    api_url = get_approval_api_url()
                    if api_url:
                        approve_url = f"{api_url}/approve?token={token}&emp_id={emp_id}&action=approve&approver=portal-debug"
                        st.info("💡 **Debug / Shortcut Link:** You can simulate the Tech Lead's approval by clicking the button below:")
                        st.link_button("✅ Approve & Provision Access", approve_url)
        except Exception as exc:
            st.warning(f"Approval request is being processed. Refresh to check status. Details: {exc}")

        if st.button("🔄 Refresh Status", type="primary"):
            st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
# UI — Step 4: Done
# ═══════════════════════════════════════════════════════════════════════════════

def step_done() -> None:
    st.header("Step 4 — Onboarding Complete 🎉")

    evidence = st.session_state.evidence or {}
    emp_name = evidence.get(
        "employee_name",
        (st.session_state.employee_data or {}).get("name", "Employee"),
    )

    st.success(
        f"**{emp_name}** has been successfully onboarded. "
        "All SOC 2 evidence files have been captured and stored in the vault."
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Employee", emp_name)
    col2.metric("Role", evidence.get("role", "—").capitalize())
    col3.metric("Access Bundles", len(evidence.get("access_bundles", [])))
    col4.metric("Approver", evidence.get("approver", "—"))

    st.subheader("Evidence Index")
    with st.expander("📦 Full evidence-index.json", expanded=False):
        st.json(evidence)

    st.subheader("Access Grants")
    grants = evidence.get("grants", [])
    if grants:
        import pandas as pd
        try:
            df = pd.DataFrame(grants)
            # Show available columns only
            show_cols = [c for c in ["permission_name", "policy_arn", "granted_at", "approved_by", "real_provisioning"] if c in df.columns]
            if show_cols:
                rename_map = {
                    "permission_name": "Permission",
                    "policy_arn": "Policy ARN",
                    "granted_at": "Granted At",
                    "approved_by": "Approved By",
                    "real_provisioning": "Real?",
                }
                st.dataframe(df[show_cols].rename(columns=rename_map), use_container_width=True)
            else:
                st.dataframe(df, use_container_width=True)
        except Exception:
            st.json(grants)

    st.subheader("📥 Download Evidence Files")

    if MOCK_MODE:
        # Local filesystem download
        d = get_emp_dir(st.session_state.emp_id)
        file_map = {
            "offer-letter.pdf":           ("Offer Letter",                  "application/pdf"),
            "employee.json":              ("Extracted Employee Data",        "application/json"),
            "nda-unsigned.pdf":           ("Unsigned NDA",                  "application/pdf"),
            "signed-nda.pdf":             ("Signed NDA",                    "application/pdf"),
            "signed-security.pdf":        ("Signed Security Policy",        "application/pdf"),
            "signed-handbook.pdf":        ("Signed Employee Handbook",      "application/pdf"),
            "signed-acceptable_use.pdf":  ("Signed Acceptable Use Policy",  "application/pdf"),
            "nda-audit-trail.json":       ("E-Signature Audit Trail",       "application/json"),
            "photo.jpg":                  ("Verification Photo (JPG)",      "image/jpeg"),
            "access-granted.csv":         ("Access Grant Record (CSV)",     "text/csv"),
            "aws-access-credentials.csv": ("AWS Credentials (CSV)",        "text/csv"),
            "combined-evidence.pdf":      ("Combined Evidence Bundle PDF",  "application/pdf"),
            "onboarding-report.pdf":      ("Compliance Report (PDF)",       "application/pdf"),
            "evidence-index.json":        ("Evidence Index",                "application/json"),
        }
        cols = st.columns(3)
        for i, (fname, (label, mime)) in enumerate(file_map.items()):
            fpath = d / fname
            if fpath.exists():
                with cols[i % 3]:
                    with open(fpath, "rb") as fh:
                        st.download_button(
                            f"📄 {label}",
                            fh,
                            file_name=fname,
                            mime=mime,
                            use_container_width=True,
                        )
    else:
        # S3 download
        import boto3
        s3 = boto3.client("s3")
        emp_id = st.session_state.emp_id
        prefix = f"employees/{emp_id}"
        file_map = {
            "offer-letter.pdf":           ("Offer Letter",                  "application/pdf"),
            "employee.json":              ("Extracted Employee Data",        "application/json"),
            "nda-unsigned.pdf":           ("Unsigned NDA",                  "application/pdf"),
            "signed-nda.pdf":             ("Signed NDA",                    "application/pdf"),
            "signed-security.pdf":        ("Signed Security Policy",        "application/pdf"),
            "signed-handbook.pdf":        ("Signed Employee Handbook",      "application/pdf"),
            "signed-acceptable_use.pdf":  ("Signed Acceptable Use Policy",  "application/pdf"),
            "nda-audit-trail.json":       ("E-Signature Audit Trail",       "application/json"),
            "photo.jpg":                  ("Verification Photo (JPG)",      "image/jpeg"),
            "access-granted.csv":         ("Access Grant Record (CSV)",     "text/csv"),
            "aws-access-credentials.csv": ("AWS Credentials (CSV)",        "text/csv"),
            "combined-evidence.pdf":      ("Combined Evidence Bundle PDF",  "application/pdf"),
            "onboarding-report.pdf":      ("Compliance Report (PDF)",       "application/pdf"),
            "evidence-index.json":        ("Evidence Index",                "application/json"),
        }
        cols = st.columns(3)
        for i, (fname, (label, mime)) in enumerate(file_map.items()):
            try:
                r = s3.get_object(Bucket=BUCKET_NAME, Key=f"{prefix}/{fname}")
                file_bytes = r["Body"].read()
                with cols[i % 3]:
                    st.download_button(
                        f"📄 {label}",
                        file_bytes,
                        file_name=fname,
                        mime=mime,
                        use_container_width=True,
                    )
            except Exception:
                pass  # File doesn't exist yet


# ═══════════════════════════════════════════════════════════════════════════════
# UI — Offboarding Flow
# ═══════════════════════════════════════════════════════════════════════════════

def step_offboard_init() -> None:
    st.header("Offboarding Step 1 — Initiate")
    st.write("Enter the Employee ID to begin the offboarding and access revocation process.")
    
    with st.form("offboard_init_form"):
        emp_id = st.text_input("Employee ID", placeholder="e.g. EMP-12345678")
        submit = st.form_submit_button("Fetch Employee Data", type="primary")
        
        if submit:
            if not emp_id.strip():
                st.error("Please enter an Employee ID.")
                return
            emp_id = emp_id.strip().upper()
            
            with st.spinner("Fetching data from vault..."):
                d = get_emp_dir(emp_id)
                emp_data = None
                
                # Fetch locally or from S3
                if MOCK_MODE:
                    if (d / "employee.json").exists():
                        emp_data = json.loads((d / "employee.json").read_text())
                else:
                    import boto3
                    s3 = boto3.client("s3")
                    try:
                        r = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/employee.json")
                        emp_data = json.loads(r["Body"].read())
                    except Exception as e:
                        pass
                
                if emp_data:
                    st.session_state.emp_id = emp_id
                    st.session_state.employee_data = emp_data
                    st.session_state.step = "offboard_audit"
                    st.rerun()
                else:
                    st.error(f"Employee {emp_id} not found in the evidence vault.")

def step_offboard_audit() -> None:
    st.header("Offboarding Step 2 — Audit & Backup")
    
    emp_id = st.session_state.emp_id
    data = st.session_state.employee_data or {}
    
    st.info(f"Auditing active access for **{data.get('name', emp_id)}**...")
    
    col1, col2 = st.columns(2)
    col1.metric("Name", data.get("name", "—"))
    col2.metric("Role", data.get("designation", "—"))
    
    if "offboard_audit_result" not in st.session_state:
        with st.spinner("Querying AWS IAM for active sessions and keys..."):
            import offboarding_utils
            audit = offboarding_utils.get_employee_access_audit(emp_id, data)
            st.session_state.offboard_audit_result = audit
            
            # Save backup of current state
            d = get_emp_dir(emp_id)
            backup = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "employee_data": data,
                "audit": audit
            }
            (d / "offboard-backup.json").write_text(json.dumps(backup, indent=2))
            if not MOCK_MODE:
                import boto3
                s3 = boto3.client("s3")
                s3.put_object(
                    Bucket=BUCKET_NAME,
                    Key=f"employees/{emp_id}/offboard-backup.json",
                    Body=json.dumps(backup, indent=2).encode(),
                    ContentType="application/json"
                )
    
    audit = st.session_state.offboard_audit_result
    st.subheader("Active Access Detected")
    st.write(f"**IAM Username:** `{audit.get('iam_username')}`")
    st.write(f"**Console Access:** {'Yes' if audit.get('console_access') else 'No'}")
    st.write(f"**MFA Enabled:** {'Yes' if audit.get('mfa_enabled') else 'No'}")
    
    st.write("**Policies Attached:**")
    for p in audit.get("policies", []):
        st.code(p)
        
    st.write("**Access Keys:**")
    for k in audit.get("access_keys", []):
        st.code(k)
        
    st.divider()
    if st.button("Request Manager Approval for Wipe", type="primary"):
        # Create pending-offboard.json
        req = {
            "emp_id": emp_id,
            "employee_name": data.get("name"),
            "status": "pending",
            "requested_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "audit": audit
        }
        
        d = get_emp_dir(emp_id)
        (d / "pending-offboard.json").write_text(json.dumps(req, indent=2))
        
        if not MOCK_MODE:
            import boto3
            s3 = boto3.client("s3")
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=f"employees/{emp_id}/pending-offboard.json",
                Body=json.dumps(req, indent=2).encode(),
                ContentType="application/json"
            )
            
        st.session_state.step = "offboard_approve"
        st.rerun()

def step_offboard_approve() -> None:
    st.header("Offboarding Step 3 — Manager Verification")
    
    emp_id = st.session_state.emp_id
    d = get_emp_dir(emp_id)
    
    # Check status
    status = "pending"
    approver = ""
    if MOCK_MODE:
        if (d / "pending-offboard.json").exists():
            req = json.loads((d / "pending-offboard.json").read_text())
            status = req.get("status", "pending")
            approver = req.get("approved_by", "")
    else:
        import boto3
        s3 = boto3.client("s3")
        try:
            r = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/pending-offboard.json")
            req = json.loads(r["Body"].read())
            status = req.get("status", "pending")
            approver = req.get("approved_by", "")
        except Exception:
            pass
            
    if status == "approved":
        st.success(f"✅ Offboarding approved by {approver}. Commencing secure data wipe...")
        
        if st.button("Execute Data Wipe & Revoke Access", type="primary"):
            with st.spinner("Deleting AWS IAM resources and generating report..."):
                import offboarding_utils
                revocation = offboarding_utils.revoke_employee_access(emp_id, st.session_state.employee_data)
                
                # Generate report
                out_path = d / "offboarding-report.pdf"
                offboarding_utils.generate_offboarding_report(
                    emp_id, 
                    st.session_state.employee_data, 
                    st.session_state.offboard_audit_result, 
                    revocation, 
                    approver, 
                    str(out_path)
                )
                
                if not MOCK_MODE:
                    s3.put_object(
                        Bucket=BUCKET_NAME,
                        Key=f"employees/{emp_id}/offboarding-report.pdf",
                        Body=out_path.read_bytes(),
                        ContentType="application/pdf"
                    )
                
                st.session_state.revocation_result = revocation
                st.session_state.step = "offboard_done"
                st.rerun()
                
    elif status == "rejected":
        st.error("❌ Offboarding request was rejected by the manager.")
    else:
        st.warning("⏳ Waiting for manager approval via the Manager Mailbox (Port 8002).")
        if st.button("🔄 Check Status"):
            st.rerun()

def step_offboard_done() -> None:
    st.header("Offboarding Complete 🎉")
    st.success("SOC 2 Data Wipe and Access Revocation completed successfully.")
    
    rev = st.session_state.revocation_result
    st.write("### Actions Performed")
    for act in rev.get("actions", []):
        st.markdown(f"- ✅ {act}")
        
    d = get_emp_dir(st.session_state.emp_id)
    if (d / "offboarding-report.pdf").exists():
        with open(d / "offboarding-report.pdf", "rb") as fh:
            st.download_button(
                "📥 Download Offboarding Compliance Report (PDF)",
                fh,
                file_name="offboarding-report.pdf",
                mime="application/pdf",
                type="primary"
            )

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════


render_sidebar()

_step = st.session_state.step
if _step == "upload":
    step_upload()
elif _step == "sign":
    step_sign()
elif _step == "approve":
    step_approve()
elif _step == "done":
    step_done()
elif _step == "offboard_init":
    step_offboard_init()
elif _step == "offboard_audit":
    step_offboard_audit()
elif _step == "offboard_approve":
    step_offboard_approve()
elif _step == "offboard_done":
    step_offboard_done()
else:
    st.error(f"Unknown step: {_step!r}")
    st.session_state.step = "upload" if st.session_state.flow == "onboarding" else "offboard_init"
    st.rerun()
