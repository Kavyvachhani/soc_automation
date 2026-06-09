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
    "step": "upload",
    "emp_id": None,
    "employee_data": None,
    "nda_text": None,
    "nda_pdf_path": None,
    "signed_nda_path": None,
    "audit_trail": None,
    "evidence": None,
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline helpers (used by both MOCK_MODE inline and accessible by Lambda)
# ═══════════════════════════════════════════════════════════════════════════════

def _safe(s: str) -> str:
    """Encode string to latin-1 safely for fpdf core fonts."""
    return str(s).encode("latin-1", errors="replace").decode("latin-1")


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
    github_token = os.environ.get("GITHUB_TOKEN", "")
    github_org = os.environ.get("GITHUB_ORG", "")
    github_repo = os.environ.get("GITHUB_REPO", "attest")

    if not github_token or not github_org:
        print(f"[dispatch] GITHUB_TOKEN or GITHUB_ORG not set; skipping dispatch for {event_type}")
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

        steps = [
            ("upload",  "Upload Offer Letter"),
            ("sign",    "Sign NDA"),
            ("approve", "Tech Lead Approval"),
            ("done",    "Evidence Collected"),
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
                        # Real mode: push to S3 and trigger GitHub workflow
                        import boto3, time
                        s3 = boto3.client("s3")
                        s3.put_object(
                            Bucket=BUCKET_NAME,
                            Key=f"employees/{emp_id}/offer-letter.pdf",
                            Body=pdf_bytes,
                        )
                        st.info("Offer letter uploaded to vault. Triggering processing workflow in GitHub Actions…")
                        dispatch_to_github(emp_id, "offer-uploaded")
                        st.info("Waiting for workflow to complete & NDA to generate…")
                        nda_pdf_path = None
                        for _ in range(30):
                            time.sleep(2)
                            try:
                                r = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/employee.json")
                                data = json.loads(r["Body"].read())
                                r2 = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/nda-content.txt")
                                nda_text = r2["Body"].read().decode()
                                # Download NDA PDF locally for display
                                tmp = Path(f"/tmp/{emp_id}")
                                tmp.mkdir(exist_ok=True)
                                r3 = s3.get_object(Bucket=BUCKET_NAME, Key=f"employees/{emp_id}/nda-unsigned.pdf")
                                nda_pdf_path = tmp / "nda-unsigned.pdf"
                                nda_pdf_path.write_bytes(r3["Body"].read())
                                break
                            except Exception:
                                continue
                        if nda_pdf_path is None:
                            st.error("Lambda processing timed out. Check CloudWatch logs.")
                            return

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
# UI — Step 2: Sign NDA
# ═══════════════════════════════════════════════════════════════════════════════

def step_sign() -> None:
    st.header("Step 2 — Review & Sign NDA")

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

    st.subheader("Non-Disclosure Agreement")
    nda_text = st.session_state.nda_text or ""
    with st.expander("📄 Read Full NDA (required before signing)", expanded=True):
        st.text_area(
            "NDA",
            nda_text,
            height=450,
            disabled=True,
            label_visibility="collapsed",
        )

    nda_pdf_path = st.session_state.nda_pdf_path
    if nda_pdf_path and Path(nda_pdf_path).exists():
        with open(nda_pdf_path, "rb") as fh:
            st.download_button(
                "📥 Download NDA PDF",
                fh,
                file_name="nda-unsigned.pdf",
                mime="application/pdf",
            )

    st.divider()
    st.subheader("📷 Photo Verification")
    st.write("🔒 **SOC 2 Security Compliance**: Please capture a live photo verification using your webcam:")
    photo = st.camera_input("📸 Capture Photo Verification", label_visibility="collapsed")
    
    photo_file = None
    if photo is None:
        st.caption("No working webcam? Upload a photo instead:")
        photo_file = st.file_uploader("Upload Verification Photo", type=["png", "jpg", "jpeg"])
        
    captured_photo = photo or photo_file

    st.subheader("✍️ Electronic Signature")
    consent = st.checkbox(
        "I have carefully read and understood this Non-Disclosure Agreement. "
        "I consent to sign electronically. I acknowledge that my electronic signature "
        "is legally binding and has the same effect as a handwritten signature.",
        key="nda_consent",
    )
    signature_name = st.text_input(
        "Type your **full legal name** as your signature:",
        placeholder="e.g. Priya Sharma",
        key="sig_name",
    )

    ready = consent and signature_name.strip() and captured_photo is not None

    if not consent:
        st.info("Please read and accept the NDA above and check the consent box to enable the signature field.")
    
    if consent and not signature_name.strip():
        st.info("Type your full legal name to proceed.")
        
    if consent and signature_name.strip() and captured_photo is None:
        st.info("Capture a photo using your webcam or upload a photo to enable the submit button.")

    if ready:
        if st.button("✅ Sign NDA & Submit", type="primary"):
            with st.spinner("Capturing audit trail and generating signed NDA…"):
                try:
                    nda_pdf_path_obj = Path(nda_pdf_path)
                    photo_bytes = captured_photo.getvalue()
                    emp_id = st.session_state.emp_id

                    if MOCK_MODE:
                        # Save photo locally
                        d = get_emp_dir(emp_id)
                        (d / "photo.jpg").write_bytes(photo_bytes)

                        audit_trail, signed_path = process_signing_mock(
                            emp_id,
                            nda_text,
                            nda_pdf_path_obj,
                            signature_name.strip(),
                        )
                    else:
                        import boto3
                        s3 = boto3.client("s3")
                        
                        # Upload photo to S3
                        s3.put_object(
                            Bucket=BUCKET_NAME,
                            Key=f"employees/{emp_id}/photo.jpg",
                            Body=photo_bytes,
                            ContentType="image/jpeg",
                        )

                        hash_before = sha256_file(nda_pdf_path_obj)
                        audit_trail = {
                            "emp_id": emp_id,
                            "signer_name": signature_name.strip(),
                            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "source_ip": get_client_ip(),
                            "user_agent": "Attest-Streamlit-Portal/1.0",
                            "consent": True,
                            "signature_method": "typed-name",
                            "document_hash_before": hash_before,
                            "document_hash_after": None,
                        }
                        tmp = Path(f"/tmp/{emp_id}")
                        tmp.mkdir(exist_ok=True)
                        signed_path = tmp / "signed-nda.pdf"
                        render_signed_nda_pdf(nda_text, signature_name.strip(), audit_trail, signed_path)
                        audit_trail["document_hash_after"] = sha256_file(signed_path)

                        s3.put_object(
                            Bucket=BUCKET_NAME,
                            Key=f"employees/{emp_id}/nda-audit-trail.json",
                            Body=json.dumps(audit_trail, indent=2).encode(),
                            ContentType="application/json",
                        )
                        s3.put_object(
                            Bucket=BUCKET_NAME,
                            Key=f"employees/{emp_id}/signed-nda.pdf",
                            Body=signed_path.read_bytes(),
                            ContentType="application/pdf",
                        )

                    st.session_state.audit_trail = audit_trail
                    st.session_state.signed_nda_path = str(signed_path)
                    st.session_state.step = "approve"
                    st.rerun()

                except Exception as exc:
                    st.error(f"Signing failed: {exc}")
                    st.exception(exc)


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
        df = pd.DataFrame(grants)[
            ["permission_name", "policy_arn", "granted_at", "approved_by", "mock"]
        ]
        df.columns = ["Permission", "Policy ARN", "Granted At", "Approved By", "Mock?"]
        st.dataframe(df, use_container_width=True)

    st.subheader("📥 Download Evidence Files")

    if MOCK_MODE:
        # Local filesystem download
        d = get_emp_dir(st.session_state.emp_id)
        file_map = {
            "offer-letter.pdf":       ("Offer Letter",              "application/pdf"),
            "employee.json":          ("Extracted Employee Data",   "application/json"),
            "nda-unsigned.pdf":       ("Unsigned NDA",              "application/pdf"),
            "signed-nda.pdf":         ("Signed NDA",                "application/pdf"),
            "nda-audit-trail.json":   ("E-Signature Audit Trail",   "application/json"),
            "photo.jpg":              ("Verification Photo (JPG)",  "image/jpeg"),
            "access-granted.csv":     ("Access Grant Record (CSV)", "text/csv"),
            "aws-access-credentials.csv": ("AWS Credentials (CSV)", "text/csv"),
            "onboarding-report.pdf":  ("Compliance Report (PDF)",   "application/pdf"),
            "evidence-index.json":    ("Evidence Index",            "application/json"),
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
            "offer-letter.pdf":       ("Offer Letter",              "application/pdf"),
            "employee.json":          ("Extracted Employee Data",   "application/json"),
            "nda-unsigned.pdf":       ("Unsigned NDA",              "application/pdf"),
            "signed-nda.pdf":         ("Signed NDA",                "application/pdf"),
            "nda-audit-trail.json":   ("E-Signature Audit Trail",   "application/json"),
            "photo.jpg":              ("Verification Photo (JPG)",  "image/jpeg"),
            "access-granted.csv":     ("Access Grant Record (CSV)", "text/csv"),
            "aws-access-credentials.csv": ("AWS Credentials (CSV)", "text/csv"),
            "onboarding-report.pdf":  ("Compliance Report (PDF)",   "application/pdf"),
            "evidence-index.json":    ("Evidence Index",            "application/json"),
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
else:
    st.error(f"Unknown step: {_step!r}")
    st.session_state.step = "upload"
    st.rerun()
