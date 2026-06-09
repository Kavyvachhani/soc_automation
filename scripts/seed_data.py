#!/usr/bin/env python3
"""
seed_data.py — Generate dummy/sample data for the Attest demo.

Modes:
  generate   (default) — write sample_data/ and policies/ files locally.
  upload     — push NDA template + policies + sample offer letter to S3 vault.

Usage:
  python scripts/seed_data.py
  python scripts/seed_data.py --mode upload --bucket my-vault-bucket
"""

import argparse
import datetime
import io
import os
import sys
from pathlib import Path


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe(s: str) -> str:
    return str(s).encode("latin-1", errors="replace").decode("latin-1")


def make_pdf_bytes(title: str, sections: list[tuple[str, str]]) -> bytes:
    """
    Create a simple multi-section PDF.
    sections: list of (heading, body_text) tuples.
    Returns raw PDF bytes.
    """
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos

    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 14, text=_safe(title), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    for heading, body in sections:
        if heading:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10, text=_safe(heading), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=10)
        if body:
            for line in body.split("\n"):
                pdf.multi_cell(0, 6, text=_safe(line), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)

    return bytes(pdf.output())


# ─── Offer letter ─────────────────────────────────────────────────────────────

OFFER_LETTER_SECTIONS = [
    (
        "",
        """\
Attest Corporation
123 Innovation Drive, Suite 400
San Francisco, CA 94105

{date}

Priya Sharma
42 Maple Street
Bengaluru, Karnataka 560001
India
""",
    ),
    (
        "",
        """\
Dear Priya Sharma,

We are delighted to extend an offer of employment for the position of Software Engineer
in our Platform team at Attest Corporation. This letter confirms the key terms of your offer.
""",
    ),
    (
        "Position Details",
        """\
Position:         Software Engineer
Team:             Platform
Department:       Engineering
Employment Type:  Full-Time
Start Date:       July 1, 2026
Reporting To:     Engineering Manager, Platform Team
Location:         Bengaluru, India (Hybrid — 3 days on-site per week)
""",
    ),
    (
        "Experience & Level",
        """\
You are joining as an experienced engineer with over 4 years of industry experience in
distributed systems and platform infrastructure. Your designation reflects your prior
experience and the scope of the role.
""",
    ),
    (
        "Compensation",
        """\
Base Salary:  INR 24,00,000 per annum (paid monthly)
Joining Bonus: INR 1,50,000 (paid with first salary, recoverable if you leave within 1 year)
Annual Bonus:  Up to 15% of base salary (performance-based)
Stock Options: 800 RSUs vesting over 4 years (25% cliff at 1 year, monthly thereafter)
""",
    ),
    (
        "Benefits",
        """\
- Comprehensive health insurance for employee, spouse, and two children
- Annual training budget: USD 2,000
- 20 days paid annual leave + 10 sick days + public holidays
- Internet and home-office equipment allowance: INR 60,000 one-time
- Employee assistance programme (EAP)
""",
    ),
    (
        "Conditions of Employment",
        """\
This offer is contingent upon:
  1. Successful completion of a background verification check.
  2. Submission of all required documents before your start date.
  3. Signing the Non-Disclosure and Confidentiality Agreement.
  4. Signing the Employee Handbook Acknowledgement.

Please sign and return a copy of this letter to confirm your acceptance no later than
June 20, 2026. Should you have any questions, please contact hr@attest.io.
""",
    ),
    (
        "",
        """\
We are excited to have you join the Attest team and look forward to your contributions.

Sincerely,

John Smith
Head of Engineering
Attest Corporation
john.smith@attest.io | +1-415-555-0100

___________________________
Accepted by: Priya Sharma
Date: ____________________
""",
    ),
]


def generate_offer_letter(
    name: str,
    designation: str,
    team: str,
    experience_text: str,
    output_path: Path,
) -> None:
    today = datetime.date.today().strftime("%B %d, %Y")
    
    sections = [
        (
            "",
            f"""\
Attest Corporation
123 Innovation Drive, Suite 400
San Francisco, CA 94105

{today}

{name}
42 Maple Street
Bengaluru, Karnataka 560001
India
""",
        ),
        (
            "",
            f"""\
Dear {name},

We are delighted to extend an offer of employment for the position of {designation}
in our {team} team at Attest Corporation. This letter confirms the key terms of your offer.
""",
        ),
        (
            "Position Details",
            f"""\
Position:         {designation}
Team:             {team}
Department:       Engineering
Employment Type:  Full-Time
Start Date:       July 1, 2026
Reporting To:     Engineering Manager, {team} Team
Location:         Bengaluru, India (Hybrid — 3 days on-site per week)
""",
        ),
        (
            "Experience & Level",
            experience_text,
        ),
        (
            "Compensation",
            """\
Base Salary:  INR 24,00,000 per annum (paid monthly)
Joining Bonus: INR 1,50,000 (paid with first salary, recoverable if you leave within 1 year)
Annual Bonus:  Up to 15% of base salary (performance-based)
Stock Options: 800 RSUs vesting over 4 years (25% cliff at 1 year, monthly thereafter)
""",
        ),
        (
            "Benefits",
            """\
- Comprehensive health insurance for employee, spouse, and two children
- Annual training budget: USD 2,00,0
- 20 days paid annual leave + 10 sick days + public holidays
- Internet and home-office equipment allowance: INR 60,000 one-time
- Employee assistance programme (EAP)
""",
        ),
        (
            "Conditions of Employment",
            f"""\
This offer is contingent upon:
  1. Successful completion of a background verification check.
  2. Submission of all required documents before your start date.
  3. Signing the Non-Disclosure and Confidentiality Agreement.
  4. Signing the Employee Handbook Acknowledgement.

Please sign and return a copy of this letter to confirm your acceptance no later than
June 20, 2026. Should you have any questions, please contact hr@attest.io.
""",
        ),
        (
            "",
            f"""\
We are excited to have you join the Attest team and look forward to your contributions.

Sincerely,

John Smith
Head of Engineering
Attest Corporation
john.smith@attest.io | +1-415-555-0100

___________________________
Accepted by: {name}
Date: ____________________
""",
        ),
    ]

    filled_sections = []
    for heading, body in sections:
        filled_sections.append((heading, body))

    pdf_bytes = make_pdf_bytes("OFFER LETTER", filled_sections)
    output_path.write_bytes(pdf_bytes)
    print(f"  Generated: {output_path}")


# ─── Policy acknowledgement PDFs ──────────────────────────────────────────────

def generate_signed_ack(
    policy_name: str,
    employee_name: str,
    output_path: Path,
) -> None:
    today = datetime.date.today().strftime("%B %d, %Y")
    sections = [
        (
            "Policy Acknowledgement",
            f"""\
Policy:        {policy_name}
Employee:      {employee_name}
Acknowledged:  {today}
Method:        Electronic signature via Attest Onboarding Portal
""",
        ),
        (
            "Declaration",
            f"""\
I, {employee_name}, confirm that I have read, understood, and agree to comply with the
{policy_name} of Attest Corporation, effective as of the date above.

I acknowledge that non-compliance may result in disciplinary action up to and including
termination of employment.
""",
        ),
        (
            "Signature",
            f"""\
Signed (electronic):  {employee_name}
Timestamp (UTC):      {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}
Document Hash:        [captured at time of signing by the Attest portal]

This is a system-generated acknowledgement record.
""",
        ),
    ]
    pdf_bytes = make_pdf_bytes(f"{policy_name} — Acknowledgement", sections)
    output_path.write_bytes(pdf_bytes)
    print(f"  Generated: {output_path}")


# ─── Main generation logic ────────────────────────────────────────────────────

def generate_all(repo_root: Path) -> None:
    sample_dir = repo_root / "sample_data"
    sample_dir.mkdir(exist_ok=True)

    print("\n[seed_data] Generating offer letters...")
    # 1. DevOps Kavy (Experienced)
    generate_offer_letter(
        name="Kavy Vachhani",
        designation="Senior DevOps Engineer",
        team="DevOps",
        experience_text="You are joining as an experienced engineer with over 5 years of experience in distributed systems, cloud computing, and DevOps practices.",
        output_path=sample_dir / "offer-letter-kavy.pdf",
    )
    # 2. Priya Intern (Fresher)
    generate_offer_letter(
        name="Priya",
        designation="Intern",
        team="Platform",
        experience_text="You are joining as a fresher intern to gain industry experience.",
        output_path=sample_dir / "offer-letter-priya.pdf",
    )
    # 3. Default Priya Sharma (Experienced - software engineer)
    generate_offer_letter(
        name="Priya Sharma",
        designation="Software Engineer",
        team="Platform",
        experience_text="You are joining as an experienced engineer with over 4 years of industry experience.",
        output_path=sample_dir / "offer-letter.pdf",
    )

    print("\n[seed_data] Generating policy acknowledgement PDFs...")
    policies = [
        ("Employee Handbook", "signed-handbook-ack.pdf"),
        ("Information Security Policy", "signed-security-policy-ack.pdf"),
        ("Acceptable Use Policy", "signed-acceptable-use-ack.pdf"),
        ("Non-Disclosure Agreement", "signed-nda-sample.pdf"),
    ]
    for policy_name, filename in policies:
        generate_signed_ack(
            policy_name=policy_name,
            employee_name="Priya Sharma",
            output_path=sample_dir / filename,
        )

    print("\n[seed_data] All sample files generated.")
    print(f"  Location: {sample_dir.resolve()}")


# ─── Upload mode ──────────────────────────────────────────────────────────────

def upload_to_s3(repo_root: Path, bucket: str) -> None:
    import boto3

    s3 = boto3.client("s3")
    uploads = []

    # NDA template
    nda_tpl = repo_root / "policies" / "nda_template.txt"
    if nda_tpl.exists():
        uploads.append((nda_tpl, "templates/nda_template.txt", "text/plain"))

    # Markdown policies
    for md_file in (repo_root / "policies").glob("*.md"):
        uploads.append((md_file, f"policies/{md_file.name}", "text/markdown"))

    # Sample offer letters
    for offer_file in (repo_root / "sample_data").glob("offer-letter*.pdf"):
        uploads.append((offer_file, f"sample_data/{offer_file.name}", "application/pdf"))

    for local_path, s3_key, content_type in uploads:
        s3.upload_file(
            str(local_path),
            bucket,
            s3_key,
            ExtraArgs={"ContentType": content_type},
        )
        print(f"  Uploaded: s3://{bucket}/{s3_key}")

    print(f"\n[seed_data] Upload complete ({len(uploads)} files).")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Attest seed data generator.")
    parser.add_argument(
        "--mode",
        choices=["generate", "upload"],
        default="generate",
        help="'generate' creates local files; 'upload' pushes them to S3.",
    )
    parser.add_argument("--bucket", default=os.environ.get("S3_BUCKET", ""))
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).parent.parent),
        help="Path to repo root (default: parent of scripts/).",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()

    if args.mode == "generate":
        generate_all(repo_root)
    elif args.mode == "upload":
        if not args.bucket:
            print("ERROR: --bucket is required for upload mode (or set S3_BUCKET env var).")
            sys.exit(1)
        # Ensure files exist first
        generate_all(repo_root)
        print(f"\n[seed_data] Uploading to s3://{args.bucket}/ ...")
        upload_to_s3(repo_root, args.bucket)


if __name__ == "__main__":
    main()
