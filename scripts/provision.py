"""
scripts/provision.py — Access provisioner (mock + real IAM modes)

Usage (CLI):
  python provision.py EMP-ABCD1234 --approver alice --data-dir ./data
  python provision.py EMP-ABCD1234 --approver alice --data-dir ./data --real

Usage (importable):
  from provision import provision
  result = provision("EMP-ABCD1234", "alice-tech-lead", Path("./data"), real=False)

Modes:
  mock (default) — logs what would happen, writes evidence files
  real (--real)  — creates IAM user under attest-managed/* path, attaches policies
"""

import argparse
import csv
import datetime
import json
import sys
from pathlib import Path

import yaml

# ─── Catalog discovery ────────────────────────────────────────────────────────

def find_catalog() -> Path:
    """Walk up from this script's dir to find catalog.yaml."""
    here = Path(__file__).resolve().parent
    for candidate in [here.parent / "catalog.yaml", here / "catalog.yaml"]:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("catalog.yaml not found near scripts/")


# ─── Core provisioning logic ──────────────────────────────────────────────────

def provision(emp_id: str, approver: str, data_dir: Path, real: bool = False) -> dict:
    emp_dir = data_dir / "employees" / emp_id
    emp_json = emp_dir / "employee.json"

    if not emp_json.exists():
        raise FileNotFoundError(
            f"employee.json not found at {emp_json}. "
            "Ensure the offer-letter processing step completed successfully."
        )

    employee_data: dict = json.loads(emp_json.read_text())
    exp_level: str = employee_data.get("experience_level", "fresher")
    role_key: str = "experienced" if exp_level == "experienced" else "fresher"

    catalog: dict = yaml.safe_load(find_catalog().read_text())
    role_cfg: dict = catalog.get("roles", {}).get(role_key, {})
    bundles: list = role_cfg.get("access_bundles", [])

    now_ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── IAM provisioning (real or mock) ──
    iam_result = {"real": real, "policies_attached": []}

    if real:
        iam_result = _real_provision(employee_data, bundles, emp_id, now_ts)
    else:
        iam_result = _mock_provision(employee_data, bundles, emp_id)

    # ── Build grant records ──
    grants = []
    for bundle in bundles:
        grants.append({
            "emp_id": emp_id,
            "employee_name": employee_data.get("name", "Unknown"),
            "role": role_key,
            "permission_id": bundle.get("id", ""),
            "permission_name": bundle.get("name", ""),
            "policy_arn": bundle.get("policy_arn", ""),
            "granted_at": now_ts,
            "approved_by": approver,
            "real_provisioning": str(real).lower(),
        })

    # ── Write access-granted.csv ──
    csv_path = emp_dir / "access-granted.csv"
    if grants:
        with open(csv_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(grants[0].keys()))
            writer.writeheader()
            writer.writerows(grants)
    else:
        csv_path.write_text("emp_id,note\n{emp_id},no_bundles_found\n")
    print(f"\n  Wrote: {csv_path}")

    # ── Write evidence-index.json ──
    evidence_files = _collect_evidence_files(emp_dir)
    evidence_index = {
        "emp_id": emp_id,
        "employee_name": employee_data.get("name", "Unknown"),
        "designation": employee_data.get("designation", "Employee"),
        "team": employee_data.get("team", "Engineering"),
        "role": role_key,
        "approved_by": approver,
        "approved_at": now_ts,
        "provisioned_at": now_ts,
        "real_provisioning": real,
        "iam_result": iam_result,
        "access_bundles": [
            {"id": b["id"], "name": b["name"], "policy_arn": b["policy_arn"]}
            for b in bundles
        ],
        "evidence_files": evidence_files,
        "pipeline_version": "2.0",
    }
    index_path = emp_dir / "evidence-index.json"
    index_path.write_text(json.dumps(evidence_index, indent=2))
    print(f"  Wrote: {index_path}")

    return {
        "employee_name": employee_data.get("name", "Unknown"),
        "role": role_key,
        "access_bundles": bundles,
        "evidence_files": evidence_files,
        "iam_result": iam_result,
    }


# ─── Mock provisioning ───────────────────────────────────────────────────────

def _mock_provision(employee_data: dict, bundles: list, emp_id: str) -> dict:
    """Log what would happen without creating real resources."""
    result = {"real": False, "policies_attached": []}
    for bundle in bundles:
        print(
            f"  [MOCK] Would grant '{bundle.get('name')}' "
            f"({bundle.get('policy_arn', '')}) to {employee_data.get('name')}"
        )
        result["policies_attached"].append(bundle.get("policy_arn", ""))
    return result


# ─── Real IAM provisioning ───────────────────────────────────────────────────

def _real_provision(employee_data: dict, bundles: list, emp_id: str, now_ts: str) -> dict:
    """Create a real IAM user under attest-managed/ and attach policies."""
    import boto3

    iam = boto3.client("iam")
    name = employee_data.get("name", "employee").replace(" ", "-").lower()
    username = f"{name}-{emp_id.lower()}"

    result = {"real": True, "username": username, "path": "/attest-managed/", "policies_attached": [], "console_login": False}

    try:
        iam.create_user(
            Path="/attest-managed/",
            UserName=username,
            Tags=[
                {"Key": "ManagedBy", "Value": "attest"},
                {"Key": "emp_id", "Value": emp_id},
                {"Key": "created_at", "Value": now_ts},
            ],
        )
        print(f"  [IAM] Created user: /attest-managed/{username}")

        for bundle in bundles:
            arn = bundle.get("policy_arn", "")
            if arn:
                iam.attach_user_policy(UserName=username, PolicyArn=arn)
                result["policies_attached"].append(arn)
                print(f"  [IAM] Attached: {bundle.get('name')} ({arn})")

        # Create console login (force password change)
        import secrets
        temp_pass = secrets.token_urlsafe(16) + "!A1"
        iam.create_login_profile(
            UserName=username,
            Password=temp_pass,
            PasswordResetRequired=True,
        )
        result["console_login"] = True
        result["password_reset_required"] = True
        # NOTE: Never email plaintext passwords. The tech lead communicates
        # credentials out-of-band or the employee uses SSO.
        print(f"  [IAM] Console login created (password reset required)")

    except Exception as e:
        result["error"] = str(e)
        print(f"  [IAM] Error: {e}")

    return result


# ─── Evidence helpers ─────────────────────────────────────────────────────────

def _collect_evidence_files(emp_dir: Path) -> list:
    """List all evidence files in the employee directory."""
    expected = [
        "offer-letter.pdf", "employee.json", "nda-content.txt",
        "nda-unsigned.pdf", "signed-nda.pdf", "nda-audit-trail.json",
        "access-granted.csv", "evidence-index.json",
    ]
    return [f for f in expected if (emp_dir / f).exists()] + ["evidence-index.json"]


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Provision access for an onboarded employee."
    )
    parser.add_argument("emp_id", help="Employee ID (e.g. EMP-ABCD1234)")
    parser.add_argument("--approver", default="tech-lead", help="Name/email of the approver")
    parser.add_argument("--data-dir", default="./data", help="Local data directory")
    parser.add_argument("--real", action="store_true", help="Create real IAM users (requires AWS credentials)")
    args = parser.parse_args()

    result = provision(args.emp_id, args.approver, Path(args.data_dir), real=args.real)
    print(f"\n  Done. Provisioned {result['employee_name']} as {result['role']} "
          f"with {len(result['access_bundles'])} bundles.")


if __name__ == "__main__":
    main()
