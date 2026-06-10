#!/usr/bin/env python3
"""
scripts/collect_github_evidence.py — GitHub Compliance Evidence Collector

Validates GitHub repository security controls for SOC 2 readiness.
Evidence collected:
  - Branch protection rules
  - Required PR review enforcement
  - Force push restrictions
  - Direct commit restrictions
  - Deployment environment approvals

Usage:
  python scripts/collect_github_evidence.py --repo owner/repo --output /tmp/github_evidence
"""

import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _pass(control_id: str, control: str, evidence: dict) -> dict:
    return {"control_id": control_id, "control": control, "status": "PASS", "evidence": evidence, "collected_at": now_utc()}


def _fail(control_id: str, control: str, evidence: dict, reason: str) -> dict:
    return {"control_id": control_id, "control": control, "status": "FAIL", "evidence": evidence, "reason": reason, "collected_at": now_utc()}


def _warn(control_id: str, control: str, evidence: dict, reason: str) -> dict:
    return {"control_id": control_id, "control": control, "status": "WARN", "evidence": evidence, "reason": reason, "collected_at": now_utc()}


class GitHubAPIClient:
    """Minimal GitHub API client using stdlib only."""

    BASE = "https://api.github.com"

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get(self, path: str) -> dict | list | None:
        url = f"{self.BASE}{path}"
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise RuntimeError(f"GitHub API {path} → {e.code}: {e.read().decode(errors='replace')[:300]}")
        except Exception as e:
            raise RuntimeError(f"GitHub API {path} → {e}")


def collect_branch_protection(client: GitHubAPIClient, repo: str, branch: str = "main") -> list[dict]:
    """CC6.2 — Branch protection rules enforcement."""
    results = []
    data = client.get(f"/repos/{repo}/branches/{branch}/protection")

    if data is None:
        return [_fail("CC6.2", f"Branch Protection ({branch})",
                      {"branch": branch, "repo": repo},
                      f"Branch protection NOT enabled on '{branch}'")]

    # Required reviews
    req_reviews = data.get("required_pull_request_reviews", {})
    min_approvals = req_reviews.get("required_approving_review_count", 0)
    dismiss_stale = req_reviews.get("dismiss_stale_reviews", False)

    if min_approvals >= 1:
        results.append(_pass("CC6.2", "Required PR Reviews",
                             {"branch": branch, "required_approvals": min_approvals,
                              "dismiss_stale": dismiss_stale}))
    else:
        results.append(_fail("CC6.2", "Required PR Reviews",
                             {"branch": branch, "required_approvals": min_approvals},
                             "PR reviews NOT required before merging"))

    # Force push restriction
    allow_force = data.get("allow_force_pushes", {}).get("enabled", True)
    if not allow_force:
        results.append(_pass("CC6.2", "Force Pushes Disabled", {"branch": branch, "force_pushes_allowed": False}))
    else:
        results.append(_fail("CC6.2", "Force Pushes Disabled",
                             {"branch": branch, "force_pushes_allowed": True},
                             "Force pushes are ALLOWED on protected branch"))

    # Direct commit restriction (requires PR)
    allow_direct = data.get("allow_deletions", {}).get("enabled", True)
    enforce_admins = data.get("enforce_admins", {}).get("enabled", False)
    results.append(
        _pass("CC6.2", "Admin Enforcement on Branch",
              {"branch": branch, "enforce_admins": enforce_admins})
        if enforce_admins else
        _warn("CC6.2", "Admin Enforcement on Branch",
              {"branch": branch, "enforce_admins": enforce_admins},
              "Admins can bypass branch protection rules")
    )

    # Required status checks
    req_checks = data.get("required_status_checks", {})
    if req_checks:
        contexts = req_checks.get("contexts", []) or []
        results.append(_pass("CC6.2", "Required Status Checks",
                             {"branch": branch, "checks": contexts, "strict": req_checks.get("strict", False)}))
    else:
        results.append(_warn("CC6.2", "Required Status Checks",
                             {"branch": branch},
                             "No required status checks configured on branch"))

    return results


def collect_repo_settings(client: GitHubAPIClient, repo: str) -> list[dict]:
    """CC6.1 — Repository security settings."""
    results = []
    data = client.get(f"/repos/{repo}")
    if data is None:
        return [_warn("CC6.1", "Repository Settings", {"repo": repo}, "Could not fetch repo settings")]

    # Private repo check
    is_private = data.get("private", False)
    results.append(
        _pass("CC6.1", "Repository Visibility",
              {"repo": repo, "private": is_private, "visibility": data.get("visibility", "unknown")})
        if is_private else
        _warn("CC6.1", "Repository Visibility",
              {"repo": repo, "private": is_private},
              "Repository is PUBLIC — ensure this is intentional")
    )

    # Vulnerability alerts
    vuln = client.get(f"/repos/{repo}/vulnerability-alerts")
    if vuln is not None:  # 204 = enabled, 404 = disabled
        results.append(_pass("CC6.1", "Vulnerability Alerts", {"repo": repo, "enabled": True}))
    else:
        results.append(_warn("CC6.1", "Vulnerability Alerts", {"repo": repo, "enabled": False},
                             "GitHub vulnerability alerts not enabled"))

    return results


def collect_deployment_environments(client: GitHubAPIClient, repo: str) -> list[dict]:
    """CC6.2 — Deployment environment approval gates."""
    results = []
    envs_data = client.get(f"/repos/{repo}/environments")
    if envs_data is None:
        return [_warn("CC6.2", "Deployment Environments", {"repo": repo},
                      "No deployment environments configured")]

    envs = envs_data.get("environments", []) if isinstance(envs_data, dict) else []
    if not envs:
        return [_warn("CC6.2", "Deployment Environments", {"repo": repo},
                      "No deployment environments configured")]

    env_summaries = []
    protected_count = 0
    for env in envs:
        protection_rules = env.get("protection_rules", [])
        has_approval = any(r.get("type") == "required_reviewers" for r in protection_rules)
        if has_approval:
            protected_count += 1
        env_summaries.append({
            "name": env.get("name"),
            "has_approval_gate": has_approval,
            "protection_rules": [r.get("type") for r in protection_rules],
        })

    if protected_count > 0:
        results.append(_pass("CC6.2", "Deployment Approval Gates",
                             {"environments": env_summaries, "protected_count": protected_count}))
    else:
        results.append(_warn("CC6.2", "Deployment Approval Gates",
                             {"environments": env_summaries},
                             "No deployment environments have approval gates"))

    return results


def collect_actions_secrets(client: GitHubAPIClient, repo: str) -> dict:
    """CC6.3 — GitHub Actions secrets inventory (names only, not values)."""
    secrets_data = client.get(f"/repos/{repo}/actions/secrets")
    if secrets_data is None:
        return _warn("CC6.3", "GitHub Actions Secrets", {"repo": repo}, "Could not list secrets")

    secrets = secrets_data.get("secrets", []) if isinstance(secrets_data, dict) else []
    REQUIRED_SECRETS = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "S3_BUCKET"}
    found_names = {s["name"] for s in secrets}
    missing = REQUIRED_SECRETS - found_names

    if not missing:
        return _pass("CC6.3", "Required GitHub Secrets Configured",
                     {"secrets_count": len(secrets), "required_present": sorted(REQUIRED_SECRETS)})
    return _warn("CC6.3", "Required GitHub Secrets Configured",
                 {"secrets_count": len(secrets), "missing": sorted(missing)},
                 f"Missing required secrets: {', '.join(sorted(missing))}")


def collect_workflow_runs(client: GitHubAPIClient, repo: str) -> dict:
    """CC7.2 — Recent workflow execution history."""
    runs_data = client.get(f"/repos/{repo}/actions/runs?per_page=10")
    if runs_data is None:
        return _warn("CC7.2", "Workflow Execution History", {"repo": repo}, "Could not fetch workflow runs")

    runs = runs_data.get("workflow_runs", []) if isinstance(runs_data, dict) else []
    summary = [{
        "name": r.get("name", ""),
        "status": r.get("status", ""),
        "conclusion": r.get("conclusion", ""),
        "created_at": r.get("created_at", ""),
        "run_id": r.get("id"),
    } for r in runs[:10]]

    return _pass("CC7.2", "Workflow Execution History",
                 {"total_recent_runs": len(summary), "runs": summary})


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Collect GitHub SOC 2 compliance evidence")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="owner/repo")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", os.environ.get("PROJECT_GITHUB_TOKEN", "")))
    parser.add_argument("--branch", default="main")
    parser.add_argument("--output", default="/tmp/github_evidence")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--bucket", default=os.environ.get("S3_BUCKET", ""))
    args = parser.parse_args()

    if not args.repo:
        print("ERROR: --repo or GITHUB_REPOSITORY env var required")
        sys.exit(1)
    if not args.token:
        print("ERROR: --token or GITHUB_TOKEN env var required")
        sys.exit(1)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    client = GitHubAPIClient(args.token)
    all_results = []
    failures = []

    print(f"[GitHub Evidence] Collecting compliance evidence for {args.repo}")

    # Branch protection
    for r in collect_branch_protection(client, args.repo, args.branch):
        all_results.append(r)
        if r["status"] == "FAIL":
            failures.append(r["control"])

    # Repo settings
    for r in collect_repo_settings(client, args.repo):
        all_results.append(r)
        if r["status"] == "FAIL":
            failures.append(r["control"])

    # Deployment environments
    for r in collect_deployment_environments(client, args.repo):
        all_results.append(r)
        if r["status"] == "FAIL":
            failures.append(r["control"])

    # Secrets inventory
    secrets_r = collect_actions_secrets(client, args.repo)
    all_results.append(secrets_r)
    if secrets_r["status"] == "FAIL":
        failures.append(secrets_r["control"])

    # Workflow history
    all_results.append(collect_workflow_runs(client, args.repo))

    # Write evidence
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    evidence_file = output_dir / f"github_evidence_{ts}.json"
    manifest = {
        "collector": "collect_github_evidence.py",
        "collected_at": now_utc(),
        "repository": args.repo,
        "branch": args.branch,
        "controls_checked": len(all_results),
        "pass_count": sum(1 for r in all_results if r["status"] == "PASS"),
        "fail_count": sum(1 for r in all_results if r["status"] == "FAIL"),
        "warn_count": sum(1 for r in all_results if r["status"] == "WARN"),
        "failures": failures,
        "results": all_results,
    }
    evidence_file.write_text(json.dumps(manifest, indent=2, default=str))
    latest_file = output_dir / "github_evidence_latest.json"
    latest_file.write_text(json.dumps(manifest, indent=2, default=str))
    print(f"[GitHub Evidence] Written: {evidence_file}")

    if args.upload and args.bucket:
        import boto3
        s3 = boto3.client("s3")
        for fname in [evidence_file, latest_file]:
            key = f"evidence/github/{fname.name}"
            s3.upload_file(str(fname), args.bucket, key,
                           ExtraArgs={"ContentType": "application/json"})
            print(f"[GitHub Evidence] Uploaded: s3://{args.bucket}/{key}")

    print("\n" + "=" * 60)
    print(f"GitHub Compliance Summary — {len(all_results)} controls checked")
    print("=" * 60)
    for r in all_results:
        icon = "✅" if r["status"] == "PASS" else ("❌" if r["status"] == "FAIL" else "⚠️")
        print(f"  {icon} [{r['control_id']}] {r['control']}: {r['status']}")
        if r["status"] in ("FAIL", "WARN"):
            print(f"       → {r.get('reason', '')}")

    if failures:
        print(f"\n❌ COMPLIANCE FAILURES: {', '.join(failures)}")
        sys.exit(1)
    else:
        print("\n✅ All critical GitHub controls passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
