#!/usr/bin/env python3
"""
Update Lambda environment variables to match the current config.
Run: python3 scripts/update_lambda_env.py
Requires AWS credentials in environment.
"""
import boto3
import json
import os
import sys
from pathlib import Path
try:
    from dotenv import load_dotenv
    # Load local environment variables
    dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(dotenv_path=dotenv_path)
except ImportError:
    pass

REGION = "us-east-1"
BUCKET = os.getenv("S3_BUCKET", "attest-vault-669167971016")
APPROVAL_API_URL = "https://auq93txerd.execute-api.us-east-1.amazonaws.com"
GITHUB_ORG = os.getenv("PROJECT_GITHUB_ORG", "Kavyvachhani")
GITHUB_REPO = os.getenv("GITHUB_REPO", "soc_automation")

# Read GitHub token from env or stdin
github_token = os.getenv("PROJECT_GITHUB_TOKEN", "")
if not github_token:
    if len(sys.argv) >= 2:
        github_token = sys.argv[1]
    else:
        github_token = input("Enter PROJECT_GITHUB_TOKEN (PAT): ").strip()

zoho_id = os.getenv("ZOHO_CLIENT_ID", "")
zoho_secret = os.getenv("ZOHO_CLIENT_SECRET", "")
zoho_refresh = os.getenv("ZOHO_REFRESH_TOKEN", "")
zoho_domain = os.getenv("ZOHO_DOMAIN", "in")

zoho_env = {
    "ZOHO_CLIENT_ID": zoho_id,
    "ZOHO_CLIENT_SECRET": zoho_secret,
    "ZOHO_REFRESH_TOKEN": zoho_refresh,
    "ZOHO_DOMAIN": zoho_domain,
}

client = boto3.client("lambda", region_name=REGION)

functions = {
    "attest-offer-processor": {
        "S3_BUCKET": BUCKET,
        "GITHUB_REPO": GITHUB_REPO,
        "PROJECT_GITHUB_TOKEN": github_token,
        "PROJECT_GITHUB_ORG": GITHUB_ORG,
        **zoho_env,
    },
    "attest-signed-processor": {
        "S3_BUCKET": BUCKET,
        "ENABLE_SES": "false",
        "SES_SENDER_EMAIL": "",
        "TECH_LEAD_EMAIL": "",
        "APPROVAL_API_URL": APPROVAL_API_URL,
        "GITHUB_REPO": GITHUB_REPO,
        "PROJECT_GITHUB_TOKEN": github_token,
        "PROJECT_GITHUB_ORG": GITHUB_ORG,
        **zoho_env,
    },
    "attest-approval-handler": {
        "S3_BUCKET": BUCKET,
        "ENABLE_REAL_PROVISIONING": "true",
        "ENABLE_SES": "false",
        "SES_SENDER_EMAIL": "",
        "TECH_LEAD_EMAIL": "",
        "READONLY_POLICY_ARN": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        "DEVELOPER_POLICY_ARN": "arn:aws:iam::aws:policy/PowerUserAccess",
        "PORTAL_URL": "http://localhost:8501",
        "GITHUB_REPO": GITHUB_REPO,
        "PROJECT_GITHUB_TOKEN": github_token,
        "PROJECT_GITHUB_ORG": GITHUB_ORG,
        **zoho_env,
    },
    "attest-portal-api": {
        "S3_BUCKET": BUCKET,
        "GITHUB_REPO": GITHUB_REPO,
        "PROJECT_GITHUB_TOKEN": github_token,
        "PROJECT_GITHUB_ORG": GITHUB_ORG,
        **zoho_env,
    },
}

for fn_name, env_vars in functions.items():
    print(f"\nUpdating {fn_name} ...")
    try:
        # Get current env vars and merge
        current = client.get_function_configuration(FunctionName=fn_name)
        existing = current.get("Environment", {}).get("Variables", {})
        merged = {**existing, **env_vars}

        client.update_function_configuration(
            FunctionName=fn_name,
            Environment={"Variables": merged},
        )
        print(f"  OK — {len(merged)} env vars set")
        # Print non-sensitive vars for verification
        for k, v in merged.items():
            if "TOKEN" in k or "SECRET" in k or "KEY" in k:
                print(f"  {k} = {'***' if v else '(empty)'}")
            else:
                print(f"  {k} = {v}")
    except Exception as e:
        print(f"  ERROR: {e}")

print("\nDone. All Lambda env vars updated.")
