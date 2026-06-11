#!/usr/bin/env python3
"""
scripts/upload_secrets.py — Programmatically upload Zoho secrets to GitHub Actions
"""

import os
import sys
import base64
import requests
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from nacl import encoding, public

# Configuration
GITHUB_TOKEN = os.getenv("PROJECT_GITHUB_TOKEN")
GITHUB_ORG = os.getenv("PROJECT_GITHUB_ORG", "Kavyvachhani")
GITHUB_REPO = os.getenv("GITHUB_REPO", "soc_automation")

SECRETS_TO_UPLOAD = {
    "ZOHO_CLIENT_ID": os.getenv("ZOHO_CLIENT_ID"),
    "ZOHO_CLIENT_SECRET": os.getenv("ZOHO_CLIENT_SECRET"),
    "ZOHO_REFRESH_TOKEN": os.getenv("ZOHO_REFRESH_TOKEN"),
    "ZOHO_DOMAIN": os.getenv("ZOHO_DOMAIN", "in")
}

def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return encoding.Base64Encoder.encode(encrypted).decode("utf-8")

def get_public_key(owner: str, repo: str, token: str) -> dict:
    """Get the public key for the repository actions secrets."""
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        print(f"Error fetching public key: HTTP {res.status_code} - {res.text}")
        sys.exit(1)
    return res.json()

def upload_secret(owner: str, repo: str, token: str, secret_name: str, secret_val: str, key_id: str, public_key: str):
    """Encrypt and upload a secret to GitHub Actions."""
    encrypted_val = encrypt(public_key, secret_val)
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/secrets/{secret_name}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "encrypted_value": encrypted_val,
        "key_id": key_id
    }
    res = requests.put(url, headers=headers, json=payload)
    if res.status_code in (201, 204):
        print(f"✅ Successfully set secret: {secret_name}")
    else:
        print(f"❌ Failed to set secret {secret_name}: HTTP {res.status_code} - {res.text}")

def main():
    if not GITHUB_TOKEN:
        print("Error: PROJECT_GITHUB_TOKEN not found in environment/.env file.")
        sys.exit(1)

    print(f"Targeting Repository: {GITHUB_ORG}/{GITHUB_REPO}")
    
    # 1. Get public key
    print("Fetching repository public key from GitHub...")
    pub_key_data = get_public_key(GITHUB_ORG, GITHUB_REPO, GITHUB_TOKEN)
    key_id = pub_key_data["key_id"]
    public_key = pub_key_data["key"]
    print(f"Successfully fetched public key. Key ID: {key_id}")

    # 2. Upload secrets
    for name, value in SECRETS_TO_UPLOAD.items():
        if not value:
            print(f"⚠️ Skipping {name} (no value found in environment/.env)")
            continue
        print(f"Encrypting and uploading {name}...")
        upload_secret(GITHUB_ORG, GITHUB_REPO, GITHUB_TOKEN, name, value, key_id, public_key)

    print("=== GitHub Secrets Upload Complete ===")

if __name__ == "__main__":
    main()
