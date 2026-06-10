# 🛡️ Attest — SOC 2 Onboarding Evidence Automation

Automated employee onboarding pipeline that handles offer letter processing, NDA + policy
e-signatures, tech lead approval, real IAM user provisioning, and full SOC 2 evidence
collection — all in one system.

---

## Live AWS Environment (Current State)

| Resource | Value |
|---|---|
| **AWS Account** | `669167971016` |
| **Region** | `us-east-1` |
| **S3 Evidence Vault** | `attest-vault-669167971016` |
| **Approval API** | `https://auq93txerd.execute-api.us-east-1.amazonaws.com/approve` |
| **GitHub Repo** | `Kavyvachhani/soc_automation` |
| **IAM Path (managed users)** | `/attest-managed/` |

### Lambda Functions (deployed, active)

| Function | Trigger | Purpose |
|---|---|---|
| `attest-offer-processor` | S3 `offer-letter.pdf` created | Extract employee data → generate NDA PDF |
| `attest-signed-processor` | S3 `signed-nda.pdf` created | Create approval token → dispatch to GitHub |
| `attest-approval-handler` | API Gateway GET `/approve` | Create IAM user → generate evidence → write S3 |

---

## Full Flow (How It Works)

```
Employee                Portal                  AWS / GitHub
─────────               ──────                  ────────────
Upload offer letter ──► S3 put offer-letter.pdf
                        dispatch offer-uploaded ──► offer-processing.yml
                                                    └─► invoke offer-processor Lambda
                                                        └─► employee.json
                                                            nda-content.txt
                                                            nda-unsigned.pdf  (in S3)

Review NDA +
sign 4 policies ──────► render signed-*.pdf (local)
capture selfie          PUT signed-nda.pdf ──────────► S3
                        PUT photo.jpg                   └─► signed-processor Lambda
                        dispatch nda-signed ──────────────► provisioning.yml
                                                            └─► APPROVAL GATE
                                                               (Kavyvachhani reviews)
                                                                     │ Approve
                                                                     ▼
                                                            invoke approval-handler Lambda
                                                            └─► Create IAM user
                                                                Attach SOC2 policies
                                                                Generate 16-char password
                                                                access-granted.csv
                                                                aws-access-credentials.csv
                                                                onboarding-report.pdf
                                                                evidence-index.json  (in S3)

Download evidence ◄──── portal reads from S3
(CSV, PDFs, JSON)
```

---

## Repository Structure

```
attest/
├── .github/workflows/
│   ├── deploy-lambdas.yml      # Auto-deploy Lambdas on lambda/** push
│   ├── offer-processing.yml    # Invoke offer-processor Lambda (repo_dispatch)
│   ├── provisioning.yml        # Approval-gated IAM provisioning
│   └── compliance.yml          # Weekly SOC 2 snapshots (Mondays 06:00 UTC)
│
├── lambda/
│   ├── offer_processor.py      # Extract data from offer letter PDF, fill NDA
│   ├── signed_processor.py     # Verify signed NDA, create approval token, dispatch
│   ├── approval_handler.py     # Validate token, create IAM user, build evidence
│   ├── requirements.txt        # Lambda Python deps (fpdf2, pypdf, anthropic, ...)
│   └── templates/
│       └── nda_template.txt    # NDA template used by Lambda
│
├── portal/
│   ├── app.py                  # Streamlit 4-step UI (upload/sign/approve/done)
│   └── requirements.txt        # Portal Python deps (streamlit, boto3, ...)
│
├── policies/
│   ├── nda_template.txt        # NDA with {{placeholders}}
│   ├── security_policy.md      # Information Security Policy (SOC 2 v2.1)
│   ├── employee_handbook.md    # Employee Handbook v3.2
│   └── acceptable_use.md       # Acceptable Use Policy v1.5
│
├── scripts/
│   ├── provision.py            # Local mock provisioner (used by portal + CLI)
│   ├── deploy_lambdas_direct.py  # Deploy Lambdas from local machine (hotfix)
│   ├── update_lambda_env.py    # Update Lambda env vars (run after token changes)
│   ├── smoke_test.py           # Live end-to-end smoke test against real AWS
│   ├── seed_data.py            # Generate sample PDFs for testing
│   └── deploy_local.py         # Local dev helpers
│
├── terraform/
│   ├── main.tf                 # KMS key, S3 vault, GitHub OIDC, IAM roles
│   ├── lambda.tf               # Lambda functions, S3 notifications, API GW
│   ├── variables.tf            # All variables with descriptions
│   ├── outputs.tf              # Key outputs (ARNs, URLs, bucket names)
│   ├── terraform.tfvars        # Current values (DO NOT commit secrets)
│   └── terraform.tfvars.example
│
├── sample_data/
│   ├── offer-letter.pdf        # Priya Sharma sample offer letter
│   └── offer-letter-kavy.pdf   # Kavy sample offer letter
│
├── catalog.yaml                # Role → access bundle mapping (fresher / experienced)
└── README.md                   # This file
```

---

## GitHub Secrets (already configured)

Go to: `https://github.com/Kavyvachhani/soc_automation/settings/secrets/actions`

| Secret | Value / Notes |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key for `terrafrom_user` |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_REGION` | `us-east-1` |
| `S3_BUCKET` | `attest-vault-669167971016` |
| `PROJECT_NAME` | `attest` |
| `PROJECT_GITHUB_TOKEN` | GitHub PAT with `repo` + `workflow` scope |
| `PROJECT_GITHUB_ORG` | `Kavyvachhani` |
| `ENABLE_REAL_PROVISIONING` | `true` |

### GitHub Environment (already configured)

Go to: `https://github.com/Kavyvachhani/soc_automation/settings/environments`

- Environment name: `provisioning`
- Required reviewer: `Kavyvachhani`
- This gates IAM user creation — nothing provisions until you click Approve

---

## How to Run

### Option A — Local Mock Mode (no AWS needed)

Everything runs on your local filesystem. No cloud, no credentials required.

**Step 1 — Set up Python environment**
```bash
cd /Users/kavy/Desktop/Task/attest

python3 -m venv .venv
source .venv/bin/activate
pip install -r portal/requirements.txt
```

**Step 2 — Launch the portal**
```bash
MOCK_MODE=true streamlit run portal/app.py
```

Portal opens at **http://localhost:8501**

**Step 3 — Run through the flow**
1. Click "Download sample offer letter (Priya Sharma)" → upload it back
2. Click **Process →**
3. In the "Sign NDA & Policies" step:
   - Capture a photo (webcam or upload)
   - Open each of the 4 tabs (NDA, Security Policy, Handbook, Acceptable Use)
   - Check consent → type your name → click Sign for each
4. Click **Submit All Signatures & Proceed to Approval**
5. Enter approver name → click **Approve & Provision Access**
6. Download all evidence files from Step 4

**Step 4 — Check generated files**
```bash
ls -la data/employees/EMP-*/
# offer-letter.pdf, employee.json, nda-unsigned.pdf
# signed-nda.pdf, signed-security.pdf, signed-handbook.pdf, signed-acceptable_use.pdf
# nda-audit-trail.json, photo.jpg
# access-granted.csv, aws-access-credentials.csv
# combined-evidence.pdf, onboarding-report.pdf, evidence-index.json
```

---

### Option B — Live Mode (real AWS)

Uses S3, Lambda, GitHub Actions, real IAM provisioning.

**Step 1 — Set up Python environment**
```bash
cd /Users/kavy/Desktop/Task/attest

python3 -m venv .venv
source .venv/bin/activate
pip install -r portal/requirements.txt
```

**Step 2 — Configure AWS credentials locally**
```bash
export AWS_ACCESS_KEY_ID=<your-key>
export AWS_SECRET_ACCESS_KEY=<your-secret>
export AWS_DEFAULT_REGION=us-east-1
```

**Step 3 — Launch the portal in live mode**
```bash
MOCK_MODE=false \
S3_BUCKET=attest-vault-669167971016 \
PROJECT_GITHUB_TOKEN=<your-pat> \
PROJECT_GITHUB_ORG=Kavyvachhani \
streamlit run portal/app.py
```

**Step 4 — Run through the flow**
1. Upload the offer letter — portal uploads to S3, triggers GitHub workflow
2. Click **Check Status** after ~30 seconds (Lambda extracts data)
3. Sign all 4 documents + capture photo
4. Submit — signed-nda.pdf goes to S3, `signed-processor` Lambda fires, `provisioning` workflow is triggered
5. Go to GitHub Actions → `Provisioning` workflow → click **Review deployments** → **Approve**
6. Lambda creates IAM user, generates all evidence files
7. Portal shows download links for all evidence

---

### Option C — Deploy Lambda Code Changes

When you change any file in `lambda/`, GitHub Actions auto-deploys.

**Via GitHub Actions (automatic)**
```bash
# Just push — deploy-lambdas.yml triggers on lambda/** changes
git add lambda/
git commit -m "fix: ..."
git push origin main
```

**Via local script (immediate, bypasses GitHub Actions)**
```bash
cd /Users/kavy/Desktop/Task/attest

export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>

python3 scripts/deploy_lambdas_direct.py
```

---

### Option D — Update Lambda Environment Variables

When GitHub PAT or other config changes:

```bash
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>

python3 scripts/update_lambda_env.py "ghp_your_new_token_here"
```

---

### Option E — Run Live Smoke Test

Verifies all 3 Lambdas work end-to-end against real AWS:

```bash
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>

python3 scripts/smoke_test.py
```

Expected output: `✅ ALL SMOKE TESTS PASSED`

The test creates `employees/SMOKE-TEST-002/` in S3, creates a real IAM user, verifies all
evidence files, then cleans up. Run it any time to verify the system is healthy.

---

## Access Bundles (catalog.yaml)

| Experience Level | Role | Policies Granted |
|---|---|---|
| 0–2 years | `fresher` | `AmazonS3ReadOnlyAccess`, `AWSCodeCommitReadOnly`, `CloudWatchReadOnlyAccess` |
| 2+ years | `experienced` | `PowerUserAccess`, `AWSCodeCommitPowerUser`, `AmazonEC2ContainerRegistryPowerUser`, `AmazonS3FullAccess` |

Role is auto-detected from the offer letter. Experience keywords (Senior, Lead, Principal, etc.)
and years-of-experience patterns trigger `experienced`. Everything else defaults to `fresher`.

---

## Evidence Files Produced Per Employee

```
employees/{EMP_ID}/
├── offer-letter.pdf              Original uploaded offer letter
├── employee.json                 Extracted data (name, role, team, experience_level)
├── nda-content.txt               Filled NDA plain text
├── nda-unsigned.pdf              Generated NDA PDF (before signing)
├── signed-nda.pdf                Electronically signed NDA
├── signed-security.pdf           Signed Information Security Policy
├── signed-handbook.pdf           Signed Employee Handbook
├── signed-acceptable_use.pdf     Signed Acceptable Use Policy
├── nda-audit-trail.json          E-signature audit trail (IP, timestamp, doc hash)
├── photo.jpg                     Live selfie captured at signing
├── access-granted.csv            IAM policies granted with timestamps
├── aws-access-credentials.csv    IAM username, console URL, access key, temp password
├── combined-evidence.pdf         All-in-one: cover + selfie + audit trail + policy summary
├── onboarding-report.pdf         SOC 2 compliance report with credentials and photo
└── evidence-index.json           Complete index of all evidence files
```

---

## SOC 2 Compliance Controls

| Control | Implementation |
|---|---|
| **CC6.1** Logical access security | IAM users under `/attest-managed/` path with least-privilege policies |
| **CC6.2** New user provisioning | Requires tech lead approval via GitHub Environment gate |
| **CC6.3** Access modification | All changes logged in evidence-index.json |
| **CC7.2** System monitoring | CloudWatch log groups for all 3 Lambdas (90-day retention) |
| **CC9.1** Risk assessment | Fresher vs experienced role catalog with scoped policies |
| **A1.1** Availability | S3 versioning enabled, Lambda managed concurrency |
| **C1.1** Confidentiality | S3 KMS encryption (AES-256), TLS-only bucket policy |
| **P6.1** Privacy notice | NDA + all 3 policies signed electronically with full audit trail |

---

## Password Policy (SOC 2 Compliant)

Generated passwords are always exactly **16 characters** containing:
- 4 uppercase letters
- 4 lowercase letters
- 4 digits
- 4 special characters (`!@#$%^&*()-_=+`)

Characters are shuffled randomly. AWS IAM console enforces password reset on first login.
MFA enrollment is required within 24 hours (documented in onboarding-report.pdf).

---

## Infrastructure (Terraform)

Current `terraform.tfvars`:
```hcl
aws_region                = "us-east-1"
evidence_bucket_name      = "attest-vault-669167971016"
github_org                = "Kavyvachhani"
github_repo               = "soc_automation"
create_oidc_provider      = true
enable_provisioning       = true
enable_real_provisioning  = true
enable_worm               = false
enable_ses                = false
```

To apply infrastructure changes:
```bash
cd terraform

# Export secrets as env vars (never put them in tfvars)
export TF_VAR_github_token="ghp_..."
export TF_VAR_anthropic_api_key="sk-ant-..."

terraform init
terraform plan
terraform apply
```

---

## Troubleshooting

### Lambda not found (ResourceNotFoundException)
Lambda names use dashes: `attest-offer-processor`, `attest-signed-processor`, `attest-approval-handler`.
The GitHub Actions workflow converts underscores to dashes automatically.

### GitHub dispatch not firing (status != 204)
Check that `PROJECT_GITHUB_TOKEN` secret has `repo` + `workflow` scope.
Update Lambda env vars: `python3 scripts/update_lambda_env.py "ghp_new_token"`

### PDF rendering crashes (Character "⚠" not supported)
Helvetica (fpdf2 core font) cannot render emoji. All emoji have been removed from PDF
generation code. If this appears, check `approval_handler.py` and `provision.py` for
any emoji in `pdf.cell()` or `pdf.multi_cell()` calls.

### offer-letter.pdf confidence is 0.4 (regex fallback)
The offer letter text wasn't extracted with enough structure for AI. Set
`ANTHROPIC_API_KEY` in Lambda env vars for higher-confidence extraction:
```bash
python3 scripts/update_lambda_env.py "ghp_token" "sk-ant-anthropic-key"
```
Or update `scripts/update_lambda_env.py` to include the key.

### provisioning workflow stuck at approval gate
Go to: `https://github.com/Kavyvachhani/soc_automation/actions`
Find the `Provisioning` run → click **Review deployments** → **Approve**

### Reset / clean up a test employee
```bash
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
python3 - << 'EOF'
import boto3
iam = boto3.client("iam", region_name="us-east-1")
s3  = boto3.client("s3",  region_name="us-east-1")
username = "priya-sharma-emp-xxxxx"   # change to actual username
# Detach policies, delete keys, delete login, delete user
for p in iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]:
    iam.detach_user_policy(UserName=username, PolicyArn=p["PolicyArn"])
for k in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
    iam.delete_access_key(UserName=username, AccessKeyId=k["AccessKeyId"])
try: iam.delete_login_profile(UserName=username)
except: pass
iam.delete_user(UserName=username)
print(f"Deleted {username}")
EOF
```

---

## Continuing Development

### Key files to edit

| What you want to change | File |
|---|---|
| UI / portal flow | `portal/app.py` |
| NDA content | `policies/nda_template.txt` and `lambda/templates/nda_template.txt` |
| Security / Handbook / AUP policies | `policies/*.md` |
| Access bundles per role | `catalog.yaml` |
| IAM provisioning logic | `lambda/approval_handler.py` → `create_iam_user()` |
| Evidence PDF layout | `lambda/approval_handler.py` → `generate_onboarding_report_pdf()` |
| Combined evidence PDF | `portal/app.py` → `generate_combined_evidence_pdf()` |
| Email notifications | Set `ENABLE_SES=true` + configure `SES_SENDER_EMAIL` + `TECH_LEAD_EMAIL` in Lambda env |
| Add new policy to sign | Add entry to `POLICIES` list in `portal/app.py` and add `.md` to `policies/` |

### After any Lambda code change

```bash
# Option 1 — push to GitHub (auto-deploys via CI)
git push origin main

# Option 2 — deploy directly (faster, good for hotfixes)
python3 scripts/deploy_lambdas_direct.py

# Option 3 — deploy single function
# Edit scripts/deploy_lambdas_direct.py FUNCTIONS dict to only include the one you need
```

### After changing GitHub PAT

```bash
python3 scripts/update_lambda_env.py "ghp_new_token_here"
# Also update PROJECT_GITHUB_TOKEN secret on GitHub:
# https://github.com/Kavyvachhani/soc_automation/settings/secrets/actions
```

---

## Verified Working (Last Smoke Test: 2026-06-10)

```
✅  offer-processor Lambda — extract Priya Sharma from PDF
✅  employee.json, nda-content.txt, nda-unsigned.pdf written to S3
✅  signed-processor Lambda — approval token created
✅  GitHub dispatch nda-signed → provisioning workflow (HTTP 204)
✅  pending-approval.json written to S3
✅  approval-handler Lambda — real IAM user created
✅  SOC 2 policies attached (S3, CodeCommit, CloudWatch)
✅  Console login + 16-char password (reset required on first login)
✅  Programmatic access key generated
✅  access-granted.csv written
✅  aws-access-credentials.csv written (16-char password confirmed)
✅  onboarding-report.pdf written
✅  evidence-index.json written
```
