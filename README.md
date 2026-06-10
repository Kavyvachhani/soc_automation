# Attest — SOC 2 Onboarding Automation

Automated employee onboarding pipeline with SOC 2 evidence collection, DevSecOps security scanning, and cloud-native approvals. No local AWS credentials required — everything runs through a Portal API Lambda.

---

## Live Infrastructure

| Resource | Value |
|---|---|
| AWS Account | `669167971016` |
| Region | `us-east-1` |
| S3 Evidence Vault | `attest-vault-669167971016` |
| Portal API | `https://a5otw1fo40.execute-api.us-east-1.amazonaws.com` |
| Approval API | `https://auq93txerd.execute-api.us-east-1.amazonaws.com` |
| GitHub Repo | `Kavyvachhani/soc_automation` |

### Lambda Functions

| Function | Purpose |
|---|---|
| `attest-portal-api` | Portal backend — all S3 operations via HTTP |
| `attest-offer-processor` | Extract employee data from offer letter PDF |
| `attest-signed-processor` | Create approval token after NDA signed |
| `attest-approval-handler` | Create IAM user + generate SOC 2 evidence |

---

## Running on Your System

### Prerequisites

- Python 3.11+
- Git
- A terminal (macOS / Linux / WSL on Windows)

### Step 1 — Clone and set up Python environment

```bash
git clone https://github.com/Kavyvachhani/soc_automation.git
cd soc_automation

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r portal/requirements.txt
```

### Step 2 — Create .env file

Create a file named `.env` in the project root:

```
PORTAL_API_URL=https://a5otw1fo40.execute-api.us-east-1.amazonaws.com
```

That is the only value required to run the portal locally. No AWS keys needed.

### Step 3 — Start the portals

Open two terminals (or run in background):

```bash
# Terminal 1 — Employee onboarding portal
source .venv/bin/activate
streamlit run portal/app.py

# Terminal 2 — Manager approval portal
source .venv/bin/activate
streamlit run portal/manager_app.py --server.port 8502
```

| Portal | URL |
|---|---|
| Employee onboarding | http://localhost:8501 |
| Manager approvals | http://localhost:8502 |

### Step 4 — Test the full flow

1. **http://localhost:8501** — upload a PDF offer letter
2. Complete the NDA and policy signing steps
3. **http://localhost:8502** — approve the pending request
4. Back on **http://localhost:8501** — download evidence files

---

## Architecture

```
Browser (Streamlit)
      │
      │  HTTPS only — no local AWS credentials
      ▼
API Gateway  https://a5otw1fo40.execute-api.us-east-1.amazonaws.com
      │  ANY /portal/{proxy+}
      ▼
Lambda: attest-portal-api
      │
      ├─ POST /portal/upload-offer      → presigned S3 PUT URL
      ├─ POST /portal/dispatch-offer    → trigger offer-processing workflow
      ├─ GET  /portal/status            → employee data + NDA PDF URL
      ├─ POST /portal/submit-signed     → upload signed docs to S3
      ├─ POST /portal/signed-upload-url → presigned PUT for signed PDFs
      ├─ GET  /portal/evidence          → presigned download URLs
      ├─ POST /portal/approve           → manager approve/reject
      └─ GET  /portal/pending           → list pending approvals

S3: attest-vault-669167971016
      └─ employees/{EMP_ID}/
            ├─ offer-letter.pdf
            ├─ employee.json
            ├─ nda-unsigned.pdf
            ├─ signed-nda.pdf
            ├─ nda-audit-trail.json
            ├─ access-granted.csv
            ├─ aws-access-credentials.csv
            ├─ onboarding-report.pdf
            └─ evidence-index.json
```

**Presigned URL flow (zero local credentials):**
1. Portal calls `POST /portal/upload-offer` → Lambda returns a presigned S3 PUT URL
2. Portal PUTs file directly to that URL (pure HTTPS, no signing needed client-side)
3. Lambda handles all other S3 operations server-side

---

## Repository Structure

```
attest/
├── .env.example                      Template for your .env
├── .github/workflows/
│   ├── setup-portal-api.yml          Deploy attest-portal-api Lambda (run once)
│   ├── deploy-lambdas.yml            Auto-deploy Lambdas on lambda/** push
│   ├── offer-processing.yml          Invoke offer-processor (repository_dispatch)
│   ├── provisioning.yml              Approval-gated IAM provisioning
│   └── devsecops-pipeline.yml        Full security scan → PDF report → S3
│
├── lambda/
│   ├── portal_api.py                 Portal backend (all S3 ops)
│   ├── offer_processor.py            Extract employee data from PDF
│   ├── signed_processor.py           Verify signed NDA, create approval token
│   ├── approval_handler.py           Create IAM user, generate evidence
│   └── requirements.txt
│
├── portal/
│   ├── app.py                        Employee onboarding portal (port 8501)
│   ├── manager_app.py                Manager approval portal (port 8502)
│   └── requirements.txt
│
├── scripts/
│   ├── ai_pentest.py                 Claude-powered OWASP Top 10 analysis
│   └── generate_security_pdf.py      Combine scan results into A4 PDF report
│
├── policies/
│   ├── nda_template.txt
│   ├── security_policy.md
│   ├── employee_handbook.md
│   └── acceptable_use.md
│
├── terraform/                        Infrastructure as Code (S3, Lambda, API GW, KMS)
├── catalog.yaml                      Role → IAM policy bundle mapping
└── sample_data/                      Test offer letter PDFs
```

---

## GitHub Secrets Required

Go to: `https://github.com/Kavyvachhani/soc_automation/settings/secrets/actions`

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `AWS_REGION` | `us-east-1` |
| `S3_BUCKET` | `attest-vault-669167971016` |
| `PROJECT_GITHUB_TOKEN` | GitHub PAT with `repo` + `workflow` scope |
| `ANTHROPIC_API_KEY` | For AI pentester in DevSecOps pipeline |
| `ALERT_EMAIL` | Email for critical security alerts (optional) |
| `SES_SENDER` | Verified SES sender address (optional) |

---

## DevSecOps Pipeline

Triggered on every push, pull request, and daily at midnight UTC.

**Pipeline jobs:**

| Job | Tools | Output |
|---|---|---|
| `sast` | Bandit, Semgrep (OWASP p/python, p/owasp-top-ten) | `bandit.json`, `semgrep.json` |
| `dependencies` | pip-audit, Trivy FS scan | `pip_audit.json`, `trivy-vuln.json` |
| `secrets-scan` | Trivy secrets, Gitleaks, detect-secrets | `trivy-secrets.json`, `detect-secrets-results.json` |
| `ai-pentest` | Claude (OWASP Top 10 analysis) | `ai-pentest.json` |
| `report` | fpdf2 PDF generator | `devsecops-report.pdf` → S3 |

**Report location in S3:**
```
security-reports/{project}/{branch}/{date}-{commit-sha}/
├── devsecops-report.pdf      Full A4 PDF with all findings
├── bandit.json
├── semgrep.json
├── pip_audit.json
├── trivy-vuln.json
├── trivy-secrets.json
├── ai-pentest.json
└── manifest.json             Commit info + run metadata
```

An SES alert email is sent automatically if CRITICAL CVEs or secrets are detected.

---

## Deploying the Portal API Lambda (first-time setup)

If starting fresh on a new AWS account or the Lambda doesn't exist:

1. Set all GitHub Secrets listed above
2. Go to: `https://github.com/Kavyvachhani/soc_automation/actions/workflows/setup-portal-api.yml`
3. Click **Run workflow**
4. Copy the `PORTAL_API_URL` from the workflow output
5. Add it to your `.env` file

---

## SOC 2 Controls

| Control | Implementation |
|---|---|
| CC6.1 Logical access | IAM users under `/attest-managed/` with least-privilege policies |
| CC6.2 New user provisioning | Requires tech lead approval via GitHub Environment gate |
| CC6.3 Access modification | All changes logged in `evidence-index.json` |
| CC7.2 System monitoring | CloudWatch log groups for all Lambdas (90-day retention) |
| CC9.1 Risk assessment | Fresher vs experienced role catalog with scoped policies |
| A1.1 Availability | S3 versioning, Lambda managed concurrency |
| C1.1 Confidentiality | S3 KMS encryption (AES-256), TLS-only bucket policy |
| P6.1 Privacy notice | NDA + 3 policies signed electronically with full audit trail |

---

## Evidence Files Per Employee

```
employees/{EMP_ID}/
├── offer-letter.pdf              Original offer letter
├── employee.json                 Extracted: name, role, team, experience level
├── nda-unsigned.pdf              Generated NDA before signing
├── signed-nda.pdf                Electronically signed NDA
├── signed-security.pdf           Signed Information Security Policy
├── signed-handbook.pdf           Signed Employee Handbook
├── signed-acceptable_use.pdf     Signed Acceptable Use Policy
├── nda-audit-trail.json          E-signature audit trail (IP, timestamp, doc hash)
├── photo.jpg                     Live selfie at signing time
├── access-granted.csv            IAM policies granted with timestamps
├── aws-access-credentials.csv    IAM username, console URL, temp password
├── combined-evidence.pdf         All-in-one SOC 2 evidence package
├── onboarding-report.pdf         Compliance report with credentials
└── evidence-index.json           Index of all evidence with S3 keys
```

---

## Troubleshooting

**Portal shows "Portal API Not Configured"**
Add `PORTAL_API_URL=https://a5otw1fo40.execute-api.us-east-1.amazonaws.com` to `.env` and restart.

**Upload fails with 400 Bad Request**
The S3 bucket uses KMS encryption which requires SigV4. The `attest-portal-api` Lambda must use `signature_version="s3v4"` when generating presigned URLs — already fixed in current code.

**Manager portal shows "Not Configured"**
Same fix — `PORTAL_API_URL` must be in `.env`. The manager portal does not need any AWS credentials.

**Provisioning workflow stuck**
Go to `https://github.com/Kavyvachhani/soc_automation/actions` → find the Provisioning run → click **Review deployments** → **Approve**.

**Lambda not found (ResourceNotFoundException)**
Lambda names use dashes: `attest-offer-processor`, `attest-signed-processor`, `attest-approval-handler`, `attest-portal-api`. Run the `Setup Portal API Lambda` workflow to redeploy.

**GitHub dispatch failing (status != 204)**
Check that `PROJECT_GITHUB_TOKEN` secret has `repo` + `workflow` scope. Update Lambda env: go to AWS Console → Lambda → `attest-offer-processor` → Configuration → Environment variables.

---

## Making Changes

| What to change | File |
|---|---|
| Portal UI / flow | `portal/app.py` |
| Manager portal | `portal/manager_app.py` |
| Portal API routes | `lambda/portal_api.py` |
| NDA content | `policies/nda_template.txt` |
| IAM provisioning logic | `lambda/approval_handler.py` |
| Access bundles per role | `catalog.yaml` |
| Security scan config | `.github/workflows/devsecops-pipeline.yml` |
| PDF report layout | `scripts/generate_security_pdf.py` |
| AI pentester prompt | `scripts/ai_pentest.py` |

After any Lambda change, push to `main` — `deploy-lambdas.yml` auto-deploys all four functions.
