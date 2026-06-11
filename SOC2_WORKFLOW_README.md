# SOC 2 Daily Compliance Workflow

## Overview

Two GitHub Actions workflows sync together to provide complete SOC 2 compliance automation:

### 1. Technical Evidence Workflow (`attest-technical-auditor.yml`)
**Triggers:** Daily at 00:00 UTC

**Collects:**
- CloudTrail logs (CC6.1, CC7.2)
- IAM users, MFA status, access key rotation (CC6.3)
- S3 encryption, versioning, WORM (A1.1, C1.1)
- Security group exposure (CC6.1)
- CloudWatch alarms (CC7.2)
- Lambda inventory (A1.1)

### 2. Non-Technical Evidence Workflow (`attest-non-tech-auditor.yml`)
**Triggers:** Daily at 00:00 UTC (same time)

**Collects:**
- Employee documents (NDAs, handbooks, policies) (CC8.1, P6.1)
- Security training completion (CC8.2)
- Background checks (CC1.2)

## Synced Execution

Both workflows run **at the same time** (00:00 UTC daily) and:

1. **Collect Evidence** - Technical and non-technical evidence in parallel
2. **Run Compliance Engine** - Consolidates all evidence
3. **Generate Final PDF** - Professional SOC 2 compliance report
4. **Upload to S3** - Storing both evidence and reports
5. **Upload Artifacts** - 90-day retention in GitHub Actions

## Final Output

**PDF Report Location (S3):**
```
s3://attest-vault-669167971016/attest-compliance-auditor/{date}/reports/soc2_compliance_report.pdf
```

**Evidence Location (S3):**
```
s3://attest-vault-669167971016/attest-compliance-auditor/{date}/aws/
s3://attest-vault-669167971016/attest-compliance-auditor/{date}/zoho/
```

## Dependencies

Both workflows require these GitHub secrets:

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | AWS region (us-east-1) |
| `S3_BUCKET` | Evidence vault bucket |
| `PROJECT_NAME` | Project prefix |
| `ZOHO_CLIENT_ID` | Zoho OAuth client ID |
| `ZOHO_CLIENT_SECRET` | Zoho OAuth client secret |
| `ZOHO_REFRESH_TOKEN` | Zoho refresh token |

## Report Generation

The `compliance_engine.py` consolidates evidence from both workflows and:
- Evaluates all SOC 2 controls
- Calculates compliance score
- Identifies failures and warnings
- Generates summary JSON

The `generate_compliance_pdf.py` creates a professional PDF with:
- Cover page
- Executive summary
- Control status matrix
- Infrastructure footprint
- HR governance metrics

## Compliance Score

```
Score >= 90% → COMPLIANT
Score 70-89% → NEEDS IMPROVEMENT
Score < 70% → NON-COMPLIANT
```

## Controls Mapped

| Control ID | Category | Status |
|------------|----------|--------|
| CC6.1 | Security | Technical |
| CC6.2 | Security | Technical |
| CC6.3 | Security | Technical |
| CC7.1 | Security | Technical |
| CC7.2 | Security | Technical |
| CC8.1 | Security | Non-Technical |
| CC8.2 | Security | Non-Technical |
| CC1.2 | Security | Non-Technical |
| A1.1 | Availability | Technical |
| C1.1 | Confidentiality | Technical |
| P6.1 | Privacy | Non-Technical |