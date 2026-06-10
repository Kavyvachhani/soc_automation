# Industrility SOC 2 Compliance Automation Prototype

This repository contains the prototype implementation for the Industrility DevSecOps assignment. It demonstrates a lightweight, automated compliance platform capable of collecting both technical and non-technical SOC 2 evidence, validating it against required controls, and securely storing it as audit-ready artifacts.

## Assignment Objectives Achieved

### 1. Automated SOC 2 Evidence Collection via GitHub Workflows
- **Implementation:** The core compliance engine is driven by `.github/workflows/compliance.yml`. 
- **Execution:** Scheduled to run nightly via `cron`, this workflow coordinates the collection of all compliance telemetry and triggers the evaluation engine automatically.

### 2. External System Integration (Zoho People)
- **Implementation:** Non-technical controls (e.g., employee NDAs, handbook acknowledgments, onboarding/offboarding logs) are fetched using `scripts/collect_zoho_evidence.py`.
- **Execution:** The script connects to the Zoho Identity/People API, identifies signed policy documents, and packages the results as verified evidence JSON.

### 3. AWS Infrastructure Evidence
- **Implementation:** Technical controls are validated using `scripts/collect_aws_evidence.py`.
- **Execution:** It audits the AWS environment for critical misconfigurations (e.g., S3 encryption, CloudTrail status, IAM MFA, Access Key rotation) simulating an AuditKit-style check.

### 4. Active Endpoint Pentesting (Shannon AI)
- **Implementation:** Simulated active adversarial testing is conducted using an AI-driven agent framework (`scripts/ai_pentest.py`).
- **Execution:** The Shannon AI agent actively probes the target endpoints for the OWASP Top 10 vulnerabilities during the nightly workflow. The findings are evaluated and injected into the final DevSecOps PDF Report.

### 5. Automated Alerting & Failure Generation
- **Implementation:** Immediate alerting is configured within the `compliance.yml` workflow.
- **Execution:** If the compliance engine (`scripts/compliance_engine.py`) detects missing evidence or a critical compliance failure, it immediately creates a High-Priority `🚨 URGENT` GitHub Incident Issue, assigning it to the security team for rapid triage.

### 6. Secure Artifact Storage (S3 Vault)
- **Implementation:** The evidence artifacts are uploaded directly from the CI pipeline to a highly secured AWS S3 Vault.
- **Execution:** The Terraform configuration (`terraform/`) enforces WORM (Write Once, Read Many) compliance policies, strict versioning, and Block Public Access controls on the evidence bucket, ensuring the integrity of the audit trail.

### 7. Bonus: Automated Governance within GitHub
- **Implementation:** `governance-controls.yml` and `collect_github_evidence.py`.
- **Execution:** 
  - **Pre-merge Checks:** The governance workflow actively parses Pull Request bodies to enforce ticket tracking (e.g., Jira/Issue links). It also flags unauthorized modifications to CI/CD workflows.
  - **Post-merge Validation:** The nightly evidence collection validates branch protection rules to ensure peer review is enforced on `main` at all times.

## How to Demo

1. **Review Workflows:** Inspect the `.github/workflows/` directory to see the GitHub Actions configuration.
2. **Review Scripts:** See `scripts/` for the Python collection modules and the central `compliance_engine.py`.
3. **Trigger Pipeline:** Run the `Compliance Evidence Collection` workflow manually via the `workflow_dispatch` trigger in the GitHub Actions UI.
4. **View Artifacts:** Once the run completes, download the generated PDFs (Compliance Report & Security Pentest Report) from the Actions Artifacts or via the S3 Bucket.
5. **Simulate a Failure:** Temporarily remove an environment secret or modify the `ai_pentest.py` target to intentionally fail a control. Observe the automated GitHub Issue being generated.

## Architectural Tradeoffs

- **Serverless vs. Centralized:** We opted for a lightweight, serverless, CI/CD-driven execution model (GitHub Actions) rather than a persistent polling service to minimize cost and reduce the compliance scope of the tool itself.
- **Mocked Endpoints:** For the sake of the prototype, certain Zoho HR API calls are simulated via stubbed JSON files, but the integration logic mirrors a production implementation.

---

*Confidential: Prepared for Industrility, Inc.*
