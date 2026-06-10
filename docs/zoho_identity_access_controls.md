# Zoho Identity — Non-Technical Access Controls

This document outlines the standard operating procedures (SOPs) for non-technical controls governing access to Zoho Identity, addressing the onboarding and offboarding requirements of **SOC 2 Logical and Physical Access Controls (CC6.1 - CC6.3)**.

---

## 1. Onboarding Process (Access Provisioning)

When a new employee is hired, their identity and access are centrally managed via Zoho Identity.

### 1.1. Request and Approval
*   **Initiation:** HR generates an onboarding ticket within Zoho People upon a signed offer letter.
*   **Approval:** The hiring manager must explicitly approve the baseline access request via the IT ticketing system.
*   **Provisioning SLA:** IT provisions the Zoho Identity account within 48 hours of the employee's start date.

### 1.2. Authentication & Credential Management
*   **SSO Enforcement:** Zoho Identity serves as the Single Sign-On (SSO) IdP for all downstream SaaS applications (AWS, GitHub, internal tools).
*   **MFA Mandate:** Multi-Factor Authentication (MFA) is strictly enforced upon the very first login. Employees cannot bypass MFA setup.
*   **Password Policy:** Passwords must be at least 14 characters, expire every 90 days, and cannot match the previous 5 passwords.

### 1.3. Role-Based Access Control (RBAC)
*   Access is granted on a strict Principle of Least Privilege (PoLP).
*   Baseline groups (e.g., `All Employees`) are assigned by default. Department-specific access (e.g., `Engineering-Prod`) requires secondary Tech Lead approval.

---

## 2. Offboarding Process (Access Revocation)

To prevent unauthorized access post-employment, offboarding must be swift and fully documented.

### 2.1. Initiation
*   HR or the employee's manager triggers an Offboarding request in Zoho People.
*   The request strictly specifies the employee's termination/departure timestamp.

### 2.2. Execution & SLAs
*   **Immediate Revocation:** For involuntary terminations, IT immediately suspends the Zoho Identity account, severing SSO access to all downstream applications simultaneously.
*   **Standard SLA:** For voluntary departures, IT suspends the account at 5:00 PM local time on the employee's final day.
*   **Session Termination:** IT forcibly invalidates all active web and mobile application sessions tied to the Zoho Identity account.

### 2.3. Evidence Collection & Data Archival
*   The employee's Zoho Identity account is **Disabled/Suspended**, *not deleted*. This preserves the audit logs of their past activity for SOC 2 compliance.
*   A deprovisioning report (like the `offboarding-report.pdf`) is attached to the employee's Zoho People record.
*   After 30 days, the user's data vault is backed up to cold storage (S3) and their downstream application seats are formally reclaimed.

---

## 3. Regular Access Reviews (UAR)
*   Quarterly, IT exports active Zoho Identity users and their group mappings.
*   Managers must certify that their direct reports still require the assigned access levels.
*   Unjustified access is revoked within 5 business days of the review.
