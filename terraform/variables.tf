# ─── Core ──────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name used as a prefix for all resource names."
  type        = string
  default     = "attest"
}

variable "evidence_bucket_name" {
  description = "Globally-unique S3 bucket name for the evidence vault."
  type        = string
}

# ─── GitHub ────────────────────────────────────────────────────────────────────

variable "github_org" {
  description = "GitHub organisation or username that owns the repository."
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name (without the org prefix)."
  type        = string
  default     = "attest"
}

variable "create_oidc_provider" {
  description = "Set to false if a GitHub OIDC provider already exists in this AWS account."
  type        = bool
  default     = true
}

variable "existing_oidc_provider_arn" {
  description = "ARN of an existing GitHub OIDC provider. Used when create_oidc_provider = false."
  type        = string
  default     = ""
}

# ─── Secrets ───────────────────────────────────────────────────────────────────

# Add compliance-specific secrets here if needed in the future.
