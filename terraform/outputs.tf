# ─── S3 / KMS ─────────────────────────────────────────────────────────────────

output "evidence_bucket_name" {
  description = "Name of the S3 evidence vault bucket."
  value       = aws_s3_bucket.vault.id
}

output "evidence_bucket_arn" {
  description = "ARN of the S3 evidence vault bucket."
  value       = aws_s3_bucket.vault.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used to encrypt vault objects."
  value       = aws_kms_key.vault.arn
}

output "kms_key_alias" {
  description = "KMS key alias."
  value       = aws_kms_alias.vault.name
}

# ─── IAM ──────────────────────────────────────────────────────────────────────

output "github_actions_role_arn" {
  description = "ARN of the IAM role assumed by GitHub Actions via OIDC."
  value       = aws_iam_role.github_actions.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub OIDC identity provider (created or existing)."
  value       = local.oidc_provider_arn
}


