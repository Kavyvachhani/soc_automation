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

output "lambda_exec_role_arn" {
  description = "ARN of the Lambda execution role."
  value       = aws_iam_role.lambda_exec.arn
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub OIDC identity provider (created or existing)."
  value       = local.oidc_provider_arn
}

# ─── Lambda ───────────────────────────────────────────────────────────────────

output "offer_processor_function_name" {
  description = "Name of the offer-processor Lambda function."
  value       = aws_lambda_function.offer_processor.function_name
}

output "signed_processor_function_name" {
  description = "Name of the signed-processor Lambda function."
  value       = aws_lambda_function.signed_processor.function_name
}

output "approval_handler_function_name" {
  description = "Name of the approval-handler Lambda function."
  value       = aws_lambda_function.approval_handler.function_name
}

# ─── API Gateway ──────────────────────────────────────────────────────────────

output "approval_api_url" {
  description = "Base URL for the approval HTTP API (append /approve?token=...&emp_id=...)."
  value       = aws_apigatewayv2_api.approval.api_endpoint
}

# ─── SES ──────────────────────────────────────────────────────────────────────

output "ses_sender_identity" {
  description = "SES sender email identity ARN (if enabled)."
  value       = var.enable_ses ? aws_ses_email_identity.sender[0].arn : "SES not enabled"
}
