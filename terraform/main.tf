terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = var.project_name
      ManagedBy   = "terraform"
      Environment = "production"
    }
  }
}

# ─── Data sources ─────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # Resolve OIDC provider ARN — either create new or use existing
  oidc_provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : var.existing_oidc_provider_arn
}

# ─── KMS key — evidence vault ────────────────────────────────────────────────
#
# NOTE: The KMS policy grants to the root account only. Lambda and GitHub Actions
# roles get key-usage via their own IAM policies — no circular dependency.

resource "aws_kms_key" "vault" {
  description             = "${var.project_name} evidence vault encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowRootFullControl"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "vault" {
  name          = "alias/${var.project_name}-vault"
  target_key_id = aws_kms_key.vault.key_id
}

# ─── S3 evidence vault ────────────────────────────────────────────────────────

resource "aws_s3_bucket" "vault" {
  bucket        = var.evidence_bucket_name
  force_destroy = false # never auto-delete evidence

  # Object Lock must be enabled at bucket creation; can't change after.
  dynamic "object_lock_configuration" {
    for_each = var.enable_worm ? [1] : []
    content {
      object_lock_enabled = "Enabled"
    }
  }
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.vault.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# TLS-only bucket policy — deny any request that doesn't use HTTPS
resource "aws_s3_bucket_policy" "vault_tls" {
  bucket     = aws_s3_bucket.vault.id
  depends_on = [aws_s3_bucket_public_access_block.vault]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.vault.arn,
          "${aws_s3_bucket.vault.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# WORM: Object Lock configuration (only when enable_worm = true)
resource "aws_s3_bucket_object_lock_configuration" "vault_worm" {
  count  = var.enable_worm ? 1 : 0
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

# ─── GitHub OIDC provider ─────────────────────────────────────────────────────
# Set create_oidc_provider = false if one already exists in this account.

data "tls_certificate" "github_oidc" {
  count = var.create_oidc_provider ? 1 : 0
  url   = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github_oidc[0].certificates[0].sha1_fingerprint]
}

# ─── IAM: GitHub Actions role ─────────────────────────────────────────────────

resource "aws_iam_role" "github_actions" {
  name        = "${var.project_name}-github-actions"
  description = "Assumed by GitHub Actions via OIDC for CI/CD and provisioning."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GitHubOIDC"
        Effect = "Allow"
        Principal = {
          Federated = local.oidc_provider_arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Vault write access for GitHub Actions (Lambda deploys + evidence uploads)
resource "aws_iam_role_policy" "github_vault_write" {
  name = "vault-write"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "VaultReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.vault.arn,
          "${aws_s3_bucket.vault.arn}/*",
        ]
      },
      {
        Sid    = "KMSForVault"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = aws_kms_key.vault.arn
      },
    ]
  })
}

# Read-only compliance collector (IAM/S3/CloudTrail/Config)
resource "aws_iam_role_policy" "github_collector_readonly" {
  name = "collector-readonly"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CollectorReadOnly"
        Effect = "Allow"
        Action = [
          "iam:List*",
          "iam:Get*",
          "s3:List*",
          "s3:GetBucketPolicy",
          "s3:GetBucketVersioning",
          "s3:GetBucketEncryption",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails",
          "cloudtrail:LookupEvents",
          "config:DescribeConfigRules",
          "config:GetComplianceDetailsByConfigRule",
        ]
        Resource = "*"
      },
    ]
  })
}

# Lambda deploy + invoke permission
resource "aws_iam_role_policy" "github_lambda_deploy" {
  name = "lambda-deploy"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:GetFunction",
        ]
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:${var.project_name}-*",
        ]
      },
      {
        Sid    = "LambdaInvoke"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
        ]
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:${var.project_name}-*",
        ]
      },
    ]
  })
}

# Optional: scoped provisioning policy (only attached if enable_provisioning = true)
resource "aws_iam_role_policy" "github_provisioning" {
  count = var.enable_provisioning ? 1 : 0
  name  = "scoped-provisioning"
  role  = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ScopedUserManagement"
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:DeleteUser",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy",
          "iam:ListAttachedUserPolicies",
          "iam:GetUser",
          "iam:TagUser",
          "iam:CreateLoginProfile",
        ]
        Resource = "arn:aws:iam::${local.account_id}:user/attest-managed/*"
      },
    ]
  })
}

# ─── SES — Email notifications (optional) ────────────────────────────────────

resource "aws_ses_email_identity" "sender" {
  count = var.enable_ses ? 1 : 0
  email = var.ses_sender_email
}

resource "aws_ses_email_identity" "tech_lead" {
  count = var.enable_ses && var.tech_lead_email != "" ? 1 : 0
  email = var.tech_lead_email
}

# ─── API Gateway — Approval endpoint ─────────────────────────────────────────
# GET /approve?token=<uuid>&emp_id=<id>&action=approve

resource "aws_apigatewayv2_api" "approval" {
  name          = "${var.project_name}-approval-api"
  protocol_type = "HTTP"
  description   = "HTTP API for tech lead approval of onboarding provisioning."
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.approval.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.project_name}-approval"
  retention_in_days = 30
}

resource "aws_apigatewayv2_integration" "approval_lambda" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.approval_handler.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "approve" {
  api_id    = aws_apigatewayv2_api.approval.id
  route_key = "GET /approve"
  target    = "integrations/${aws_apigatewayv2_integration.approval_lambda.id}"
}
