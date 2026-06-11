# ─── PRODUCTION APPLICATION INFRASTRUCTURE ────────────────────────────────────
# This file defines the core production infrastructure elements to be audited
# for SOC 2 security, confidentiality, availability, and monitoring controls.

# ─── VPC & Network Boundaries (SOC 2 CC6.1 / CC6.2) ───────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "attest-production-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "attest-production-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "attest-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "attest-private-subnet"
  }
}

# ─── Security Groups (SOC 2 CC6.1 / CC6.2) ────────────────────────────────────

# Web application security group (allows HTTP/HTTPS, denies SSH inbound from world)
resource "aws_security_group" "app_sg" {
  name        = "attest-app-security-group"
  description = "Allows secure web traffic and blocks insecure protocols"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS inbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "attest-app-sg"
  }
}

# Database security group (restricted access: only accepts traffic from application)
resource "aws_security_group" "db_sg" {
  name        = "attest-db-security-group"
  description = "Allows database traffic ONLY from application tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow database connections from app security group"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "attest-db-sg"
  }
}

# ─── KMS Keys for Encryption (SOC 2 C1.1 / CC6.2) ─────────────────────────────

resource "aws_kms_key" "database_key" {
  description             = "KMS Key for RDS Database storage encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = {
    Name = "attest-database-kms-key"
  }
}

# ─── RDS Database (SOC 2 C1.1 / A1.1 / CC6.1) ──────────────────────────────────

resource "aws_db_subnet_group" "db_subnet" {
  name       = "attest-db-subnet-group"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]

  tags = {
    Name = "attest-db-subnet-group"
  }
}

resource "aws_db_instance" "production_db" {
  identifier             = "attest-production-database"
  allocated_storage      = 20
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t3.micro"
  db_name                = "attest_prod"
  username               = "dbadmin"
  password               = "dummySuperSecurePassword123!" # In real deploy, use aws_secretsmanager
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.db_subnet.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  # SOC 2 Safeguards
  storage_encrypted = true
  kms_key_id        = aws_kms_key.database_key.arn
  
  # Ensure the database is not exposed to the public internet
  publicly_accessible = false
  
  # Backup retention for availability / recovery
  backup_retention_period = 7
  deletion_protection     = false # Set to true in real production

  tags = {
    Name = "attest-production-rds"
  }
}

# ─── DynamoDB Table (SOC 2 C1.1 / A1.1) ───────────────────────────────────────

resource "aws_dynamodb_table" "portal_audits" {
  name             = "attest-portal-audit-records"
  billing_mode     = "PAY_PER_REQUEST"
  hash_key         = "audit_id"
  range_key        = "timestamp"

  attribute {
    name = "audit_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  # Point-in-Time-Recovery for SOC 2 availability
  point_in_time_recovery {
    enabled = true
  }

  # Server Side Encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.database_key.arn
  }

  tags = {
    Name = "attest-audit-table"
  }
}

# ─── SQS Queue with Encrypted Storage (SOC 2 CC6.2) ───────────────────────────

resource "aws_sqs_queue" "alert_queue" {
  name                              = "attest-compliance-alerts"
  kms_master_key_id                 = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300
  visibility_timeout_seconds        = 30

  tags = {
    Name = "attest-alerts-queue"
  }
}

# ─── CloudWatch Alerting & Monitoring (SOC 2 CC7.2) ───────────────────────────

resource "aws_cloudwatch_metric_alarm" "db_connections_alarm" {
  alarm_name          = "attest-rds-high-database-connections"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Monitors the number of database connections to detect abuse or scaling issues."
  
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.production_db.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "db_cpu_alarm" {
  alarm_name          = "attest-rds-high-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "Triggers when database CPU usage exceeds 85% for two consecutive evaluation periods."

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.production_db.identifier
  }
}

# ─── Audit Trail Configuration (SOC 2 CC6.1 / CC7.2) ──────────────────────────

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "attest-cloudtrail-logs-${var.project_name}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/prefix/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "production_trail" {
  name                          = "attest-production-audit-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_policy
  ]
}

# ─── Web Application Firewall (SOC 2 CC6.1 / CC6.2) ───────────────────────────

resource "aws_wafv2_web_acl" "main" {
  name        = "attest-production-waf"
  description = "Protects Application Load Balancer from web-based exploits"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "attest-waf-common-rules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "attest-waf-web-acl"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "attest-waf"
  }
}

# ─── Application Load Balancer (SOC 2 CC6.1 / A1.1) ───────────────────────────

resource "aws_lb" "app" {
  name               = "attest-production-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.app_sg.id]
  subnets            = [aws_subnet.public.id, aws_subnet.private.id]

  enable_deletion_protection = false

  tags = {
    Name = "attest-production-alb"
  }
}

resource "aws_lb_target_group" "app" {
  name        = "attest-app-target-group"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/health"
    protocol            = "HTTP"
    port                = "80"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = "80"
  protocol          = "HTTP"

  # Redirect HTTP to HTTPS for SOC 2 CC6.1 Logical Access
  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:${local.account_id}:certificate/mock-cert-uuid"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# ─── ECS Cluster & Fargate Service (SOC 2 A1.1 / CC6.1) ───────────────────────

resource "aws_ecs_cluster" "main" {
  name = "attest-production-ecs-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "attest-ecs-cluster"
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = "attest-production-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = "arn:aws:iam::${local.account_id}:role/ecsTaskExecutionRole"
  task_role_arn            = "arn:aws:iam::${local.account_id}:role/ecsTaskRole"

  container_definitions = jsonencode([{
    name      = "attest-app"
    image     = "${local.account_id}.dkr.ecr.us-east-1.amazonaws.com/attest-app:latest"
    essential = true
    
    portMappings = [{
      containerPort = 80
      hostPort      = 80
      protocol      = "tcp"
    }]

    # SOC 2 Security Safeguards
    readonlyRootFilesystem = true
    user                   = "node"

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/attest-production"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "app" {
  name            = "attest-production-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private.id]
    security_groups  = [aws_security_group.app_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "attest-app"
    container_port   = 80
  }
}

# ─── Secrets Manager (SOC 2 CC6.1 / C1.1) ─────────────────────────────────────

resource "aws_secretsmanager_secret" "db_secret" {
  name                    = "attest/production/db-credentials"
  description             = "Production Database credentials"
  kms_key_id              = aws_kms_key.database_key.id
  recovery_window_in_days = 7

  tags = {
    Name = "attest-db-secret"
  }
}

resource "aws_secretsmanager_secret_version" "db_secret_ver" {
  secret_id     = aws_secretsmanager_secret.db_secret.id
  secret_string = jsonencode({
    username = "dbadmin"
    password = "dummySuperSecurePassword123!"
  })
}

# ─── AWS Backup (SOC 2 A1.1) ──────────────────────────────────────────────────

resource "aws_backup_vault" "production" {
  name        = "attest-production-backup-vault"
  kms_key_arn = aws_kms_key.database_key.arn

  tags = {
    Name = "attest-backup-vault"
  }
}

resource "aws_backup_plan" "production" {
  name = "attest-production-backup-plan"

  rule {
    rule_name         = "daily_backup_rule"
    target_vault_name = aws_backup_vault.production.name
    schedule          = "cron(0 12 * * ? *)"

    lifecycle {
      delete_after = 30
    }
  }

  tags = {
    Name = "attest-backup-plan"
  }
}

# ─── VPC Endpoints for S3 (SOC 2 CC6.1) ───────────────────────────────────────

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "attest-private-route-table"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name = "attest-s3-endpoint"
  }
}

# ─── Route 53 (SOC 2 CC6.1) ───────────────────────────────────────────────────

resource "aws_route53_zone" "production" {
  name = "production.attest-compliance.internal"
  vpc {
    vpc_id = aws_vpc.main.id
  }

  tags = {
    Name = "attest-private-dns-zone"
  }
}

