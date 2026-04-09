# Insecure Infrastructure Demo - Terraform
# This file contains intentional security misconfigurations for demonstration purposes

# ============================================================================
# S3 Bucket - Multiple Vulnerabilities
# ============================================================================

resource "aws_s3_bucket" "public_data" {
  bucket = "company-public-data-bucket"
  acl    = "public-read"  # CRITICAL: Public read access

  tags = {
    Name        = "Public Data Bucket"
    Environment = "Production"
  }
}

# Missing encryption and versioning
resource "aws_s3_bucket" "logs" {
  bucket = "company-logs-bucket"
  # HIGH: No server-side encryption
  # MEDIUM: No versioning enabled

  tags = {
    Name = "Logs Bucket"
  }
}

# ============================================================================
# IAM - Overly Permissive Policies
# ============================================================================

resource "aws_iam_policy" "admin_policy" {
  name        = "admin-full-access"
  description = "Full admin access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # CRITICAL: Wildcard action
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "developer" {
  name = "developer-user"
  path = "/developers/"
}

# ============================================================================
# Security Groups - Open to Internet
# ============================================================================

resource "aws_security_group" "web_server" {
  name        = "web-server-sg"
  description = "Web server security group"
  vpc_id      = "vpc-12345678"

  # CRITICAL: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # CRITICAL: RDP open to the world
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "RDP access"
  }

  # HTTP is acceptable for web servers
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Web Server SG"
  }
}

# ============================================================================
# RDS Database - Insecure Configuration
# ============================================================================

resource "aws_db_instance" "production_db" {
  identifier        = "production-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.medium"
  allocated_storage = 100

  db_name  = "proddb"
  username = "admin"
  password = "changeme123"  # Hardcoded password (should be in secrets manager)

  publicly_accessible    = true    # CRITICAL: Database publicly accessible
  storage_encrypted      = false   # HIGH: No encryption at rest
  skip_final_snapshot    = true

  tags = {
    Name        = "Production Database"
    Environment = "Production"
  }
}

# ============================================================================
# EKS Cluster - Insecure Configuration
# ============================================================================

resource "aws_eks_cluster" "main" {
  name     = "production-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-cluster-role"

  vpc_config {
    subnet_ids              = ["subnet-1234", "subnet-5678"]
    endpoint_public_access  = true    # HIGH: Public endpoint enabled
    endpoint_private_access = false   # Should be true for internal access
  }

  # HIGH: Audit logging not enabled
  # enabled_cluster_log_types should include "audit"

  tags = {
    Name = "Production EKS"
  }
}

# ============================================================================
# CloudTrail - Disabled Logging
# ============================================================================

resource "aws_cloudtrail" "audit_trail" {
  name                          = "audit-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  enable_logging                = false   # CRITICAL: Logging disabled
  is_multi_region_trail         = false   # HIGH: Not multi-region
  enable_log_file_validation    = false   # HIGH: No log validation

  tags = {
    Name = "Audit Trail"
  }
}

# ============================================================================
# EBS Volume - Unencrypted
# ============================================================================

resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false   # HIGH: Unencrypted volume

  tags = {
    Name = "Data Volume"
  }
}

# ============================================================================
# EC2 Instance - Unencrypted Volumes
# ============================================================================

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 50
    encrypted   = false   # HIGH: Unencrypted root volume
  }

  tags = {
    Name = "Web Server"
  }
}
