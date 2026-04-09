# Terraform fixture with properly configured resources
# Expected findings: 0

# Properly configured S3 bucket - private, encrypted, versioned
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

# Least-privilege IAM policy
resource "aws_iam_policy" "readonly_policy" {
  name = "readonly-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
      }
    ]
  })
}

# Restricted security group - SSH from specific IP only
resource "aws_security_group" "restricted_ssh" {
  name        = "allow-ssh-office"
  description = "Allow SSH from office IP only"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# Encrypted EBS volume
resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}

# Properly configured CloudTrail
resource "aws_cloudtrail" "enabled_trail" {
  name                          = "enabled-trail"
  s3_bucket_name                = "my-cloudtrail-bucket"
  enable_logging                = true
  enable_log_file_validation    = true
  is_multi_region_trail         = true
}

# Private RDS instance with encryption
resource "aws_db_instance" "private_encrypted_db" {
  identifier           = "private-database"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "secure-password-from-secrets-manager"
  publicly_accessible  = false
  storage_encrypted    = true
  kms_key_id           = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}

# EKS cluster with private endpoint enabled
resource "aws_eks_cluster" "private_cluster" {
  name     = "private-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids              = ["subnet-12345678", "subnet-87654321"]
    endpoint_public_access  = true
    endpoint_private_access = true
  }
}
