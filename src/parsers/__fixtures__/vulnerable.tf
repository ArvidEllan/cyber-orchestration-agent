# Terraform fixture with intentional security misconfigurations
# Expected findings: 11 total (one per resource)

# S3_PUBLIC_ACL - Public bucket ACL
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}

# S3_NO_ENCRYPTION - Missing server-side encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"
}

# S3_NO_VERSIONING - Missing versioning
resource "aws_s3_bucket" "unversioned_bucket" {
  bucket = "my-unversioned-bucket"
  versioning {
    enabled = false
  }
}

# IAM_WILDCARD_ACTION - Wildcard action policy
resource "aws_iam_policy" "admin_policy" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# EC2_SG_OPEN_SSH - SSH open to 0.0.0.0/0
resource "aws_security_group" "open_ssh" {
  name        = "allow-ssh-all"
  description = "Allow SSH from anywhere"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2_SG_OPEN_RDP - RDP open to 0.0.0.0/0
resource "aws_security_group" "open_rdp" {
  name        = "allow-rdp-all"
  description = "Allow RDP from anywhere"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2_UNENCRYPTED_EBS - Unencrypted EBS volume
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# CLOUDTRAIL_NOT_ENABLED - Logging disabled
resource "aws_cloudtrail" "disabled_trail" {
  name                          = "disabled-trail"
  s3_bucket_name                = "my-cloudtrail-bucket"
  enable_logging                = false
  enable_log_file_validation    = false
}

# RDS_PUBLICLY_ACCESSIBLE - Public RDS instance
resource "aws_db_instance" "public_db" {
  identifier           = "public-database"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  publicly_accessible  = true
}

# RDS_NO_ENCRYPTION - Unencrypted RDS storage
resource "aws_db_instance" "unencrypted_db" {
  identifier           = "unencrypted-database"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  storage_encrypted    = false
}

# EKS_PUBLIC_ENDPOINT - Public-only EKS endpoint
resource "aws_eks_cluster" "public_cluster" {
  name     = "public-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-role"

  vpc_config {
    subnet_ids              = ["subnet-12345678", "subnet-87654321"]
    endpoint_public_access  = true
    endpoint_private_access = false
  }
}
