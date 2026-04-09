# Terraform fixture with mixed configurations
# Expected findings: 5 (documented below)

# FINDING 1: S3_PUBLIC_ACL - Public bucket
resource "aws_s3_bucket" "mixed_public" {
  bucket = "mixed-public-bucket"
  acl    = "public-read-write"
}

# PASS: Secure private bucket
resource "aws_s3_bucket" "mixed_private" {
  bucket = "mixed-private-bucket"
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

# FINDING 2: IAM_WILDCARD_ACTION - Overly permissive
resource "aws_iam_role_policy" "mixed_admin" {
  name = "mixed-admin-policy"
  role = "some-role"
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

# PASS: Restricted IAM policy
resource "aws_iam_policy" "mixed_restricted" {
  name = "mixed-restricted-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      }
    ]
  })
}

# FINDING 3: EC2_SG_OPEN_SSH - Open SSH
resource "aws_security_group" "mixed_open_ssh" {
  name        = "mixed-open-ssh"
  description = "Allows SSH from anywhere"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# PASS: Restricted security group
resource "aws_security_group" "mixed_restricted" {
  name        = "mixed-restricted"
  description = "Restricted access"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# FINDING 4: RDS_PUBLICLY_ACCESSIBLE - Public database
resource "aws_db_instance" "mixed_public_db" {
  identifier           = "mixed-public-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  publicly_accessible  = true
  storage_encrypted    = true
}

# PASS: Private encrypted RDS
resource "aws_db_instance" "mixed_private_db" {
  identifier           = "mixed-private-db"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  publicly_accessible  = false
  storage_encrypted    = true
}

# FINDING 5: EC2_UNENCRYPTED_EBS
resource "aws_ebs_volume" "mixed_unencrypted" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false
}

# PASS: Encrypted EBS
resource "aws_ebs_volume" "mixed_encrypted" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = true
}
