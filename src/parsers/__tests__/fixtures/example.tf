variable "bucket_name" {
  type        = string
  description = "Name of the S3 bucket"
  default     = "my-test-bucket"
}

variable "environment" {
  type    = string
  default = "dev"
}

resource "aws_s3_bucket" "example" {
  bucket = var.bucket_name
  
  tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id

  versioning_configuration {
    status = "Enabled"
  }
}

output "bucket_arn" {
  value       = aws_s3_bucket.example.arn
  description = "ARN of the S3 bucket"
}
