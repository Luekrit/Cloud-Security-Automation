output "state_bucket_name" {
  description = "Terraform remote state S3 bucket name"
  value       = aws_s3_bucket.terraform_state.bucket
}
