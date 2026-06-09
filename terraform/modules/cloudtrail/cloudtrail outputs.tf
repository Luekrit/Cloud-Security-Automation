output "trail_name" {
  description = "CloudTrail trail name"
  value       = aws_cloudtrail.this.name
}

output "trail_arn" {
  description = "CloudTrail trail ARN"
  value       = aws_cloudtrail.this.arn
}

output "home_region" {
  description = "CloudTrail home region"
  value       = aws_cloudtrail.this.home_region
}