output "event_rule_name" {
  description = "Name of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.this.name
}

output "event_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.this.arn
}

output "event_target_id" {
  description = "Target ID for the remediation Lambda target"
  value       = aws_cloudwatch_event_target.lambda.target_id
}