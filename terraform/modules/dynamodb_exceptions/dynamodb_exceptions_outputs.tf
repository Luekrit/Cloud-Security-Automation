output "table_name" {
  description = "Name of the DynamoDB exception table."
  value       = aws_dynamodb_table.this.name
  # Feeds lambda_global's EXCEPTION_TABLE_NAME environment variable - this
  # is how remediate.py knows which table to read.
}

output "table_arn" {
  description = "ARN of the DynamoDB exception table."
  value       = aws_dynamodb_table.this.arn
  # Feeds the IAM module's exception_table_arn input, which scopes the
  # Lambda's dynamodb:GetItem permission to exactly this table - not "any
  # table in the account."
}
