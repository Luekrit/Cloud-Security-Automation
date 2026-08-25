output "lambda_function_name" {
  value = module.lambda.lambda_function_name
}

output "lambda_function_arn" {
  value = module.lambda.lambda_function_arn
}

output "lambda_global_function_name" {
  value = module.lambda_global.lambda_function_name
}

output "lambda_global_function_arn" {
  value = module.lambda_global.lambda_function_arn
}

output "exception_table_name" {
  description = "Name of the DynamoDB security exception table."
  value       = module.dynamodb_exceptions_global.table_name
}

output "exception_table_arn" {
  description = "ARN of the DynamoDB security exception table."
  value       = module.dynamodb_exceptions_global.table_arn
}