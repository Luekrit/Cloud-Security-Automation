locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

module "iam" {
  source = "../../modules/iam"

  project_name = var.project_name
  environment  = var.environment
  tags         = local.common_tags
}

module "lambda" {
  source = "../../modules/lambda"

  project_name       = var.project_name
  environment        = var.environment
  lambda_role_arn    = module.iam.lambda_execution_role_arn
  lambda_source_path = "../../../lambda/src/remediate.py"
  tags               = local.common_tags
}

module "cloudtrail_logs_bucket" {
  source = "../../modules/s3"

  bucket_name = "${var.project_name}-${var.environment}-cloudtrail-logs"
  tags        = local.common_tags
}

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  project_name   = var.project_name
  environment    = var.environment
  s3_bucket_name = module.cloudtrail_logs_bucket.bucket_name
  tags           = local.common_tags
}

module "eventbridge" {
  source = "../../modules/eventbridge"

  project_name        = var.project_name
  environment         = var.environment
  lambda_function_arn = module.lambda.lambda_function_arn

  event_names = [
    "AttachUserPolicy"
  ]

  tags = local.common_tags
}