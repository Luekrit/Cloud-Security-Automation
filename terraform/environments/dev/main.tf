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

  project_name = var.project_name
  environment  = var.environment

  lambda_role_arn = module.iam.lambda_role_arn

  lambda_source_path = "../../../lambda/src/remediate.py"

  tags = local.common_tags
}

module "cloudwatch" {
  source = "../../modules/cloudwatch"

  project_name = var.project_name
  environment  = var.environment

  lambda_function_arn = module.lambda.lambda_function_arn

  tags = local.common_tags
}
