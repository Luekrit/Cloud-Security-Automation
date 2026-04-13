import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
sns = boto3.client("sns")

DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")

PROTECTED_USERS = {
    "SecurityteamAdmin",
    "terraform-operator",
}

DANGEROUS_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}

SUPPORTED_EVENTS = {
    "AttachUserPolicy",
}


def log_json(level: str, message: str, **kwargs: Any) -> None:
    payload = {
        "message": message,
        **kwargs,
    }

    log_line = json.dumps(payload, default=str)

    if level.upper() == "ERROR":
        logger.error(log_line)
    elif level.upper() == "WARNING":
        logger.warning(log_line)
    else:
        logger.info(log_line)


def get_nested(data: Dict[str, Any], path: list, default: Any = None) -> Any:
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def extract_username_from_arn(arn: Optional[str]) -> Optional[str]:
    if not arn:
        return None

    parts = arn.split("/")
    if len(parts) < 2:
        return None

    return parts[-1]


def parse_cloudtrail_event(event: Dict[str, Any]) -> Dict[str, Optional[str]]:
    detail = event.get("detail", {})

    return {
        "event_name": detail.get("eventName"),
        "event_source": detail.get("eventSource"),
        "event_time": detail.get("eventTime"),
        "aws_region": detail.get("awsRegion"),
        "source_ip": detail.get("sourceIPAddress"),
        "account_id": detail.get("recipientAccountId"),
        "actor_arn": get_nested(detail, ["userIdentity", "arn"]),
        "target_user_name": get_nested(detail, ["requestParameters", "userName"]),
        "policy_arn": get_nested(detail, ["requestParameters", "policyArn"]),
    }


def should_remediate(parsed: Dict[str, Optional[str]]) -> Tuple[bool, str]:
    event_name = parsed.get("event_name")
    target_user_name = parsed.get("target_user_name")
    policy_arn = parsed.get("policy_arn")
    actor_arn = parsed.get("actor_arn")
    actor_name = extract_username_from_arn(actor_arn)

    if event_name not in SUPPORTED_EVENTS:
        return False, f"Unsupported event: {event_name}"

    if not actor_arn:
        return False, "Missing actor ARN"

    if not target_user_name:
        return False, "Missing target user name"

    if target_user_name in PROTECTED_USERS:
        return False, f"Target user is protected: {target_user_name}"

    if actor_name and target_user_name == actor_name:
        return False, "Actor and target user are the same"

    if not policy_arn:
        return False, "Missing policy ARN"

    if policy_arn not in DANGEROUS_POLICIES:
        return False, f"Policy not in remediation scope: {policy_arn}"

    return True, "Approved for remediation"


def publish_sns_alert(subject: str, message: Dict[str, Any]) -> Dict[str, Any]:
    if not SNS_TOPIC_ARN:
        return {
            "status": "skipped",
            "reason": "SNS_TOPIC_ARN not configured",
        }

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message, default=str, indent=2),
        )
        return {
            "status": "success",
            "message_id": response.get("MessageId"),
        }
    except ClientError as exc:
        return {
            "status": "error",
            "error": str(exc),
        }


def detach_user_policy(user_name: str, policy_arn: str) -> Dict[str, Any]:
    try:
        iam.detach_user_policy(
            UserName=user_name,
            PolicyArn=policy_arn,
        )
        return {
            "status": "success",
            "action": "detach_user_policy",
            "user_name": user_name,
            "policy_arn": policy_arn,
        }
    except ClientError as exc:
        return {
            "status": "error",
            "action": "detach_user_policy",
            "user_name": user_name,
            "policy_arn": policy_arn,
            "error": str(exc),
        }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    log_json(
        "INFO",
        "Security detection triggered",
        dry_run=DRY_RUN,
        raw_event=event,
        request_id=getattr(context, "aws_request_id", None),
    )

    try:
        parsed = parse_cloudtrail_event(event)

        log_json(
            "INFO",
            "Parsed event",
            parsed_event=parsed,
        )

        approved, reason = should_remediate(parsed)

        alert_payload = {
            "control": "IAM AdministratorAccess Attachment Detection",
            "severity": "high",
            "dry_run": DRY_RUN,
            "approved_for_remediation": approved,
            "decision_reason": reason,
            "parsed_event": parsed,
        }

        alert_result = publish_sns_alert(
            subject="Cloud Security Automation Alert",
            message=alert_payload,
        )

        log_json(
            "INFO",
            "SNS alert processed",
            sns_result=alert_result,
            parsed_event=parsed,
        )

        if not approved:
            log_json(
                "INFO",
                "No remediation performed",
                reason=reason,
                parsed_event=parsed,
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "No remediation required",
                    "reason": reason,
                    "parsed_event": parsed,
                    "dry_run": DRY_RUN,
                    "sns_result": alert_result,
                }),
            }

        if DRY_RUN:
            simulated = {
                "status": "dry_run",
                "action": "detach_user_policy",
                "user_name": parsed["target_user_name"],
                "policy_arn": parsed["policy_arn"],
            }
            log_json(
                "INFO",
                "Dry run enabled - remediation skipped",
                remediation_result=simulated,
                parsed_event=parsed,
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Dry run only - remediation skipped",
                    "result": simulated,
                    "parsed_event": parsed,
                    "dry_run": DRY_RUN,
                    "sns_result": alert_result,
                }),
            }

        result = detach_user_policy(
            user_name=parsed["target_user_name"],
            policy_arn=parsed["policy_arn"],
        )

        if result["status"] == "success":
            log_json(
                "INFO",
                "Remediation completed",
                remediation_result=result,
                parsed_event=parsed,
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Remediation completed successfully",
                    "result": result,
                    "parsed_event": parsed,
                    "dry_run": DRY_RUN,
                    "sns_result": alert_result,
                }),
            }

        log_json(
            "ERROR",
            "Remediation failed",
            remediation_result=result,
            parsed_event=parsed,
        )
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": "Remediation failed",
                "result": result,
                "parsed_event": parsed,
                "dry_run": DRY_RUN,
                "sns_result": alert_result,
            }),
        }

    except Exception as exc:
        log_json(
            "ERROR",
            "Unhandled Lambda exception",
            error=str(exc),
        )
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": "Unhandled exception",
                "error": str(exc),
                "dry_run": DRY_RUN,
            }),
        }