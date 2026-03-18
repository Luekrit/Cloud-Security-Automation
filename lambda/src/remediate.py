import json
import logging
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")

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

    if event_name not in SUPPORTED_EVENTS:
        return False, f"Unsupported event: {event_name}"

    if not target_user_name:
        return False, "Missing target user name"

    if not policy_arn:
        return False, "Missing policy ARN"

    if policy_arn not in DANGEROUS_POLICIES:
        return False, f"Policy not in remediation scope: {policy_arn}"

    return True, "Approved for remediation"


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
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "message": "Remediation completed successfully",
                    "result": result,
                }),
            }

        log_json(
            "ERROR",
            "Remediation failed",
            remediation_result=result,
        )
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": "Remediation failed",
                "result": result,
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
            }),
        }