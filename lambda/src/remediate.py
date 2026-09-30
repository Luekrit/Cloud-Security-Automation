"""
remediate.py - Cloud Security Automation, post-Phase 4.5 corrections

Exception governance moved from IAM tags to DynamoDB.

Three design principles are encoded in this file. They are worth knowing by
name because they are the things an interviewer will actually push on:

  1. DEFAULT DENY / FAIL CLOSED.
     The exception store is a *bypass* mechanism. If it is missing,
     empty, or returns an invalid record, no exception is granted. An
     unavailable store grants no approval either, but postpones mutation
     and raises after notification so retries/DLQ can retain the event.

  2. DECIDE, NOTIFY, ACT - in that order, as three separate steps.
     We attempt an alert for every evaluated event, including skips.
     Publication failure raises before mutation; unexpected errors raise too.

  3. ONE ENGINE, MANY CONTROLS.
     Each risky event is described by a small ControlHandler in
     CONTROL_REGISTRY. Adding a control is adding a registry entry, not
     editing the decision engine. The engine never names a specific event.
"""

import json
import logging
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam = boto3.client("iam")
sns = boto3.client("sns")

# Pin the DynamoDB region explicitly. The global Lambda runs in us-east-1, and so
# must the exception table; relying on the Lambda's implicit region works but
# hides that coupling. EXCEPTION_TABLE_REGION makes it explicit and overridable.
EXCEPTION_TABLE_REGION = os.getenv("EXCEPTION_TABLE_REGION", os.getenv("AWS_REGION", "us-east-1"))
dynamodb = boto3.resource("dynamodb", region_name=EXCEPTION_TABLE_REGION)

# Only an explicit "false" enables mutations. Typos must keep dry-run on.
DRY_RUN = os.getenv("DRY_RUN", "true").strip().lower() != "false"
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")
EXCEPTION_TABLE_NAME = os.getenv("EXCEPTION_TABLE_NAME", "")

# Identities we will never auto-remediate against, regardless of approvals.
# This is a guardrail against the automation locking out its own operators.
PROTECTED_USERS = {
    "SecurityteamAdmin",
    "terraform-operator",
    "DevOps-IAM-Admin",
}

DANGEROUS_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
}


# ---------------------------------------------------------------------------
# Logging + small parsing helpers (unchanged in spirit from the tag version)
# ---------------------------------------------------------------------------

def log_json(level: str, message: str, **kwargs: Any) -> None:
    payload = {"message": message, **kwargs}
    log_line = json.dumps(payload, default=str)
    if level.upper() == "ERROR":
        logger.error(log_line)
    elif level.upper() == "WARNING":
        logger.warning(log_line)
    else:
        logger.info(log_line)


def get_nested(data: Dict[str, Any], path: List[str], default: Any = None) -> Any:
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


# ---------------------------------------------------------------------------
# DynamoDB exception check - the heart of Phase 4
# ---------------------------------------------------------------------------

@dataclass
class ExceptionDecision:
    valid: bool
    reason: str
    record: Optional[Dict[str, Any]] = None
    lookup_failed: bool = False


def check_exception(resource_name: str, control_id: str) -> ExceptionDecision:
    """Only a well-formed APPROVED record grants an exception.

    Invalid records deny the exception. An unavailable approval store denies
    approval too, but postpones mutation and surfaces an invocation failure.
    """
    if not EXCEPTION_TABLE_NAME:
        return ExceptionDecision(False, "Exception table not configured", lookup_failed=True)

    key = {
        "pk": f"RESOURCE#{resource_name}",
        "sk": f"CONTROL#{control_id}",
    }
    try:
        response = dynamodb.Table(EXCEPTION_TABLE_NAME).get_item(
            Key=key, ConsistentRead=True
        )
    except (ClientError, BotoCoreError) as exc:
        return ExceptionDecision(
            False, f"Exception lookup failed: {exc}", lookup_failed=True
        )

    item = response.get("Item")
    if item is None:
        return ExceptionDecision(False, "No exception record found")
    if not isinstance(item, dict) or not item:
        return ExceptionDecision(False, "Malformed exception record")
    # DynamoDB's exact-key lookup establishes scope. Validate returned key
    # fields too, so malformed fixtures/records cannot become broad approvals.
    if any(item.get(k) != value for k, value in key.items()):
        return ExceptionDecision(False, "Exception resource/control key mismatch", item)
    status = item.get("status")
    if status != "APPROVED":
        return ExceptionDecision(False, f"Exception status is {status}, not APPROVED", item)

    expiry = item.get("expires_at_epoch")
    try:
        # Boto3 returns DynamoDB numbers as Decimal. Reject booleans, null,
        # containers, non-finite numbers and fractions; do not truncate them.
        if isinstance(expiry, bool) or not isinstance(expiry, (str, int, Decimal)):
            raise ValueError("expiry must be an integer epoch")
        numeric_expiry = Decimal(str(expiry))
        if not numeric_expiry.is_finite() or numeric_expiry != numeric_expiry.to_integral_value():
            raise ValueError("expiry must be a finite integer epoch")
        expires_at_epoch = int(numeric_expiry)
    except (InvalidOperation, TypeError, ValueError, OverflowError):
        return ExceptionDecision(False, "Malformed or missing exception expiry", item)
    if expires_at_epoch <= int(time.time()):
        return ExceptionDecision(False, "Exception has expired", item)
    return ExceptionDecision(True, "Valid approved exception found", item)


# ---------------------------------------------------------------------------
# Per-event control handlers
#
# Each risky event differs in three ways the engine should NOT have to know
# about: how to read its fields, what makes a given instance risky, and how
# to remediate it. We isolate those three differences behind a ControlHandler
# so the engine stays generic.
# ---------------------------------------------------------------------------

@dataclass
class RiskResult:
    risky: bool
    reason: str


@dataclass
class ControlHandler:
    control_id: str
    parse: Callable[[Dict[str, Any]], Dict[str, Any]]
    resource_name: Callable[[Dict[str, Any]], Optional[str]]
    is_risky: Callable[[Dict[str, Any]], RiskResult]
    remediate: Callable[[Dict[str, Any]], Dict[str, Any]]


def _safe_iam_action(action: str, fn: Callable[[], Any], **context: Any) -> Dict[str, Any]:
    """Return IAM service-error results; transport failures propagate."""
    try:
        fn()
        return {"status": "success", "action": action, **context}
    except ClientError as exc:
        # A replayed detach can encounter an already absent user/policy.
        # This narrow no-op rule does not enable other destructive handlers.
        code = exc.response.get("Error", {}).get("Code")
        if action == "detach_user_policy" and code == "NoSuchEntity":
            return {"status": "success", "action": action,
                    "outcome": "target_already_absent", **context}
        return {"status": "error", "action": action, "error": str(exc), **context}


# --- AttachUserPolicy: conditionally risky (only if the policy is dangerous)

def parse_attach_user_policy(detail: Dict[str, Any]) -> Dict[str, Any]:
    rp = detail.get("requestParameters") or {}
    return {
        "target_user_name": rp.get("userName"),
        "policy_arn": rp.get("policyArn"),
    }


def risky_attach_user_policy(parsed: Dict[str, Any]) -> RiskResult:
    policy_arn = parsed.get("policy_arn")
    if not policy_arn:
        return RiskResult(False, "Missing policy ARN")
    if policy_arn not in DANGEROUS_POLICIES:
        return RiskResult(False, f"Policy not in remediation scope: {policy_arn}")
    return RiskResult(True, f"Dangerous managed policy attached: {policy_arn}")


def remediate_attach_user_policy(parsed: Dict[str, Any]) -> Dict[str, Any]:
    return _safe_iam_action(
        "detach_user_policy",
        lambda: iam.detach_user_policy(
            UserName=parsed["target_user_name"],
            PolicyArn=parsed["policy_arn"],
        ),
        user_name=parsed["target_user_name"],
        policy_arn=parsed["policy_arn"],
    )


# --- PutUserPolicy: an INLINE policy. There is no policyArn - we must read
#     the policy document and judge it. Different shape, different risk logic.

def parse_put_user_policy(detail: Dict[str, Any]) -> Dict[str, Any]:
    rp = detail.get("requestParameters") or {}
    return {
        "target_user_name": rp.get("userName"),
        "policy_name": rp.get("policyName"),
        "policy_document": rp.get("policyDocument"),
    }


def _grants_wildcard_admin(policy_document: Optional[str]) -> bool:
    """
    Heuristic: does this inline policy grant Action '*' on Resource '*'?
    This is NOT a full IAM policy evaluator (real systems use IAM Access
    Analyzer policy validation). If we cannot parse it, we flag it for review
    rather than assume it is safe - secure default applied to detection.
    """
    if not policy_document:
        return True  # cannot prove safe -> flag for review
    try:
        doc = json.loads(urllib.parse.unquote(policy_document))
    except (ValueError, TypeError):
        return True  # cannot parse -> flag for review

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        actions = [actions] if isinstance(actions, str) else actions
        resources = [resources] if isinstance(resources, str) else resources
        if "*" in actions and "*" in resources:
            return True
    return False


def risky_put_user_policy(parsed: Dict[str, Any]) -> RiskResult:
    if _grants_wildcard_admin(parsed.get("policy_document")):
        return RiskResult(True, "Inline policy grants (or may grant) wildcard admin")
    return RiskResult(False, "Inline policy not admin-equivalent")


def remediate_put_user_policy(parsed: Dict[str, Any]) -> Dict[str, Any]:
    return _safe_iam_action(
        "delete_user_policy",
        lambda: iam.delete_user_policy(
            UserName=parsed["target_user_name"],
            PolicyName=parsed["policy_name"],
        ),
        user_name=parsed["target_user_name"],
        policy_name=parsed.get("policy_name"),
    )


# --- CreateAccessKey: risky by default. NOTE the access key id lives in
#     responseElements, not requestParameters - a parsing trap.

def parse_create_access_key(detail: Dict[str, Any]) -> Dict[str, Any]:
    rp = detail.get("requestParameters") or {}
    access_key = get_nested(detail, ["responseElements", "accessKey"], {}) or {}
    # If no userName in the request, the key was created for the caller; the
    # response carries the resolved owner.
    target = rp.get("userName") or access_key.get("userName")
    return {
        "target_user_name": target,
        "access_key_id": access_key.get("accessKeyId"),
    }


def risky_create_access_key(parsed: Dict[str, Any]) -> RiskResult:
    if not parsed.get("target_user_name"):
        return RiskResult(False, "No target user resolved")
    return RiskResult(True, "Programmatic access key created (persistence vector)")


def remediate_create_access_key(parsed: Dict[str, Any]) -> Dict[str, Any]:
    if not parsed.get("access_key_id"):
        return {
            "status": "error",
            "action": "delete_access_key",
            "error": "No accessKeyId present in event; cannot target deletion",
            "user_name": parsed.get("target_user_name"),
        }
    return _safe_iam_action(
        "delete_access_key",
        lambda: iam.delete_access_key(
            UserName=parsed["target_user_name"],
            AccessKeyId=parsed["access_key_id"],
        ),
        user_name=parsed["target_user_name"],
        access_key_id=parsed["access_key_id"],
    )


# --- CreateLoginProfile: risky by default (console access / persistence).

def parse_create_login_profile(detail: Dict[str, Any]) -> Dict[str, Any]:
    rp = detail.get("requestParameters") or {}
    return {"target_user_name": rp.get("userName")}


def risky_create_login_profile(parsed: Dict[str, Any]) -> RiskResult:
    if not parsed.get("target_user_name"):
        return RiskResult(False, "No target user resolved")
    return RiskResult(True, "Console login profile created (persistence vector)")


def remediate_create_login_profile(parsed: Dict[str, Any]) -> Dict[str, Any]:
    return _safe_iam_action(
        "delete_login_profile",
        lambda: iam.delete_login_profile(UserName=parsed["target_user_name"]),
        user_name=parsed["target_user_name"],
    )


# The registry. The engine reads this; it never hard-codes an event name.
CONTROL_REGISTRY: Dict[str, ControlHandler] = {
    "AttachUserPolicy": ControlHandler(
        control_id="IAM_ADMIN_POLICY_ATTACHMENT",
        parse=parse_attach_user_policy,
        resource_name=lambda p: p.get("target_user_name"),
        is_risky=risky_attach_user_policy,
        remediate=remediate_attach_user_policy,
    ),
    "PutUserPolicy": ControlHandler(
        control_id="IAM_INLINE_ADMIN_POLICY",
        parse=parse_put_user_policy,
        resource_name=lambda p: p.get("target_user_name"),
        is_risky=risky_put_user_policy,
        remediate=remediate_put_user_policy,
    ),
    "CreateAccessKey": ControlHandler(
        control_id="IAM_ACCESS_KEY_CREATION",
        parse=parse_create_access_key,
        resource_name=lambda p: p.get("target_user_name"),
        is_risky=risky_create_access_key,
        remediate=remediate_create_access_key,
    ),
    "CreateLoginProfile": ControlHandler(
        control_id="IAM_LOGIN_PROFILE_CREATION",
        parse=parse_create_login_profile,
        resource_name=lambda p: p.get("target_user_name"),
        is_risky=risky_create_login_profile,
        remediate=remediate_create_login_profile,
    ),
}


# ---------------------------------------------------------------------------
# Decision engine - generic, names no specific event
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    action: str  # REMEDIATE | SKIP_APPROVED | NO_ACTION | RETRY_REQUIRED
    reason: str
    event_name: Optional[str] = None
    control_id: Optional[str] = None
    resource_name: Optional[str] = None
    exception_record: Optional[Dict[str, Any]] = None
    target: Dict[str, Any] = field(default_factory=dict)


def evaluate(detail: Dict[str, Any]) -> Decision:
    event_name = detail.get("eventName")
    handler = CONTROL_REGISTRY.get(event_name)
    if not handler:
        return Decision("NO_ACTION", f"Unsupported event: {event_name}", event_name)

    parsed = handler.parse(detail)
    target_name = handler.resource_name(parsed)

    base = dict(event_name=event_name, control_id=handler.control_id)

    # Cheapest, most decisive guards first. None of these need DynamoDB.
    if not target_name:
        return Decision("NO_ACTION", "No target resource resolved", **base)
    if target_name in PROTECTED_USERS:
        return Decision("NO_ACTION", f"Target is protected: {target_name}",
                        resource_name=target_name, **base)
    if not isinstance(target_name, str) or not re.fullmatch(r"iam-test-[A-Za-z0-9_+=,.@-]+", target_name):
        return Decision("NO_ACTION", "Target outside controlled iam-test-* scope",
                        resource_name=target_name, **base)
    # Self-issued changes are evaluated normally; actor identity is not approval.
    if detail.get("errorCode"):
        return Decision("NO_ACTION", "IAM API call failed; no successful change to remediate",
                        resource_name=target_name, **base)

    risk = handler.is_risky(parsed)
    if not risk.risky:
        return Decision("NO_ACTION", risk.reason, resource_name=target_name, **base)

    # Only now - once we know the action is genuinely risky - do we spend a
    # DynamoDB read consulting the approvals store.
    exc = check_exception(target_name, handler.control_id)
    if exc.lookup_failed:
        return Decision("RETRY_REQUIRED", exc.reason, resource_name=target_name, **base)
    if exc.valid:
        return Decision("SKIP_APPROVED", exc.reason, resource_name=target_name,
                        exception_record=exc.record, **base)

    return Decision("REMEDIATE", f"{risk.reason}; {exc.reason}",
                    resource_name=target_name, target=parsed, **base)


# ---------------------------------------------------------------------------
# Notify
# ---------------------------------------------------------------------------

def build_alert_payload(detail: Dict[str, Any], decision: Decision) -> Dict[str, Any]:
    record = decision.exception_record or {}
    return {
        "control": decision.control_id,
        "severity": "info" if decision.action == "SKIP_APPROVED" else "high",
        "dry_run": DRY_RUN,
        "decision": decision.action,
        "decision_reason": decision.reason,
        "event_name": decision.event_name,
        "resource": decision.resource_name,
        "actor_arn": get_nested(detail, ["userIdentity", "arn"]),
        "event_time": detail.get("eventTime"),
        "source_ip": detail.get("sourceIPAddress"),
        "account_id": detail.get("recipientAccountId"),
        # Audit trail when a pre-approved exception suppressed remediation.
        "exception_ticket_id": record.get("ticket_id"),
        "exception_approved_by": record.get("approved_by"),
    }


def publish_sns_alert(subject: str, message: Dict[str, Any]) -> Dict[str, Any]:
    if not SNS_TOPIC_ARN:
        return {"status": "error", "error": "SNS_TOPIC_ARN not configured"}
    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(message, default=str, indent=2),
        )
        return {"status": "success", "message_id": response.get("MessageId")}
    except ClientError as exc:
        # If the topic is KMS-encrypted and this role lacks kms:GenerateDataKey*
        # / kms:Decrypt, the failure surfaces HERE. We return it; the handler
        # logs it at ERROR so a metric filter / alarm can catch a dead alert
        # channel instead of it failing silently.
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Act
# ---------------------------------------------------------------------------

def _response(status: int, message: str, decision: Decision,
              alert: Dict[str, Any], remediation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    body = {
        "message": message,
        "decision": decision.action,
        "reason": decision.reason,
        "control_id": decision.control_id,
        "resource": decision.resource_name,
        "dry_run": DRY_RUN,
        "sns_result": alert,
    }
    if remediation is not None:
        body["remediation_result"] = remediation
    return {"statusCode": status, "body": json.dumps(body, default=str)}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    log_json("INFO", "Detection triggered", dry_run=DRY_RUN, raw_event=event,
             request_id=getattr(context, "aws_request_id", None))

    try:
        detail = event.get("detail", {}) or {}

        # 1) DECIDE
        decision = evaluate(detail)
        log_json("INFO", "Governance decision", decision=asdict(decision))

        # 2) NOTIFY - attempt publication for every normal decision.
        alert = publish_sns_alert(
            "Cloud Security Automation Alert",
            build_alert_payload(detail, decision),
        )
        if alert.get("status") != "success":
            log_json("ERROR", "SNS alert failed - alert channel may be down",
                     sns_result=alert, control_id=decision.control_id)
            # Publish before mutation: an alert failure must not cause a
            # successful IAM change followed by an alert-driven replay.
            raise RuntimeError("SNS notification failed; no IAM action attempted")
        else:
            log_json("INFO", "SNS alert processed", sns_result=alert)

        if decision.action == "RETRY_REQUIRED":
            raise RuntimeError("Exception lookup unavailable; no IAM action attempted")

        # 3) ACT - only on a REMEDIATE decision.
        if decision.action != "REMEDIATE":
            log_json("INFO", "No remediation performed", reason=decision.reason,
                     decision=decision.action)
            return _response(200, "No remediation required", decision, alert)

        if DRY_RUN:
            simulated = {
                "status": "dry_run",
                "control_id": decision.control_id,
                "resource": decision.resource_name,
                "would_run": decision.target,
            }
            log_json("INFO", "Dry run enabled - remediation skipped",
                     remediation_result=simulated)
            return _response(200, "Dry run only - remediation skipped",
                             decision, alert, remediation=simulated)

        handler = CONTROL_REGISTRY[decision.event_name]
        result = handler.remediate(decision.target)

        if result.get("status") == "success":
            log_json("INFO", "Remediation completed", remediation_result=result)
            return _response(200, "Remediation completed successfully",
                             decision, alert, remediation=result)

        log_json("ERROR", "Remediation failed", remediation_result=result)
        raise RuntimeError("IAM remediation failed; see structured remediation_result log")

    except Exception as exc:  # noqa: BLE001 - top-level safety net only
        log_json("ERROR", "Unhandled Lambda exception", error=str(exc))
        # EventBridge invokes asynchronously. Returning {statusCode: 500}
        # is a normal return, so Lambda would not retry or route to the DLQ.
        raise
