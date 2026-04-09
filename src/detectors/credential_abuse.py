"""
Credential Abuse Detector
Detects credential misuse patterns including impossible travel, API key abuse and root account usage
Rferences: MITRE ATT&CK T1552, T1078
"""

import re
from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# Root account usage is always suspicious
ROOT_INDICATORS = {"Root", "root", "<root_account>"}

# Programmatic credential misuse patterns
AUTOMATED_MISUSE_USER_AGENTS = [
    r"aws-cli/[0-9]",  # CLI usage from unusual contexts
    r"Boto3",
    r"aws-sdk-java",
    r"aws-sdk-go",
]

# High-value read actions that indicate data reconnaissance
RECON_ACTIONS = {
    "ListUsers", "ListRoles", "ListPolicies", "ListBuckets",
    "ListKeys", "ListSecrets", "DescribeInstances", "DescribeVpcs",
    "GetAccountAuthorizationDetails", "ListAttachedUserPolicies",
    "GetCredentialReport", "GenerateCredentialReport",
    "ListAccessKeys", "GetAccessKeyLastUsed",
}

# Actions indicating credential/key manipulation
CREDENTIAL_ACTIONS = {
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "CreateVirtualMFADevice", "DeactivateMFADevice", "DeleteVirtualMFADevice",
    "EnableMFADevice", "ResyncMFADevice",
}


class CredentialAbuseDetector:
    """
    Detects credential abuse patterns in CloudTrail events.
    Focuses on root usage, reconnaissance activity, and suspicious credential operations.
    """

    def __init__(self):
        self.detector_name = "CredentialAbuseDetector"
        self._recon_session_tracker = {}  # In production we use ElastiCache/DynamoDB
        logger.info(f"Initialized {self.detector_name}")

    def analyze(self, event: dict) -> Optional[dict]:
        """
        Analyze a CloudTrail event for credential abuse indicators.

        Args:
            event: Parsed CloudTrail event dictionary

        Returns:
            Finding dict if threat detected, None otherwise
        """
        user_identity = event.get("userIdentity", {})
        identity_type = user_identity.get("type", "")
        event_name = event.get("eventName", "")

        # Check 1: Root account usage
        if self._is_root_usage(user_identity, identity_type):
            return self._build_root_finding(event)

        # Check 2: Reconnaissance activity
        if event_name in RECON_ACTIONS:
            return self._build_recon_finding(event)

        # Check 3: Suspicious credential operations on other users
        if event_name in CREDENTIAL_ACTIONS:
            return self._build_credential_op_finding(event)

        # Check 4: Console login from programmatic credential
        if event_name == "ConsoleLogin" and self._is_suspicious_login(event):
            return self._build_suspicious_login_finding(event)

        return None

    def _is_root_usage(self, user_identity: dict, identity_type: str) -> bool:
        """Check if the event was performed by the root account."""
        if identity_type == "Root":
            return True
        arn = user_identity.get("arn", "")
        return ":root" in arn

    def _is_suspicious_login(self, event: dict) -> bool:
        """Check if console login has suspicious characteristics."""
        response_elements = event.get("responseElements", {}) or {}
        additional_info = event.get("additionalEventData", {}) or {}

        # MFA not used on console login
        mfa_used = additional_info.get("MFAUsed", "Yes")
        login_result = response_elements.get("ConsoleLogin", "")

        return mfa_used == "No" or login_result == "Failure"

    def _build_root_finding(self, event: dict) -> dict:
        """Build finding for root account usage."""
        return {
            "finding_type": "ROOT_ACCOUNT_USAGE",
            "detector": self.detector_name,
            "severity": "CRITICAL",
            "mitre_technique": "T1078.004",
            "action": f"sts:{event.get('eventName', '')}",
            "actor": "ROOT",
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": (
                f"Root account activity detected: {event.get('eventName')} "
                f"from {event.get('sourceIPAddress', 'unknown')}. "
                "Root usage should be extremely rare and is a high-risk indicator."
            ),
            "risk_factors": ["root_account", "critical_identity"],
            "remediation": (
                "Immediately investigate root account usage. "
                "Enable MFA on root account if not already done. "
                "Create IAM users/roles for all administrative tasks. "
                "Review AWS Organizations SCPs to restrict root usage."
            ),
            "raw_event_id": event.get("eventID", "unknown"),
        }

    def _build_recon_finding(self, event: dict) -> dict:
        """Build finding for reconnaissance activity."""
        user_identity = event.get("userIdentity", {})
        actor = user_identity.get("arn") or user_identity.get("userName") or "unknown"

        return {
            "finding_type": "IAM_RECONNAISSANCE",
            "detector": self.detector_name,
            "severity": "MEDIUM",
            "mitre_technique": "T1087.004",
            "action": f"iam:{event.get('eventName', '')}",
            "actor": actor,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": (
                f"IAM reconnaissance: {actor} performed {event.get('eventName')} "
                f"— common precursor to privilege escalation."
            ),
            "risk_factors": ["reconnaissance", "iam_enumeration"],
            "remediation": (
                "Review whether this IAM enumeration is expected for this principal. "
                "Check if followed by privilege escalation attempts. "
                "Consider tighter IAM permission boundaries."
            ),
            "raw_event_id": event.get("eventID", "unknown"),
        }

    def _build_credential_op_finding(self, event: dict) -> dict:
        """Build finding for credential operations."""
        user_identity = event.get("userIdentity", {})
        actor = user_identity.get("arn") or user_identity.get("userName") or "unknown"
        request_params = event.get("requestParameters", {}) or {}
        target = request_params.get("userName", "self")

        severity = "HIGH" if event.get("eventName") in {"CreateAccessKey", "DeactivateMFADevice"} else "MEDIUM"

        return {
            "finding_type": "CREDENTIAL_MANIPULATION",
            "detector": self.detector_name,
            "severity": severity,
            "mitre_technique": "T1552.005",
            "action": f"iam:{event.get('eventName', '')}",
            "actor": actor,
            "target": target,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": (
                f"Credential operation: {actor} performed {event.get('eventName')} "
                f"targeting user '{target}'"
            ),
            "risk_factors": ["credential_manipulation"],
            "remediation": "Verify this credential operation is authorized. Audit the affected user's access keys.",
            "raw_event_id": event.get("eventID", "unknown"),
        }

    def _build_suspicious_login_finding(self, event: dict) -> dict:
        """Build finding for suspicious console login."""
        additional_info = event.get("additionalEventData", {}) or {}
        mfa_used = additional_info.get("MFAUsed", "Unknown")

        return {
            "finding_type": "SUSPICIOUS_CONSOLE_LOGIN",
            "detector": self.detector_name,
            "severity": "HIGH",
            "mitre_technique": "T1078",
            "action": "signin:ConsoleLogin",
            "actor": event.get("userIdentity", {}).get("arn", "unknown"),
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "mfa_used": mfa_used,
            "description": (
                f"Suspicious console login detected. MFA used: {mfa_used}. "
                f"Source IP: {event.get('sourceIPAddress', 'unknown')}"
            ),
            "risk_factors": ["no_mfa" if mfa_used == "No" else "failed_login"],
            "remediation": "Enforce MFA for all IAM users. Review failed login patterns.",
            "raw_event_id": event.get("eventID", "unknown"),
        }