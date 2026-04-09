"""
Privilege Escalation Detector
Detects IAM privilege escalation attempts via CloudTrail events
References: MITRE ATT&CK TA0004 - Privilege Escalation
"""

from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# High-risk IAM actions that indicate privilege escalation attempts
PRIVILEGE_ESCALATION_ACTIONS = {
    # Direct privilege escalation
    "iam:AttachUserPolicy": {"severity": "HIGH", "technique": "T1098.003"},
    "iam:AttachRolePolicy": {"severity": "HIGH", "technique": "T1098.003"},
    "iam:PutUserPolicy": {"severity": "HIGH", "technique": "T1098.003"},
    "iam:PutRolePolicy": {"severity": "HIGH", "technique": "T1098.003"},
    "iam:CreatePolicyVersion": {"severity": "HIGH", "technique": "T1098.003"},
    "iam:SetDefaultPolicyVersion": {"severity": "HIGH", "technique": "T1098.003"},

    # Role manipulation
    "iam:CreateRole": {"severity": "MEDIUM", "technique": "T1136"},
    "iam:PassRole": {"severity": "MEDIUM", "technique": "T1078.004"},
    "iam:UpdateAssumeRolePolicy": {"severity": "HIGH", "technique": "T1098"},

    # Admin access grants
    "iam:AddUserToGroup": {"severity": "MEDIUM", "technique": "T1098"},
    "iam:CreateAccessKey": {"severity": "MEDIUM", "technique": "T1098.001"},

    # Service-linked escalation paths
    "lambda:AddPermission": {"severity": "MEDIUM", "technique": "T1098"},
    "sts:AssumeRole": {"severity": "LOW", "technique": "T1548"},
    "iam:CreateLoginProfile": {"severity": "HIGH", "technique": "T1136.003"},
    "iam:UpdateLoginProfile": {"severity": "HIGH", "technique": "T1531"},
}

# Suspicious policy ARNs often used in attacks
DANGEROUS_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


class PrivilegeEscalationDetector:
    """
    Detects privilege escalation patterns in CloudTrail events.
    Implements MITRE ATT&CK techniques for cloud privilege abuse.
    """

    def __init__(self):
        self.detector_name = "PrivilegeEscalationDetector"
        logger.info(f"Initialized {self.detector_name} with {len(PRIVILEGE_ESCALATION_ACTIONS)} detection rules")

    def analyze(self, event: dict) -> Optional[dict]:
        """
        Analyze a CloudTrail event for privilege escalation indicators.

        Args:
            event: Parsed CloudTrail event dictionary

        Returns:
            Finding dict if threat detected, None otherwise
        """
        event_name = event.get("eventName", "")
        event_source = event.get("eventSource", "")
        error_code = event.get("errorCode")

        # Build full action string (eg, "iam:AttachUserPolicy")
        service = event_source.replace(".amazonaws.com", "")
        action = f"{service}:{event_name}"

        if action not in PRIVILEGE_ESCALATION_ACTIONS:
            return None

        rule = PRIVILEGE_ESCALATION_ACTIONS[action]
        finding = self._build_finding(event, action, rule)

        # Escalate severity if admin policy is being attached
        request_params = event.get("requestParameters", {}) or {}
        policy_arn = request_params.get("policyArn", "")
        if policy_arn in DANGEROUS_POLICY_ARNS:
            finding["severity"] = "CRITICAL"
            finding["description"] += f" ADMIN POLICY ATTACHED: {policy_arn}"
            finding["risk_factors"].append("dangerous_policy_arn")

        # Flag failed attempts - may indicate probing
        if error_code:
            finding["description"] += f" [FAILED: {error_code}]"
            finding["risk_factors"].append("failed_attempt")
            # Lower base score but keep as finding for recon detection
            finding["base_risk_modifier"] = 0.6

        logger.warning(
            f"Privilege escalation detected",
            extra={
                "action": action,
                "severity": finding["severity"],
                "actor": finding["actor"],
                "source_ip": finding["source_ip"]
            }
        )

        return finding

    def _build_finding(self, event: dict, action: str, rule: dict) -> dict:
        """Construct a standardized finding dictionary."""
        user_identity = event.get("userIdentity", {})
        request_params = event.get("requestParameters", {}) or {}

        actor = (
            user_identity.get("arn") or
            user_identity.get("userName") or
            user_identity.get("principalId") or
            "unknown"
        )

        return {
            "finding_type": "PRIVILEGE_ESCALATION",
            "detector": self.detector_name,
            "severity": rule["severity"],
            "mitre_technique": rule["technique"],
            "action": action,
            "actor": actor,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "target_resource": request_params.get("userName") or request_params.get("roleName") or "unknown",
            "policy_arn": request_params.get("policyArn", "N/A"),
            "description": (
                f"Potential privilege escalation: {actor} performed {action} "
                f"from {event.get('sourceIPAddress', 'unknown')}"
            ),
            "risk_factors": ["privilege_escalation_action"],
            "remediation": self._get_remediation(action),
            "raw_event_id": event.get("eventID", "unknown"),
        }

    def _get_remediation(self, action: str) -> str:
        """Return remediation guidance for the detected action."""
        remediations = {
            "iam:AttachUserPolicy": "Review and revoke the policy attachment. Audit IAM user permissions.",
            "iam:CreateRole": "Review newly created role trust policy and permissions. Remove if unauthorized.",
            "iam:CreateAccessKey": "Immediately deactivate the access key if unauthorized. Rotate all credentials.",
            "iam:CreateLoginProfile": "Disable console access for the affected user. Review account activity.",
            "sts:AssumeRole": "Review cross-account role assumptions. Verify trust relationships.",
        }
        return remediations.get(action, "Review IAM activity logs and revoke unauthorized permissions immediately.")