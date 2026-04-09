"""
Data Exfiltration Detector
Detects S3 data exfiltration, secrets access and large-scale data movement
References: MITRE ATT&CK T1530 - Data from Cloud Storage Object
"""

from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# S3 actions indicating potential exfiltration
S3_EXFIL_ACTIONS = {
    "GetObject": {"severity": "LOW", "description": "S3 object download"},
    "GetBucketAcl": {"severity": "LOW", "description": "S3 bucket ACL read"},
    "PutBucketAcl": {"severity": "HIGH", "description": "S3 bucket ACL modification"},
    "PutBucketPolicy": {"severity": "HIGH", "description": "S3 bucket policy modification"},
    "DeleteBucketPolicy": {"severity": "HIGH", "description": "S3 bucket policy deletion"},
    "PutBucketPublicAccessBlock": {"severity": "HIGH", "description": "S3 public access block modification"},
    "DeletePublicAccessBlock": {"severity": "CRITICAL", "description": "S3 public access block removed"},
}

# Secrets/sensitive data access
SECRETS_ACTIONS = {
    "GetSecretValue": {"severity": "HIGH", "technique": "T1552.007"},
    "GetParameter": {"severity": "MEDIUM", "technique": "T1552.007"},
    "GetParameters": {"severity": "MEDIUM", "technique": "T1552.007"},
    "Decrypt": {"severity": "MEDIUM", "technique": "T1486"},
    "GenerateDataKey": {"severity": "LOW", "technique": "T1486"},
}

# CloudTrail logging disruption (covers tracks)
DEFENSE_EVASION_ACTIONS = {
    "DeleteTrail": {"severity": "CRITICAL", "technique": "T1562.008"},
    "StopLogging": {"severity": "CRITICAL", "technique": "T1562.008"},
    "UpdateTrail": {"severity": "HIGH", "technique": "T1562.008"},
    "PutEventSelectors": {"severity": "HIGH", "technique": "T1562.008"},
    "DeleteFlowLogs": {"severity": "HIGH", "technique": "T1562.008"},
}


class DataExfiltrationDetector:
    """
    Detects data exfiltration attempts and defense evasion tactics in CloudTrail events.
    """

    def __init__(self):
        self.detector_name = "DataExfiltrationDetector"
        logger.info(f"Initialized {self.detector_name}")

    def analyze(self, event: dict) -> Optional[dict]:
        """
        Analyze a CloudTrail event for data exfiltration indicators.

        Args:
            event: Parsed CloudTrail event dictionary

        Returns:
            Finding dict if threat detected, None otherwise
        """
        event_name = event.get("eventName", "")
        event_source = event.get("eventSource", "")

        # Check for defense evasion (covering tracks)
        if event_name in DEFENSE_EVASION_ACTIONS:
            return self._build_defense_evasion_finding(event)

        # Check for S3 exfiltration
        if "s3" in event_source and event_name in S3_EXFIL_ACTIONS:
            return self._build_s3_finding(event)

        # Check for secrets access
        if event_name in SECRETS_ACTIONS:
            return self._build_secrets_finding(event)

        return None

    def _build_defense_evasion_finding(self, event: dict) -> dict:
        """Build finding for CloudTrail/logging disruption."""
        rule = DEFENSE_EVASION_ACTIONS[event["eventName"]]
        user_identity = event.get("userIdentity", {})
        actor = user_identity.get("arn") or user_identity.get("userName") or "unknown"

        return {
            "finding_type": "DEFENSE_EVASION_LOGGING_DISRUPTION",
            "detector": self.detector_name,
            "severity": rule["severity"],
            "mitre_technique": rule["technique"],
            "action": f"cloudtrail:{event.get('eventName', '')}",
            "actor": actor,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": (
                f"DEFENSE EVASION: {actor} performed {event.get('eventName')} "
                "— logging disruption is a strong indicator of active compromise."
            ),
            "risk_factors": ["defense_evasion", "logging_disruption", "covering_tracks"],
            "remediation": (
                "IMMEDIATE ACTION REQUIRED: Re-enable CloudTrail logging. "
                "Treat this as active incident. Isolate the principal. "
                "Review all API activity in the last 24 hours."
            ),
            "raw_event_id": event.get("eventID", "unknown"),
        }

    def _build_s3_finding(self, event: dict) -> dict:
        """Build finding for S3 exfiltration activity."""
        rule = S3_EXFIL_ACTIONS[event["eventName"]]
        user_identity = event.get("userIdentity", {})
        actor = user_identity.get("arn") or user_identity.get("userName") or "unknown"
        request_params = event.get("requestParameters", {}) or {}
        bucket_name = request_params.get("bucketName", "unknown")

        return {
            "finding_type": "S3_DATA_EXFILTRATION",
            "detector": self.detector_name,
            "severity": rule["severity"],
            "mitre_technique": "T1530",
            "action": f"s3:{event.get('eventName', '')}",
            "actor": actor,
            "bucket": bucket_name,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": f"S3 {rule['description']}: {actor} on bucket '{bucket_name}'",
            "risk_factors": ["s3_access", "potential_exfiltration"],
            "remediation": "Review S3 bucket policies and access logs. Check for public exposure.",
            "raw_event_id": event.get("eventID", "unknown"),
        }

    def _build_secrets_finding(self, event: dict) -> dict:
        """Build finding for secrets/sensitive data access."""
        rule = SECRETS_ACTIONS[event["eventName"]]
        user_identity = event.get("userIdentity", {})
        actor = user_identity.get("arn") or user_identity.get("userName") or "unknown"
        request_params = event.get("requestParameters", {}) or {}
        secret_id = request_params.get("secretId") or request_params.get("name") or "unknown"

        return {
            "finding_type": "SECRETS_ACCESS",
            "detector": self.detector_name,
            "severity": rule["severity"],
            "mitre_technique": rule["technique"],
            "action": f"secretsmanager:{event.get('eventName', '')}",
            "actor": actor,
            "secret_id": secret_id,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": f"Secrets access: {actor} retrieved secret '{secret_id}'",
            "risk_factors": ["secrets_access", "sensitive_data"],
            "remediation": "Verify this secrets access is authorized. Rotate the secret if suspicious.",
            "raw_event_id": event.get("eventID", "unknown"),
        }