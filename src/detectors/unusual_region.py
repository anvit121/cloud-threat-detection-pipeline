"""
Unusual Region Usage Detector
Detects API calls from unexpected AWS regions which is a common indicator of compromise
References: MITRE ATT&CK T1535 - Unused/Unsupported Cloud Regions
"""

from typing import Optional
from utils.logger import get_logger

logger = get_logger(__name__)

# High-value services — unusual region usage here is particularly suspicious
HIGH_VALUE_SERVICES = {
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "kms.amazonaws.com",
    "secretsmanager.amazonaws.com",
    "s3.amazonaws.com",
    "ec2.amazonaws.com",
    "organizations.amazonaws.com",
    "cloudtrail.amazonaws.com",
}

# Actions that are especially dangerous from unusual regions
CRITICAL_ACTIONS_IN_UNUSUAL_REGIONS = {
    "CreateUser", "CreateRole", "AttachUserPolicy", "AttachRolePolicy",
    "CreateAccessKey", "PutBucketPolicy", "DeleteTrail", "StopLogging",
    "CreateKey", "DisableKey", "DeleteSecret", "GetSecretValue",
    "RunInstances", "CreateVpc", "CreateInternetGateway",
}


class UnusualRegionDetector:
    """
    Detects API activity originating from unexpected or prohibited AWS regions.
    Correlates with organizational baselines to reduce false positives.
    """

    def __init__(self, baseline_regions: list = None):
        self.detector_name = "UnusualRegionDetector"
        self.baseline_regions = set(baseline_regions or ["us-east-1", "us-west-2"])
        logger.info(
            f"Initialized {self.detector_name}",
            extra={"baseline_regions": list(self.baseline_regions)}
        )

    def analyze(self, event: dict) -> Optional[dict]:
        """
        Analyze a CloudTrail event for unusual region usage.

        Args:
            event: Parsed CloudTrail event dictionary

        Returns:
            Finding dict if threat detected, None otherwise
        """
        region = event.get("awsRegion", "")
        event_source = event.get("eventSource", "")
        event_name = event.get("eventName", "")

        # Global services don't have meaningful region context
        if event_source in {"iam.amazonaws.com", "sts.amazonaws.com"}:
            # Still flag unusual regions for IAM/STS as they're high value
            if region not in self.baseline_regions and region not in {"us-east-1", "aws-global"}:
                pass  # Fall through to detection logic
            else:
                return None

        if region in self.baseline_regions or not region:
            return None

        # We have an unusual region so now we assess severity
        severity = self._assess_severity(event_source, event_name, region)
        finding = self._build_finding(event, region, severity)

        logger.warning(
            "Unusual region API activity detected",
            extra={
                "region": region,
                "event_name": event_name,
                "severity": severity,
                "actor": finding["actor"]
            }
        )

        return finding

    def _assess_severity(self, event_source: str, event_name: str, region: str) -> str:
        """Assess the severity of unusual region activity."""
        is_high_value_service = event_source in HIGH_VALUE_SERVICES
        is_critical_action = event_name in CRITICAL_ACTIONS_IN_UNUSUAL_REGIONS

        if is_high_value_service and is_critical_action:
            return "CRITICAL"
        elif is_high_value_service or is_critical_action:
            return "HIGH"
        elif self._is_rare_region(region):
            return "HIGH"
        else:
            return "MEDIUM"

    def _is_rare_region(self, region: str) -> bool:
        """Identify regions that are rarely used legitimately."""
        rare_regions = {
            "ap-east-1", "af-south-1", "eu-south-1", "me-south-1",
            "ap-southeast-3", "ap-south-2", "eu-central-2"
        }
        return region in rare_regions

    def _build_finding(self, event: dict, unusual_region: str, severity: str) -> dict:
        """Construct a standardized finding dictionary."""
        user_identity = event.get("userIdentity", {})
        actor = (
            user_identity.get("arn") or
            user_identity.get("userName") or
            user_identity.get("principalId") or
            "unknown"
        )

        return {
            "finding_type": "UNUSUAL_REGION_ACTIVITY",
            "detector": self.detector_name,
            "severity": severity,
            "mitre_technique": "T1535",
            "action": f"{event.get('eventSource', '').replace('.amazonaws.com', '')}:{event.get('eventName', '')}",
            "actor": actor,
            "account_id": event.get("recipientAccountId", "unknown"),
            "region": unusual_region,
            "baseline_regions": list(self.baseline_regions),
            "source_ip": event.get("sourceIPAddress", "unknown"),
            "user_agent": event.get("userAgent", "unknown"),
            "event_time": event.get("eventTime", "unknown"),
            "description": (
                f"API call in non-baseline region '{unusual_region}' by {actor}. "
                f"Approved regions: {', '.join(self.baseline_regions)}"
            ),
            "risk_factors": ["unusual_region"],
            "remediation": (
                "Investigate whether this region usage is authorized. "
                "If unauthorized, rotate credentials for the affected principal, "
                "review all resources created in this region, and enable GuardDuty globally."
            ),
            "raw_event_id": event.get("eventID", "unknown"),
        }