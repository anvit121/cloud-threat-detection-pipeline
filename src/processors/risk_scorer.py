"""
Risk Scorer
Multi-factor risk scoring engine for threat findings
Produces a 0-100 risk score used to prioritize alerts
"""

from typing import List
from utils.logger import get_logger

logger = get_logger(__name__)

# Base scores by severity
SEVERITY_BASE_SCORES = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 45,
    "LOW": 20,
}

# Score modifiers for contextual risk factors
RISK_FACTOR_MODIFIERS = {
    "root_account": +15,
    "dangerous_policy_arn": +12,
    "defense_evasion": +15,
    "logging_disruption": +10,
    "covering_tracks": +8,
    "unusual_region": +8,
    "no_mfa": +10,
    "failed_attempt": -15,  # Failed = less immediate threat but shows probing
    "reconnaissance": +5,
    "iam_enumeration": +5,
    "credential_manipulation": +7,
    "s3_access": +3,
    "potential_exfiltration": +5,
    "secrets_access": +8,
    "privilege_escalation_action": +5,
    "critical_identity": +10,
}


class RiskScorer:
    """
    Calculates a composite risk score for each threat finding.
    Scores range from 0 (lowest risk) to 100 (critical).
    """

    def score(self, finding: dict, original_event: dict = None) -> int:
        """
        Calculate a risk score for a finding.

        Args:
            finding: Threat finding from a detector
            original_event: Original CloudTrail event for additional context

        Returns:
            Integer risk score from 0-100
        """
        severity = finding.get("severity", "LOW")
        base_score = SEVERITY_BASE_SCORES.get(severity, 20)

        # Apply risk factor modifiers
        modifier_sum = 0
        for factor in finding.get("risk_factors", []):
            modifier_sum += RISK_FACTOR_MODIFIERS.get(factor, 0)

        # Apply optional base_risk_modifier (eg, failed attempts)
        base_modifier = finding.get("base_risk_modifier", 1.0)

        raw_score = (base_score + modifier_sum) * base_modifier

        # Apply contextual boosts from original event
        if original_event:
            raw_score = self._apply_contextual_scoring(raw_score, original_event)

        # Clamp to 0-100
        final_score = max(0, min(100, int(raw_score)))

        logger.debug(
            f"Risk score calculated",
            extra={
                "finding_type": finding.get("finding_type"),
                "base_score": base_score,
                "modifiers": modifier_sum,
                "final_score": final_score
            }
        )

        return final_score

    def _apply_contextual_scoring(self, score: float, event: dict) -> float:
        """Apply additional score adjustments based on event context."""
        boost = 0

        # Error-free execution of high-risk action = higher confidence
        if not event.get("errorCode"):
            boost += 5

        # Off-hours activity
        event_time = event.get("eventTime", "")
        if event_time:
            try:
                hour = int(event_time[11:13])
                if hour < 6 or hour > 22:  # Outside 6am-10pm UTC
                    boost += 5
            except (ValueError, IndexError):
                pass

        # Source IP is a known cloud provider IP range (potential SSRF or lateral movement)
        source_ip = event.get("sourceIPAddress", "")
        if source_ip.startswith(("54.", "52.", "18.", "34.", "35.")):
            boost += 3  # May be internal service, flag but small boost

        return score + boost

    def prioritize(self, findings: List[dict]) -> List[dict]:
        """
        Sort findings by risk score descending and deduplicate.

        Args:
            findings: List of finding dicts with risk_score populated

        Returns:
            Sorted, deduplicated list of findings
        """
        if not findings:
            return []

        # Deduplicate by (finding_type, actor, action) within same execution
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (
                finding.get("finding_type", ""),
                finding.get("actor", ""),
                finding.get("action", ""),
            )
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        # Add a unique finding ID
        for i, finding in enumerate(unique_findings):
            finding["finding_id"] = f"TDF-{finding.get('account_id', 'UNKNOWN')[:8]}-{i:04d}"

        # Sort by risk score descending
        return sorted(unique_findings, key=lambda f: f.get("risk_score", 0), reverse=True)