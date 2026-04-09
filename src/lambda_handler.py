"""
Cloud Threat Detection Pipeline - Main Lambda Handler
Processes CloudTrail events from CloudWatch Logs and generates prioritized alerts
"""

import json
import base64
import gzip
import logging
import os
from datetime import datetime
from typing import Any

from detectors.privilege_escalation import PrivilegeEscalationDetector
from detectors.unusual_region import UnusualRegionDetector
from detectors.credential_abuse import CredentialAbuseDetector
from detectors.data_exfiltration import DataExfiltrationDetector
from processors.event_parser import EventParser
from processors.risk_scorer import RiskScorer
from alerts.alert_manager import AlertManager
from utils.logger import get_logger

logger = get_logger(__name__)


def lambda_handler(event: dict, context: Any) -> dict:
    """
    Main Lambda entry point. Receives CloudWatch Logs subscription filter events
    containing CloudTrail log data.

    Args:
        event: CloudWatch Logs event containing base64-encoded, gzip-compressed log data
        context: Lambda context object

    Returns:
        dict: Processing summary with alert counts and status
    """
    logger.info("Threat detection pipeline invoked", extra={
        "request_id": context.aws_request_id,
        "function_name": context.function_name,
        "remaining_time_ms": context.get_remaining_time_in_millis()
    })

    # Decode and decompress CloudWatch Logs data
    raw_payload = base64.b64decode(event["awslogs"]["data"])
    decompressed = gzip.decompress(raw_payload)
    log_data = json.loads(decompressed)

    logger.info(f"Processing {len(log_data.get('logEvents', []))} log events from {log_data.get('logGroup', 'unknown')}")

    # Initialize components
    event_parser = EventParser()
    risk_scorer = RiskScorer()
    alert_manager = AlertManager(
        sns_topic_arn=os.environ.get("SNS_ALERT_TOPIC_ARN"),
        sqs_queue_url=os.environ.get("SQS_ALERT_QUEUE_URL"),
        dynamodb_table=os.environ.get("ALERTS_DYNAMODB_TABLE", "threat-detection-alerts")
    )

    # Initialize detectors
    detectors = [
        PrivilegeEscalationDetector(),
        UnusualRegionDetector(baseline_regions=_get_baseline_regions()),
        CredentialAbuseDetector(),
        DataExfiltrationDetector(),
    ]

    processed_count = 0
    alert_count = 0
    findings = []

    for log_event in log_data.get("logEvents", []):
        try:
            # Parse CloudTrail event from log message
            ct_events = event_parser.parse(log_event["message"])

            for ct_event in ct_events:
                processed_count += 1

                # Run each detector against the event
                for detector in detectors:
                    finding = detector.analyze(ct_event)
                    if finding:
                        # Calculate risk score
                        risk_score = risk_scorer.score(finding, ct_event)
                        finding["risk_score"] = risk_score
                        finding["timestamp"] = datetime.utcnow().isoformat() + "Z"
                        finding["event_id"] = ct_event.get("eventID", "unknown")
                        findings.append(finding)

        except Exception as e:
            logger.error(f"Error processing log event: {e}", exc_info=True)
            continue

    # Deduplicate and prioritize findings
    prioritized_findings = risk_scorer.prioritize(findings)

    # Generate and send alerts
    for finding in prioritized_findings:
        try:
            alert_manager.send_alert(finding)
            alert_count += 1
        except Exception as e:
            logger.error(f"Failed to send alert for finding {finding.get('finding_id')}: {e}")

    summary = {
        "statusCode": 200,
        "body": {
            "processed_events": processed_count,
            "findings_generated": len(findings),
            "alerts_sent": alert_count,
            "high_severity_count": sum(1 for f in prioritized_findings if f["risk_score"] >= 80),
            "medium_severity_count": sum(1 for f in prioritized_findings if 50 <= f["risk_score"] < 80),
            "low_severity_count": sum(1 for f in prioritized_findings if f["risk_score"] < 50),
            "execution_id": context.aws_request_id
        }
    }

    logger.info("Pipeline execution complete", extra=summary["body"])
    return summary


def _get_baseline_regions() -> list:
    """Load approved baseline regions from environment or default."""
    baseline = os.environ.get("BASELINE_REGIONS", "us-east-1,us-west-2,eu-west-1")
    return [r.strip() for r in baseline.split(",")]