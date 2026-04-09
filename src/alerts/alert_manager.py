"""
Alert Manager
Handles alert routing to SNS, SQS and DynamoDB persistence
Also Supports severity-based routing and alert deduplication
"""

import json
import uuid
import boto3
from botocore.exceptions import ClientError
from utils.logger import get_logger

logger = get_logger(__name__)

# Severity thresholds for different alert channels
SNS_SEVERITY_THRESHOLD = {"CRITICAL", "HIGH"}
SQS_ALL_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

class AlertManager:

    def __init__(self, sns_topic_arn: str = None, sqs_queue_url: str = None, dynamodb_table: str = None):
        self.sns_topic_arn = sns_topic_arn
        self.sqs_queue_url = sqs_queue_url
        self.dynamodb_table = dynamodb_table

        self._sns = boto3.client("sns")
        self._sqs = boto3.client("sqs")
        self._dynamodb = boto3.resource("dynamodb")

        logger.info(
            "AlertManager initialized",
            extra={
                "sns_configured": bool(sns_topic_arn),
                "sqs_configured": bool(sqs_queue_url),
                "dynamodb_configured": bool(dynamodb_table)
            }
        )

    def send_alert(self, finding: dict) -> bool:
        """
        Route a finding to appropriate alerting channels based on severity.

        Args:
            finding: Threat finding with risk_score populated

        Returns:
            True if alert was sent successfully
        """
        severity = finding.get("severity", "LOW")
        finding_id = finding.get("finding_id", str(uuid.uuid4()))

        success = True

        # Always persist to DynamoDB
        if self.dynamodb_table:
            success &= self._persist_to_dynamodb(finding, finding_id)

        # High severity -> SNS (PagerDuty/Slack/email integration)
        if severity in SNS_SEVERITY_THRESHOLD and self.sns_topic_arn:
            success &= self._send_to_sns(finding, finding_id)

        # Medium+ severity -> SQS (SIEM integration, ticketing)
        if severity in {"CRITICAL", "HIGH", "MEDIUM"} and self.sqs_queue_url:
            success &= self._send_to_sqs(finding, finding_id)

        return success

    def _send_to_sns(self, finding: dict, finding_id: str) -> bool:
        """Publish high-severity alert to SNS topic."""
        try:
            message = self._format_sns_message(finding)
            self._sns.publish(
                TopicArn=self.sns_topic_arn,
                Subject=f"[{finding['severity']}] Cloud Threat: {finding.get('finding_type', 'UNKNOWN')}",
                Message=message,
                MessageAttributes={
                    "severity": {"DataType": "String", "StringValue": finding.get("severity", "UNKNOWN")},
                    "finding_type": {"DataType": "String", "StringValue": finding.get("finding_type", "UNKNOWN")},
                    "account_id": {"DataType": "String", "StringValue": finding.get("account_id", "UNKNOWN")},
                }
            )
            logger.info(f"SNS alert sent for finding {finding_id}")
            return True
        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e.response['Error']['Message']}")
            return False

    def _send_to_sqs(self, finding: dict, finding_id: str) -> bool:
        """Send finding to SQS for downstream processing."""
        try:
            self._sqs.send_message(
                QueueUrl=self.sqs_queue_url,
                MessageBody=json.dumps(finding, default=str),
                MessageGroupId=finding.get("account_id", "default"),
                MessageDeduplicationId=finding_id,
                MessageAttributes={
                    "severity": {"DataType": "String", "StringValue": finding.get("severity", "UNKNOWN")},
                    "risk_score": {"DataType": "Number", "StringValue": str(finding.get("risk_score", 0))},
                }
            )
            logger.info(f"SQS message sent for finding {finding_id}")
            return True
        except ClientError as e:
            logger.error(f"Failed to send SQS message: {e.response['Error']['Message']}")
            return False

    def _persist_to_dynamodb(self, finding: dict, finding_id: str) -> bool:
        """Persist finding to DynamoDB for audit trail and querying."""
        try:
            table = self._dynamodb.Table(self.dynamodb_table)
            item = {
                **finding,
                "finding_id": finding_id,
                "ttl": self._get_ttl_timestamp(days=90),  # 90-day retention
            }
            # Convert floats for DynamoDB compatibility
            item = json.loads(json.dumps(item, default=str))
            table.put_item(Item=item)
            logger.debug(f"Finding persisted to DynamoDB: {finding_id}")
            return True
        except ClientError as e:
            logger.error(f"Failed to persist to DynamoDB: {e.response['Error']['Message']}")
            return False

    def _format_sns_message(self, finding: dict) -> str:
        """Format a human-readable SNS alert message."""
        return (
            f"🚨 THREAT DETECTED\n"
            f"{'=' * 50}\n"
            f"Finding ID:    {finding.get('finding_id', 'N/A')}\n"
            f"Type:          {finding.get('finding_type', 'N/A')}\n"
            f"Severity:      {finding.get('severity', 'N/A')}\n"
            f"Risk Score:    {finding.get('risk_score', 'N/A')}/100\n"
            f"MITRE:         {finding.get('mitre_technique', 'N/A')}\n"
            f"{'=' * 50}\n"
            f"Actor:         {finding.get('actor', 'N/A')}\n"
            f"Account:       {finding.get('account_id', 'N/A')}\n"
            f"Region:        {finding.get('region', 'N/A')}\n"
            f"Source IP:     {finding.get('source_ip', 'N/A')}\n"
            f"Action:        {finding.get('action', 'N/A')}\n"
            f"Time:          {finding.get('event_time', 'N/A')}\n"
            f"{'=' * 50}\n"
            f"Description:\n{finding.get('description', 'N/A')}\n\n"
            f"Remediation:\n{finding.get('remediation', 'N/A')}\n"
        )

    def _get_ttl_timestamp(self, days: int) -> int:
        """Calculate DynamoDB TTL timestamp."""
        from datetime import datetime, timedelta
        expiry = datetime.utcnow() + timedelta(days=days)
        return int(expiry.timestamp())