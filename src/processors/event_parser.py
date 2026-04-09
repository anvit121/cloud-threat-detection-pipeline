"""
CloudTrail Event Parser
Handles parsing of CloudTrail log messages from CloudWatch Logs subscription filters
Supports both single events and batch CloudTrail Records format
"""

import json
from typing import List
from utils.logger import get_logger

logger = get_logger(__name__)


class EventParser:

    def parse(self, raw_message: str) -> List[dict]:
        
        try:
            data = json.loads(raw_message)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse log message as JSON: {e}")
            return []

        # CloudTrail delivers as {"Records": [...]}
        if isinstance(data, dict) and "Records" in data:
            records = data["Records"]
            logger.debug(f"Parsed CloudTrail batch: {len(records)} records")
            return [r for r in records if isinstance(r, dict)]

        # Single event (eg, from real-time stream)
        if isinstance(data, dict) and "eventName" in data:
            return [data]

        logger.warning(f"Unrecognized CloudTrail message format: {list(data.keys()) if isinstance(data, dict) else type(data)}")
        return []

    def extract_principal(self, event: dict) -> str:
        
        user_identity = event.get("userIdentity", {})
        identity_type = user_identity.get("type", "")

        if identity_type == "Root":
            return f"ROOT:{event.get('recipientAccountId', 'unknown')}"
        elif identity_type == "IAMUser":
            return user_identity.get("userName", "unknown_user")
        elif identity_type == "AssumedRole":
            session = user_identity.get("sessionContext", {})
            session_issuer = session.get("sessionIssuer", {})
            role_name = session_issuer.get("userName", "unknown_role")
            session_name = user_identity.get("arn", "").split("/")[-1]
            return f"{role_name}/{session_name}"
        elif identity_type == "AWSService":
            return user_identity.get("invokedBy", "aws_service")
        else:
            return user_identity.get("arn") or user_identity.get("principalId") or "unknown"