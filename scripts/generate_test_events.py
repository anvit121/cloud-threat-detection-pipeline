#!/usr/bin/env python3
"""
generate_test_events.py
Generates synthetic CloudTrail events for local testing of the threat detection pipeline
How to use: python scripts/generate_test_events.py | python src/lambda_handler_local.py
"""

import json
import base64
import gzip
import random
import uuid
from datetime import datetime, timedelta

ACCOUNT_ID = "123456789012"
USERS = ["alice", "bob", "charlie", "eve-attacker"]
REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-3", "af-south-1"]

def make_event(event_name, event_source, user="alice", region="us-east-1",
               request_params=None, error_code=None, user_type="IAMUser"):
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": user_type,
            "principalId": f"AIDAI{user.upper()}",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{user}",
            "accountId": ACCOUNT_ID,
            "userName": user if user_type != "Root" else None,
        },
        "eventTime": (datetime.utcnow() - timedelta(minutes=random.randint(0, 60))).isoformat() + "Z",
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": f"203.0.113.{random.randint(1, 254)}",
        "userAgent": "aws-cli/2.0.0 Python/3.12",
        "requestParameters": request_params or {},
        "responseElements": {},
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": False,
        "recipientAccountId": ACCOUNT_ID,
    }
    if error_code:
        event["errorCode"] = error_code
    return event


# Scenario 1: Privilege Escalation Attack
priv_esc_events = [
    make_event("GetAccountAuthorizationDetails", "iam.amazonaws.com", user="eve-attacker"),
    make_event("ListUsers", "iam.amazonaws.com", user="eve-attacker"),
    make_event("ListRoles", "iam.amazonaws.com", user="eve-attacker"),
    make_event("CreateAccessKey", "iam.amazonaws.com", user="eve-attacker",
               request_params={"userName": "admin-user"}),
    make_event("AttachUserPolicy", "iam.amazonaws.com", user="eve-attacker",
               request_params={
                   "userName": "eve-attacker",
                   "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
               }),
]

# Scenario 2: Unusual Region Usage
unusual_region_events = [
    make_event("RunInstances", "ec2.amazonaws.com", region="af-south-1"),
    make_event("CreateVpc", "ec2.amazonaws.com", region="ap-east-1"),
    make_event("GetSecretValue", "secretsmanager.amazonaws.com", region="af-south-1",
               request_params={"secretId": "prod/database/master"}),
]

# Scenario 3: Defense Evasion (covering tracks)
defense_evasion_events = [
    make_event("StopLogging", "cloudtrail.amazonaws.com", user="eve-attacker"),
    make_event("DeleteTrail", "cloudtrail.amazonaws.com", user="eve-attacker"),
]

# Scenario 4: Root Account Usage
root_events = [
    make_event("CreateUser", "iam.amazonaws.com", user="root", user_type="Root",
               request_params={"userName": "new-backdoor-user"}),
]

all_events = priv_esc_events + unusual_region_events + defense_evasion_events + root_events

# Package as CloudWatch Logs format
log_events = [
    {"id": str(uuid.uuid4()), "timestamp": 1700000000000, "message": json.dumps({"Records": [event]})}
    for event in all_events
]

payload = {
    "messageType": "DATA_MESSAGE",
    "owner": ACCOUNT_ID,
    "logGroup": f"/aws/cloudtrail/threat-detection-test",
    "logStream": "123456789012_CloudTrail_us-east-1",
    "subscriptionFilters": ["threat-detection-filter"],
    "logEvents": log_events,
}

compressed = gzip.compress(json.dumps(payload).encode())
encoded = base64.b64encode(compressed).decode()

output = {"awslogs": {"data": encoded}}
print(json.dumps(output, indent=2))
print(f"\n# Generated {len(all_events)} test CloudTrail events across 4 attack scenarios", flush=True)