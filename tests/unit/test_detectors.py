"""
Unit Tests - Threat Detection Pipeline
Tests for detectors, risk scorer and event parser
"""

import json
import sys
import os
import pytest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

from detectors.privilege_escalation import PrivilegeEscalationDetector
from detectors.unusual_region import UnusualRegionDetector
from detectors.credential_abuse import CredentialAbuseDetector
from detectors.data_exfiltration import DataExfiltrationDetector
from processors.risk_scorer import RiskScorer
from processors.event_parser import EventParser


# FIXTURES

@pytest.fixture
def priv_esc_detector():
    return PrivilegeEscalationDetector()

@pytest.fixture
def region_detector():
    return UnusualRegionDetector(baseline_regions=["us-east-1", "us-west-2"])

@pytest.fixture
def cred_detector():
    return CredentialAbuseDetector()

@pytest.fixture
def exfil_detector():
    return DataExfiltrationDetector()

@pytest.fixture
def risk_scorer():
    return RiskScorer()

@pytest.fixture
def event_parser():
    return EventParser()


def make_cloudtrail_event(
    event_name="DescribeInstances",
    event_source="ec2.amazonaws.com",
    region="us-east-1",
    user_type="IAMUser",
    username="alice",
    user_arn="arn:aws:iam::123456789012:user/alice",
    source_ip="203.0.113.42",
    error_code=None,
    request_params=None,
    response_elements=None,
):
    event = {
        "eventID": "test-event-id-1234",
        "eventTime": "2024-01-15T14:23:45Z",
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": "aws-cli/2.0.0",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": user_type,
            "arn": user_arn,
            "userName": username,
            "principalId": f"AIDA{username.upper()}",
            "accountId": "123456789012",
        },
        "requestParameters": request_params or {},
        "responseElements": response_elements or {},
    }
    if error_code:
        event["errorCode"] = error_code
    return event


# PRIVILEGE ESCALATION DETECTOR TESTS

class TestPrivilegeEscalationDetector:

    def test_detects_attach_user_policy(self, priv_esc_detector):
        event = make_cloudtrail_event(
            event_name="AttachUserPolicy",
            event_source="iam.amazonaws.com",
            request_params={"userName": "victim-user", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        )
        finding = priv_esc_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "PRIVILEGE_ESCALATION"
        assert finding["severity"] == "HIGH"

    def test_escalates_to_critical_for_admin_policy(self, priv_esc_detector):
        event = make_cloudtrail_event(
            event_name="AttachUserPolicy",
            event_source="iam.amazonaws.com",
            request_params={
                "userName": "victim-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }
        )
        finding = priv_esc_detector.analyze(event)
        assert finding is not None
        assert finding["severity"] == "CRITICAL"
        assert "dangerous_policy_arn" in finding["risk_factors"]

    def test_no_finding_for_normal_ec2_action(self, priv_esc_detector):
        event = make_cloudtrail_event(
            event_name="DescribeInstances",
            event_source="ec2.amazonaws.com"
        )
        finding = priv_esc_detector.analyze(event)
        assert finding is None

    def test_failed_attempt_has_lower_modifier(self, priv_esc_detector):
        event = make_cloudtrail_event(
            event_name="AttachUserPolicy",
            event_source="iam.amazonaws.com",
            error_code="AccessDenied",
            request_params={"userName": "victim-user", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
        )
        finding = priv_esc_detector.analyze(event)
        assert finding is not None
        assert "failed_attempt" in finding["risk_factors"]
        assert finding.get("base_risk_modifier", 1.0) < 1.0

    def test_detects_create_access_key(self, priv_esc_detector):
        event = make_cloudtrail_event(
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            request_params={"userName": "victim-user"}
        )
        finding = priv_esc_detector.analyze(event)
        assert finding is not None

    def test_detects_update_assume_role_policy(self, priv_esc_detector):
        event = make_cloudtrail_event(
            event_name="UpdateAssumeRolePolicy",
            event_source="iam.amazonaws.com",
            request_params={"roleName": "admin-role"}
        )
        finding = priv_esc_detector.analyze(event)
        assert finding is not None
        assert finding["severity"] == "HIGH"


# UNUSUAL REGION DETECTOR TESTS

class TestUnusualRegionDetector:

    def test_detects_unusual_region(self, region_detector):
        event = make_cloudtrail_event(
            event_name="RunInstances",
            event_source="ec2.amazonaws.com",
            region="ap-southeast-3"
        )
        finding = region_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "UNUSUAL_REGION_ACTIVITY"

    def test_no_finding_for_baseline_region(self, region_detector):
        event = make_cloudtrail_event(
            event_name="RunInstances",
            event_source="ec2.amazonaws.com",
            region="us-east-1"
        )
        finding = region_detector.analyze(event)
        assert finding is None

    def test_critical_for_iam_action_in_unusual_region(self, region_detector):
        event = make_cloudtrail_event(
            event_name="AttachUserPolicy",
            event_source="iam.amazonaws.com",
            region="af-south-1"
        )
        finding = region_detector.analyze(event)
        assert finding is not None
        assert finding["severity"] in {"CRITICAL", "HIGH"}

    def test_unusual_region_finding_includes_baseline(self, region_detector):
        event = make_cloudtrail_event(
            event_name="CreateBucket",
            event_source="s3.amazonaws.com",
            region="eu-south-1"
        )
        finding = region_detector.analyze(event)
        assert finding is not None
        assert "us-east-1" in finding["baseline_regions"]
        assert "us-west-2" in finding["baseline_regions"]


# CREDENTIAL ABUSE DETECTOR TESTS

class TestCredentialAbuseDetector:

    def test_detects_root_usage(self, cred_detector):
        event = make_cloudtrail_event(
            event_name="CreateBucket",
            event_source="s3.amazonaws.com",
            user_type="Root",
            user_arn="arn:aws:iam::123456789012:root",
            username=""
        )
        event["userIdentity"]["type"] = "Root"
        finding = cred_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "ROOT_ACCOUNT_USAGE"
        assert finding["severity"] == "CRITICAL"

    def test_detects_iam_reconnaissance(self, cred_detector):
        event = make_cloudtrail_event(
            event_name="GetAccountAuthorizationDetails",
            event_source="iam.amazonaws.com"
        )
        finding = cred_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "IAM_RECONNAISSANCE"

    def test_detects_create_access_key(self, cred_detector):
        event = make_cloudtrail_event(
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            request_params={"userName": "victim-user"}
        )
        finding = cred_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "CREDENTIAL_MANIPULATION"

    def test_no_finding_for_normal_s3_list(self, cred_detector):
        event = make_cloudtrail_event(
            event_name="GetObject",
            event_source="s3.amazonaws.com"
        )
        finding = cred_detector.analyze(event)
        assert finding is None


# DATA EXFILTRATION DETECTOR TESTS

class TestDataExfiltrationDetector:

    def test_detects_cloudtrail_deletion(self, exfil_detector):
        event = make_cloudtrail_event(
            event_name="DeleteTrail",
            event_source="cloudtrail.amazonaws.com"
        )
        finding = exfil_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "DEFENSE_EVASION_LOGGING_DISRUPTION"
        assert finding["severity"] == "CRITICAL"

    def test_detects_stop_logging(self, exfil_detector):
        event = make_cloudtrail_event(
            event_name="StopLogging",
            event_source="cloudtrail.amazonaws.com"
        )
        finding = exfil_detector.analyze(event)
        assert finding is not None
        assert finding["severity"] == "CRITICAL"

    def test_detects_secret_access(self, exfil_detector):
        event = make_cloudtrail_event(
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            request_params={"secretId": "prod/db/password"}
        )
        finding = exfil_detector.analyze(event)
        assert finding is not None
        assert finding["finding_type"] == "SECRETS_ACCESS"
        assert finding["severity"] == "HIGH"

    def test_detects_s3_public_access_removal(self, exfil_detector):
        event = make_cloudtrail_event(
            event_name="DeletePublicAccessBlock",
            event_source="s3.amazonaws.com",
            request_params={"bucketName": "sensitive-data-bucket"}
        )
        finding = exfil_detector.analyze(event)
        assert finding is not None
        assert finding["severity"] == "CRITICAL"


# RISK SCORER TESTS

class TestRiskScorer:

    def test_critical_severity_high_score(self, risk_scorer):
        finding = {
            "finding_type": "ROOT_ACCOUNT_USAGE",
            "severity": "CRITICAL",
            "risk_factors": ["root_account", "critical_identity"]
        }
        score = risk_scorer.score(finding)
        assert score >= 80

    def test_low_severity_low_score(self, risk_scorer):
        finding = {
            "finding_type": "S3_DATA_EXFILTRATION",
            "severity": "LOW",
            "risk_factors": ["s3_access"]
        }
        score = risk_scorer.score(finding)
        assert score <= 50

    def test_score_clamped_to_100(self, risk_scorer):
        finding = {
            "finding_type": "TEST",
            "severity": "CRITICAL",
            "risk_factors": [
                "root_account", "critical_identity", "defense_evasion",
                "logging_disruption", "covering_tracks", "dangerous_policy_arn"
            ]
        }
        score = risk_scorer.score(finding)
        assert score <= 100

    def test_score_clamped_to_0(self, risk_scorer):
        finding = {
            "finding_type": "TEST",
            "severity": "LOW",
            "risk_factors": ["failed_attempt"],
            "base_risk_modifier": 0.1
        }
        score = risk_scorer.score(finding)
        assert score >= 0

    def test_prioritize_sorts_by_score(self, risk_scorer):
        findings = [
            {"finding_type": "A", "risk_score": 30, "actor": "a", "action": "a"},
            {"finding_type": "B", "risk_score": 90, "actor": "b", "action": "b"},
            {"finding_type": "C", "risk_score": 60, "actor": "c", "action": "c"},
        ]
        sorted_findings = risk_scorer.prioritize(findings)
        assert sorted_findings[0]["risk_score"] == 90
        assert sorted_findings[-1]["risk_score"] == 30

    def test_prioritize_deduplicates(self, risk_scorer):
        findings = [
            {"finding_type": "A", "risk_score": 70, "actor": "alice", "action": "iam:CreateUser"},
            {"finding_type": "A", "risk_score": 70, "actor": "alice", "action": "iam:CreateUser"},
        ]
        deduped = risk_scorer.prioritize(findings)
        assert len(deduped) == 1


# EVENT PARSER TESTS

class TestEventParser:

    def test_parses_cloudtrail_records_format(self, event_parser):
        records = {
            "Records": [
                {"eventName": "CreateUser", "eventSource": "iam.amazonaws.com"},
                {"eventName": "DeleteUser", "eventSource": "iam.amazonaws.com"},
            ]
        }
        result = event_parser.parse(json.dumps(records))
        assert len(result) == 2
        assert result[0]["eventName"] == "CreateUser"

    def test_parses_single_event(self, event_parser):
        event = {"eventName": "DescribeInstances", "eventSource": "ec2.amazonaws.com"}
        result = event_parser.parse(json.dumps(event))
        assert len(result) == 1

    def test_handles_invalid_json(self, event_parser):
        result = event_parser.parse("not-valid-json{{{")
        assert result == []

    def test_handles_empty_records(self, event_parser):
        result = event_parser.parse(json.dumps({"Records": []}))
        assert result == []