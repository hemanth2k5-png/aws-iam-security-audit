import boto3
from moto import mock_aws

import lambda_handler
from lambda_handler import build_message


def test_build_message_masks_account_and_lists_findings():
    findings = [{"severity": "High", "category": "IAM Policy", "resource": "alice", "description": "d"}]
    counts = {"High": 1, "Medium": 0, "Low": 0}
    message = build_message(findings, counts, "123456789012")
    assert "****9012" in message
    assert "123456789012" not in message
    assert "[High] IAM Policy - alice: d" in message


def test_build_message_truncates_long_lists():
    findings = [{"severity": "Low", "category": "C", "resource": str(i), "description": "d"}
                for i in range(25)]
    message = build_message(findings, {"High": 0, "Medium": 0, "Low": 25}, "123456789012")
    assert "...and 5 more." in message


@mock_aws
def test_handler_publishes_summary_to_sns(monkeypatch):
    sns = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="alerts")["TopicArn"]
    monkeypatch.setenv("TOPIC_ARN", topic_arn)

    result = lambda_handler.handler({}, None)

    assert result["statusCode"] == 200
    assert result["total"] >= 1

@mock_aws
def test_handler_saves_history_when_bucket_is_configured(monkeypatch):
    sns = boto3.client("sns", region_name="us-east-1")
    topic_arn = sns.create_topic(Name="alerts")["TopicArn"]
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="history")
    monkeypatch.setenv("TOPIC_ARN", topic_arn)
    monkeypatch.setenv("FINDINGS_BUCKET", "history")

    result = lambda_handler.handler({}, None)

    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="history")["Contents"]]
    assert result["run_id"] is not None
    assert any(k.startswith("runs/") for k in keys)