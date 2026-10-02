import boto3
from moto import mock_aws

from checks.cloudtrail import check_cloudtrail


def make_trail(multi_region=True, validation=True):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-logs")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="test-trail",
        S3BucketName="trail-logs",
        IsMultiRegionTrail=multi_region,
        EnableLogFileValidation=validation,
    )
    return ct


@mock_aws
def test_no_trail_is_flagged():
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    findings = check_cloudtrail(ct)
    assert [f["description"] for f in findings] == ["No CloudTrail trail exists"]


@mock_aws
def test_trail_that_is_not_logging_is_flagged():
    ct = make_trail()
    findings = check_cloudtrail(ct)
    assert "Trail exists but logging is stopped" in [f["description"] for f in findings]


@mock_aws
def test_healthy_trail_has_no_findings():
    ct = make_trail()
    ct.start_logging(Name="test-trail")
    assert check_cloudtrail(ct) == []


@mock_aws
def test_single_region_trail_is_flagged():
    ct = make_trail(multi_region=False)
    ct.start_logging(Name="test-trail")
    descriptions = [f["description"] for f in check_cloudtrail(ct)]
    assert any("No multi-region trail" in d for d in descriptions)


@mock_aws
def test_disabled_log_validation_is_medium():
    ct = make_trail(validation=False)
    ct.start_logging(Name="test-trail")
    findings = check_cloudtrail(ct)
    assert [f["severity"] for f in findings] == ["Medium"]