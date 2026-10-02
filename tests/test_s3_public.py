import json
from unittest.mock import MagicMock
from checks.s3_public import check_all_buckets, check_bucket_policy_public
import boto3
from moto import mock_aws
from checks.s3_public import check_all_buckets

ALL_BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
NONE_BLOCKED = {key: False for key in ALL_BLOCKED}


def descriptions(findings):
    return [f["description"] for f in findings]


@mock_aws
def test_flags_bucket_with_no_public_access_block():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="no-block")
    assert "No Block Public Access configuration exists" in descriptions(check_all_buckets(s3))


@mock_aws
def test_flags_bucket_with_block_public_access_disabled():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="open-block")
    s3.put_public_access_block(Bucket="open-block", PublicAccessBlockConfiguration=NONE_BLOCKED)
    assert "Block Public Access is not fully enabled" in descriptions(check_all_buckets(s3))


@mock_aws
def test_locked_down_bucket_has_no_findings():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="locked")
    s3.put_public_access_block(Bucket="locked", PublicAccessBlockConfiguration=ALL_BLOCKED)
    assert check_all_buckets(s3) == []


@mock_aws
def test_flags_bucket_when_aws_reports_policy_as_public():
    s3 = MagicMock()
    s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": True}}
    finding = check_bucket_policy_public(s3, "my-bucket")
    assert finding["description"] == "Bucket policy allows public access"
    assert finding["severity"] == "High"


def test_does_not_flag_bucket_when_aws_reports_policy_as_private():
    s3 = MagicMock()
    s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
    assert check_bucket_policy_public(s3, "my-bucket") is None


def test_missing_is_public_field_does_not_crash():
    s3 = MagicMock()
    s3.get_bucket_policy_status.return_value = {"PolicyStatus": {}}
    assert check_bucket_policy_public(s3, "my-bucket") is None


@mock_aws
def test_flags_public_acl():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-acl")
    s3.put_bucket_acl(Bucket="public-acl", ACL="public-read")
    assert any("AllUsers" in d for d in descriptions(check_all_buckets(s3)))