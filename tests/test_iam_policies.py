import json

import boto3
from moto import mock_aws

from checks.iam_policies import (
    check_customer_managed_wildcards,
    check_directly_attached_admin_policies,
    check_inline_policies,
)

WILDCARD = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
SCOPED = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket",
                   "Resource": "arn:aws:s3:::example"}],
}


@mock_aws
def test_flags_administrator_access_attached_directly():
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    policy = iam.create_policy(
        PolicyName="AdministratorAccess", PolicyDocument=json.dumps(WILDCARD)
    )
    iam.attach_user_policy(UserName="alice", PolicyArn=policy["Policy"]["Arn"])
    findings = check_directly_attached_admin_policies(iam)
    assert len(findings) == 1
    assert findings[0]["resource"] == "alice"
    assert findings[0]["severity"] == "High"


@mock_aws
def test_no_findings_when_user_has_no_admin_policy():
    iam = boto3.client("iam")
    iam.create_user(UserName="bob")
    assert check_directly_attached_admin_policies(iam) == []


@mock_aws
def test_flags_customer_managed_wildcard_policy():
    iam = boto3.client("iam")
    iam.create_policy(PolicyName="too-broad", PolicyDocument=json.dumps(WILDCARD))
    findings = check_customer_managed_wildcards(iam)
    assert [f["resource"] for f in findings] == ["too-broad"]


@mock_aws
def test_scoped_customer_managed_policy_is_not_flagged():
    iam = boto3.client("iam")
    iam.create_policy(PolicyName="scoped", PolicyDocument=json.dumps(SCOPED))
    assert check_customer_managed_wildcards(iam) == []


@mock_aws
def test_flags_inline_wildcard_policy():
    iam = boto3.client("iam")
    iam.create_user(UserName="carol")
    iam.put_user_policy(
        UserName="carol", PolicyName="inline-all", PolicyDocument=json.dumps(WILDCARD)
    )
    findings = check_inline_policies(iam)
    assert len(findings) == 1
    assert "carol" in findings[0]["resource"]