import boto3
from moto import mock_aws

from checks.security_groups import check_security_groups


def make_group(ec2, name):
    return ec2.create_security_group(GroupName=name, Description="test")["GroupId"]


def allow(ec2, group_id, protocol, from_port, to_port, cidr="0.0.0.0/0"):
    permission = {"IpProtocol": protocol, "IpRanges": [{"CidrIp": cidr}]}
    if from_port is not None:
        permission["FromPort"] = from_port
        permission["ToPort"] = to_port
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[permission])


def findings_for(findings, name):
    return [f for f in findings if name in f["resource"]]


@mock_aws
def test_ssh_open_to_world_is_high():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    allow(ec2, make_group(ec2, "ssh-open"), "tcp", 22, 22)
    result = findings_for(check_security_groups(ec2), "ssh-open")
    assert len(result) == 1
    assert result[0]["severity"] == "High"
    assert "22" in result[0]["description"]


@mock_aws
def test_non_sensitive_port_open_to_world_is_medium():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    allow(ec2, make_group(ec2, "web-open"), "tcp", 8080, 8080)
    result = findings_for(check_security_groups(ec2), "web-open")
    assert [f["severity"] for f in result] == ["Medium"]


@mock_aws
def test_all_traffic_open_is_high():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    allow(ec2, make_group(ec2, "all-open"), "-1", None, None)
    result = findings_for(check_security_groups(ec2), "all-open")
    assert result[0]["severity"] == "High"
    assert "All traffic" in result[0]["description"]


@mock_aws
def test_wide_port_range_covers_sensitive_port():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    allow(ec2, make_group(ec2, "range-open"), "tcp", 0, 65535)
    result = findings_for(check_security_groups(ec2), "range-open")
    assert result[0]["severity"] == "High"


@mock_aws
def test_restricted_cidr_is_not_flagged():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    allow(ec2, make_group(ec2, "private-ssh"), "tcp", 22, 22, cidr="10.0.0.0/8")
    assert findings_for(check_security_groups(ec2), "private-ssh") == []


@mock_aws
def test_ipv6_open_to_world_is_flagged():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    group_id = make_group(ec2, "v6-open")
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
    )
    assert findings_for(check_security_groups(ec2), "v6-open")