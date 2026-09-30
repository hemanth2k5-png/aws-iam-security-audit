import boto3
from checks.iam_policies import check_all_policy_findings
from checks.s3_public import check_all_buckets
from checks.security_groups import check_security_groups


session = boto3.Session(profile_name="audit-tool")
iam = session.client("iam")
s3 = session.client("s3")

findings = []
findings += check_all_policy_findings(iam)
findings += check_all_buckets(s3)

ec2 = session.client("ec2")
findings += check_security_groups(ec2)

for f in findings:
    print(f)

print(f"\nTotal findings: {len(findings)}")


