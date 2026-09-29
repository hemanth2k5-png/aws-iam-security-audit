import boto3
from checks.iam_policies import check_all_policy_findings
from checks.s3_public import check_all_buckets

session = boto3.Session(profile_name="audit-tool")
iam = session.client("iam")
s3 = session.client("s3")

findings = []
findings += check_all_policy_findings(iam)
findings += check_all_buckets(s3)

for f in findings:
    print(f)

print(f"\nTotal findings: {len(findings)}")