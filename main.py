import boto3
from checks.iam_policies import check_all_policy_findings

session = boto3.Session(profile_name="audit-tool")
iam = session.client("iam")

findings = check_all_policy_findings(iam)
for f in findings:
    print(f)

print(f"\nTotal findings: {len(findings)}")