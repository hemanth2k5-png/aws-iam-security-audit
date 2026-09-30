import boto3

from checks.iam_policies import check_all_policy_findings
from checks.s3_public import check_all_buckets
from checks.security_groups import check_security_groups
from checks.cloudtrail import check_cloudtrail
from report import prepare, summarize, write_all

PROFILE = "audit-tool"

session = boto3.Session(profile_name=PROFILE)
region = session.region_name
account_id = session.client("sts").get_caller_identity()["Account"]

iam = session.client("iam")
s3 = session.client("s3")
ec2 = session.client("ec2")
cloudtrail = session.client("cloudtrail")

raw = []
raw += check_all_policy_findings(iam)
raw += check_all_buckets(s3)
raw += check_security_groups(ec2)
raw += check_cloudtrail(cloudtrail)
# keep your Day 3 credential report check here too

findings = prepare(raw)
counts = summarize(findings)

for f in findings:
    print(f"[{f['severity']}] {f['category']} - {f['resource']}: {f['description']}")

print(f"\nHigh: {counts['High']} | Medium: {counts['Medium']} | Low: {counts['Low']} | Total: {len(findings)}")

paths = write_all(findings, account_id, PROFILE, region)
print("\nReports written:")
for kind, path in paths.items():
    print(f"  {kind}: {path}")