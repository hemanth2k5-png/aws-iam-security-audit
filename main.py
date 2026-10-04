import argparse
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from checks.iam_policies import check_all_policy_findings
from checks.s3_public import check_all_buckets
from checks.security_groups import check_security_groups
from checks.cloudtrail import check_cloudtrail
from report import SEVERITY_ORDER, prepare, summarize, write_all

DEFAULT_PROFILE = "audit-tool"
ALL_FORMATS = ("json", "csv", "html")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Read-only AWS security audit: IAM, S3, security groups, CloudTrail.",
    )
    parser.add_argument("--profile", default=DEFAULT_PROFILE,
                        help=f"AWS CLI profile to use (default: {DEFAULT_PROFILE})")
    parser.add_argument("--region", default=None,
                        help="Region for regional checks (default: the profile's region)")
    parser.add_argument("--output-dir", default="reports",
                        help="Folder for generated reports (default: reports)")
    parser.add_argument("--format", choices=[*ALL_FORMATS, "all"], default="all",
                        help="Report format to write (default: all)")
    parser.add_argument("--min-severity", choices=["Low", "Medium", "High"], default="Low",
                        help="Only include findings at or above this severity")
    parser.add_argument("--fail-on", choices=["Low", "Medium", "High", "none"], default="none",
                        help="Exit with code 2 if any finding is at or above this severity")
    parser.add_argument("--quiet", action="store_true",
                        help="Do not print individual findings")
    return parser.parse_args(argv)


def collect_findings(session):
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    cloudtrail = session.client("cloudtrail")

    raw = []
    raw += check_all_policy_findings(iam)
    raw += check_all_buckets(s3)
    raw += check_security_groups(ec2)
    raw += check_cloudtrail(cloudtrail)
    
    return raw


def main(argv=None):
    args = parse_args(argv)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        region = session.region_name
        if not region:
            print("No region set. Pass --region or set one with: "
                  f"aws configure --profile {args.profile}", file=sys.stderr)
            return 1
        account_id = session.client("sts").get_caller_identity()["Account"]
        raw = collect_findings(session)
    except ProfileNotFound:
        print(f"Profile '{args.profile}' not found. Create it with: "
              f"aws configure --profile {args.profile}", file=sys.stderr)
        return 1
    except NoCredentialsError:
        print("No AWS credentials found for this profile.", file=sys.stderr)
        return 1
    except ClientError as err:
        print(f"AWS error: {err}", file=sys.stderr)
        return 1

    findings = prepare(raw)
    cutoff = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 3) <= cutoff]
    counts = summarize(findings)

    if not args.quiet:
        for f in findings:
            print(f"[{f['severity']}] {f['category']} - {f['resource']}: {f['description']}")

    print(f"\nHigh: {counts['High']} | Medium: {counts['Medium']} | "
          f"Low: {counts['Low']} | Total: {len(findings)}")

    formats = ALL_FORMATS if args.format == "all" else (args.format,)
    paths = write_all(findings, account_id, args.profile, region,
                      out_dir=args.output_dir, formats=formats)
    print("\nReports written:")
    for kind, path in paths.items():
        print(f"  {kind}: {path}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f["severity"], 3) <= threshold for f in findings):
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
