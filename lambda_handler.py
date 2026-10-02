import os

import boto3

from main import collect_findings
from report import prepare, summarize

MAX_LISTED = 20


def build_message(findings, counts, account_id):
    lines = [
        f"AWS security audit for account ****{account_id[-4:]}",
        f"High: {counts['High']} | Medium: {counts['Medium']} | "
        f"Low: {counts['Low']} | Total: {len(findings)}",
        "",
    ]
    for f in findings[:MAX_LISTED]:
        lines.append(f"[{f['severity']}] {f['category']} - {f['resource']}: {f['description']}")
    if len(findings) > MAX_LISTED:
        lines.append(f"...and {len(findings) - MAX_LISTED} more.")
    return "\n".join(lines)


def handler(event, context):
    session = boto3.Session()
    account_id = session.client("sts").get_caller_identity()["Account"]

    findings = prepare(collect_findings(session))
    counts = summarize(findings)

    subject = f"AWS audit: {counts['High']} High, {counts['Medium']} Medium findings"
    session.client("sns").publish(
        TopicArn=os.environ["TOPIC_ARN"],
        Subject=subject[:100],
        Message=build_message(findings, counts, account_id),
    )
    return {"statusCode": 200, "counts": counts, "total": len(findings)}