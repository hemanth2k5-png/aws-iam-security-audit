import json
from datetime import datetime, timezone

FINDINGS_PREFIX = "findings"
RUNS_PREFIX = "runs"


def build_run(findings, counts, account_masked, region, now=None):
    now = now or datetime.now(timezone.utc)
    run_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = now.strftime("%Y%m%dT%H%M%SZ")
    run_date = now.strftime("%Y-%m-%d")

    records = [
        {
            "run_id": run_id,
            "run_timestamp": run_ts,
            "account": account_masked,
            "region": region,
            "severity": f["severity"],
            "category": f["category"],
            "resource": f["resource"],
            "description": f["description"],
            "remediation": f["remediation"],
        }
        for f in findings
    ]
    run_row = {
        "run_id": run_id,
        "run_timestamp": run_ts,
        "account": account_masked,
        "region": region,
        "high": counts["High"],
        "medium": counts["Medium"],
        "low": counts["Low"],
        "total": len(findings),
    }
    return run_id, run_date, records, run_row


def to_jsonl(rows):
    return "".join(json.dumps(row) + "\n" for row in rows)


def upload_run(s3, bucket, findings, counts, account_masked, region, now=None):
    run_id, run_date, records, run_row = build_run(
        findings, counts, account_masked, region, now
    )
    if records:
        s3.put_object(
            Bucket=bucket,
            Key=f"{FINDINGS_PREFIX}/run_date={run_date}/audit-{run_id}.jsonl",
            Body=to_jsonl(records).encode("utf-8"),
            ContentType="application/x-ndjson",
        )
    s3.put_object(
        Bucket=bucket,
        Key=f"{RUNS_PREFIX}/run_date={run_date}/run-{run_id}.jsonl",
        Body=to_jsonl([run_row]).encode("utf-8"),
        ContentType="application/x-ndjson",
    )
    return run_id