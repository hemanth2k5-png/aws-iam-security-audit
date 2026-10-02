import json
from datetime import datetime, timezone

import boto3
from moto import mock_aws

from history import build_run, to_jsonl, upload_run

FINDING = {
    "severity": "High", "category": "Security Group", "resource": "sg-1 (x)",
    "description": "d", "remediation": "r",
}
COUNTS = {"High": 1, "Medium": 0, "Low": 0}
NOW = datetime(2026, 10, 5, 14, 0, 0, tzinfo=timezone.utc)


def test_build_run_creates_one_record_per_finding():
    run_id, run_date, records, run_row = build_run([FINDING], COUNTS, "****9340", "us-east-1", now=NOW)
    assert run_id == "20261005T140000Z"
    assert run_date == "2026-10-05"
    assert records[0]["run_timestamp"] == "2026-10-05T14:00:00Z"
    assert records[0]["resource"] == "sg-1 (x)"
    assert run_row["total"] == 1


def test_to_jsonl_writes_one_json_object_per_line():
    text = to_jsonl([{"a": 1}, {"a": 2}])
    assert [json.loads(line) for line in text.splitlines()] == [{"a": 1}, {"a": 2}]


@mock_aws
def test_upload_run_writes_findings_and_run_record():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="history")
    upload_run(s3, "history", [FINDING], COUNTS, "****9340", "us-east-1", now=NOW)
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="history")["Contents"]]
    assert "findings/run_date=2026-10-05/audit-20261005T140000Z.jsonl" in keys
    assert "runs/run_date=2026-10-05/run-20261005T140000Z.jsonl" in keys


@mock_aws
def test_clean_run_still_records_the_run():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="history")
    upload_run(s3, "history", [], {"High": 0, "Medium": 0, "Low": 0}, "****9340", "us-east-1", now=NOW)
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="history")["Contents"]]
    assert keys == ["runs/run_date=2026-10-05/run-20261005T140000Z.jsonl"]