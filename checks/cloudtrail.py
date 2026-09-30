from botocore.exceptions import ClientError


def _finding(resource, severity, description, remediation):
    return {
        "resource": resource,
        "category": "CloudTrail",
        "severity": severity,
        "description": description,
        "remediation": remediation,
    }


def check_cloudtrail(cloudtrail):
    findings = []
    trails = cloudtrail.describe_trails(includeShadowTrails=True)["trailList"]

    unique = {t["TrailARN"]: t for t in trails}.values()

    if not unique:
        return [_finding(
            "Account",
            "High",
            "No CloudTrail trail exists",
            "Create a multi-region trail that logs management events to S3.",
        )]

    if not any(t.get("IsMultiRegionTrail") for t in unique):
        findings.append(_finding(
            "Account",
            "High",
            "No multi-region trail: activity in other regions is not recorded",
            "Enable the multi-region option on a trail.",
        ))

    for trail in unique:
        name = trail["Name"]
        try:
            status = cloudtrail.get_trail_status(Name=trail["TrailARN"])
        except ClientError:
            continue

        if not status.get("IsLogging"):
            findings.append(_finding(
                name,
                "High",
                "Trail exists but logging is stopped",
                "Start logging on this trail.",
            ))

        if not trail.get("LogFileValidationEnabled"):
            findings.append(_finding(
                name,
                "Medium",
                "Log file validation is disabled",
                "Enable log file validation so tampering can be detected.",
            ))

    return findings