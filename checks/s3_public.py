PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

def check_public_access_block(s3, bucket_name):
    """Flag if a bucket has no Block Public Access config, or has it disabled."""
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        if not all(config.values()):
            return {
                "resource": bucket_name,
                "category": "S3",
                "severity": "High",
                "description": "Block Public Access is not fully enabled",
                "remediation": "Enable all four Block Public Access settings for this bucket."
            }
    except s3.exceptions.ClientError as e:
        if "NoSuchPublicAccessBlockConfiguration" in str(e):
            return {
                "resource": bucket_name,
                "category": "S3",
                "severity": "High",
                "description": "No Block Public Access configuration exists",
                "remediation": "Enable Block Public Access for this bucket."
            }
        raise
    return None


def check_bucket_policy_public(s3, bucket_name):
    """Flag if the bucket policy status reports the bucket as public."""
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status.get("PolicyStatus", {}).get("IsPublic", False):
            return {
                "resource": bucket_name,
                "category": "S3",
                "severity": "High",
                "description": "Bucket policy allows public access",
                "remediation": "Review and remove public statements from the bucket policy."
            }
    except s3.exceptions.ClientError as e:
        if "NoSuchBucketPolicy" in str(e):
            return None
        raise
    return None


def check_bucket_acl_public(s3, bucket_name):
    """Flag if the bucket ACL grants access to AllUsers or AuthenticatedUsers."""
    acl = s3.get_bucket_acl(Bucket=bucket_name)
    for grant in acl["Grants"]:
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") in PUBLIC_GRANTEE_URIS:
            return {
                "resource": bucket_name,
                "category": "S3",
                "severity": "High",
                "description": f"Bucket ACL grants access to {grantee.get('URI')}",
                "remediation": "Remove the public grant from the bucket ACL."
            }
    return None


def check_all_buckets(s3):
    findings = []
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        for check_fn in (check_public_access_block, check_bucket_policy_public, check_bucket_acl_public):
            result = check_fn(s3, name)
            if result:
                findings.append(result)
    return findings