import json

WILDCARD_ADMIN_POLICIES = {"AdministratorAccess", "PowerUserAccess"}

def _is_wildcard_statement(statement):
    """Return True if a policy statement grants Allow on Action:* and Resource:*"""
    if statement.get("Effect") != "Allow":
        return False
    actions = statement.get("Action", [])
    resources = statement.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


def check_directly_attached_admin_policies(iam):
    """Flag users with AdministratorAccess or PowerUserAccess attached directly."""
    findings = []
    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]
        attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        for policy in attached:
            if policy["PolicyName"] in WILDCARD_ADMIN_POLICIES:
                findings.append({
                    "resource": username,
                    "category": "IAM Policy",
                    "severity": "High",
                    "description": f"User has {policy['PolicyName']} attached directly",
                    "remediation": "Attach only the specific permissions this user needs, "
                                    "or move broad access to a role assumed only when needed."
                })
    return findings


def check_customer_managed_wildcards(iam):
    """Flag customer-managed (Local scope) policies with Action:* + Resource:* statements."""
    findings = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"]
            )
            statements = version["PolicyVersion"]["Document"]["Statement"]
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if _is_wildcard_statement(stmt):
                    findings.append({
                        "resource": policy["PolicyName"],
                        "category": "IAM Policy",
                        "severity": "High",
                        "description": "Customer-managed policy grants Action:* on Resource:*",
                        "remediation": "Scope the policy to specific actions and resource ARNs."
                    })
    return findings


def check_inline_policies(iam):
    """Flag inline (embedded) user policies with Action:* + Resource:* statements."""
    findings = []
    users = iam.list_users()["Users"]
    for user in users:
        username = user["UserName"]
        policy_names = iam.list_user_policies(UserName=username)["PolicyNames"]
        for name in policy_names:
            doc = iam.get_user_policy(UserName=username, PolicyName=name)["PolicyDocument"]
            statements = doc["Statement"]
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                if _is_wildcard_statement(stmt):
                    findings.append({
                        "resource": f"{username} (inline: {name})",
                        "category": "IAM Policy",
                        "severity": "High",
                        "description": "Inline policy grants Action:* on Resource:*",
                        "remediation": "Replace with a scoped customer-managed policy, "
                                        "and delete the inline policy."
                    })
    return findings


def check_all_policy_findings(iam):
    return (
        check_directly_attached_admin_policies(iam)
        + check_customer_managed_wildcards(iam)
        + check_inline_policies(iam)
    )