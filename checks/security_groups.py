SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    27017: "MongoDB",
}
OPEN_CIDRS = {"0.0.0.0/0"}
OPEN_IPV6_CIDRS = {"::/0"}


def _is_open_to_world(rule):
    v4 = any(r.get("CidrIp") in OPEN_CIDRS for r in rule.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") in OPEN_IPV6_CIDRS for r in rule.get("Ipv6Ranges", []))
    return v4 or v6


def _finding(sg, severity, description):
    return {
        "resource": f"{sg['GroupId']} ({sg['GroupName']})",
        "category": "Security Group",
        "severity": severity,
        "description": description,
        "remediation": "Restrict the source to specific IP ranges or security groups "
                       "instead of 0.0.0.0/0 or ::/0.",
    }


def check_security_groups(ec2):
    findings = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for rule in sg.get("IpPermissions", []):
                if not _is_open_to_world(rule):
                    continue

                protocol = rule.get("IpProtocol")
                if protocol == "-1":
                    findings.append(_finding(
                        sg, "High", "All traffic (all ports, all protocols) open to the world"))
                    continue

                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")
                exposed = [
                    f"{port} ({name})"
                    for port, name in SENSITIVE_PORTS.items()
                    if from_port is not None and from_port <= port <= to_port
                ]
                if exposed:
                    findings.append(_finding(
                        sg, "High",
                        f"Sensitive port(s) open to the world: {', '.join(exposed)}"))
                else:
                    findings.append(_finding(
                        sg, "Medium",
                        f"Port range {from_port}-{to_port} ({protocol}) open to the world"))
    return findings