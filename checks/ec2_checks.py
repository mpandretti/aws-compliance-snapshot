def check_open_ssh(session):
    ec2 = session.client("ec2")
    response = ec2.describe_security_groups()

    open_groups = []

    for sg in response["SecurityGroups"]:
        for perm in sg.get("IpPermissions", []):
            if perm.get("FromPort") == 22 and perm.get("ToPort") == 22:
                for ip in perm.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        open_groups.append(sg["GroupId"])

    if not open_groups:
        return {
            "id": "EC2-01",
            "title": "SSH not open to the internet",
            "status": "PASS",
            "risk": "Low",
            "details": "No security groups allow SSH from 0.0.0.0/0.",
            "recommendation": "None"
        }

    return {
        "id": "EC2-01",
        "title": "SSH open to the internet",
        "status": "FAIL",
        "risk": "Medium",
        "details": f"Security groups with open SSH: {open_groups}",
        "recommendation": "Restrict SSH access to known IP ranges."
    }
