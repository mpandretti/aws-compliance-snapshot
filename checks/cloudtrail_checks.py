def check_cloudtrail_enabled(session):
    ct = session.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]

    if trails:
        return {
            "id": "LOG-01",
            "title": "CloudTrail enabled",
            "status": "PASS",
            "risk": "Low",
            "details": "CloudTrail is enabled in this account.",
            "recommendation": "None"
        }

    return {
        "id": "LOG-01",
        "title": "CloudTrail enabled",
        "status": "FAIL",
        "risk": "High",
        "details": "No CloudTrail trails found.",
        "recommendation": "Enable CloudTrail in all regions."
    }
