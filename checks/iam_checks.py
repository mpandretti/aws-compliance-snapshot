from datetime import datetime, timezone

def check_root_mfa(session):
    iam = session.client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    mfa_enabled = summary.get("AccountMFAEnabled", 0)

    if mfa_enabled == 1:
        return {
            "id": "IAM-01",
            "title": "Root account MFA enabled",
            "status": "PASS",
            "risk": "Low",
            "details": "Root account has MFA enabled.",
            "recommendation": "None"
        }

    return {
        "id": "IAM-01",
        "title": "Root account MFA enabled",
        "status": "FAIL",
        "risk": "High",
        "details": "Root account does not have MFA enabled.",
        "recommendation": "Enable MFA on the AWS root account immediately."
    }




def check_access_key_age(session, max_age_days=90):
    iam = session.client("iam")

    now = datetime.now(timezone.utc)
    old_keys = []

    users = iam.list_users()["Users"]

    for user in users:
        username = user["UserName"]
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

        for key in keys:
            create_date = key["CreateDate"]
            age_days = (now - create_date).days

            if age_days > max_age_days:
                old_keys.append({
                    "user": username,
                    "access_key_id": key["AccessKeyId"],
                    "age_days": age_days
                })

    if not old_keys:
        return {
            "id": "IAM-02",
            "title": "IAM access keys rotated within policy",
            "status": "PASS",
            "risk": "Low",
            "details": f"No access keys older than {max_age_days} days found.",
            "recommendation": "None"
        }

    return {
        "id": "IAM-02",
        "title": "Stale IAM access keys detected",
        "status": "FAIL",
        "risk": "Medium",
        "details": f"Access keys older than {max_age_days} days: {old_keys}",
        "recommendation": "Rotate or remove access keys older than 90 days."
    }