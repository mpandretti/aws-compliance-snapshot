import boto3
from checks.iam_checks import check_root_mfa, check_access_key_age
from checks.ec2_checks import check_open_ssh
from checks.s3_checks import check_public_buckets
from checks.cloudtrail_checks import check_cloudtrail_enabled

PROFILE = "compliance-audit"

def main():
    session = boto3.Session(profile_name=PROFILE)

    results = [
        check_root_mfa(session),
        check_access_key_age(session),
        check_open_ssh(session),
        check_public_buckets(session),
        check_cloudtrail_enabled(session),
    ]

    print("\nAWS Compliance Snapshot")
    print("-" * 30)

    for r in results:
        print(f"[{r['status']}] {r['id']}: {r['title']}")
        print(f"Risk: {r['risk']}")
        print(f"Details: {r['details']}")
        print(f"Recommendation: {r['recommendation']}\n")

if __name__ == "__main__":
    main()
