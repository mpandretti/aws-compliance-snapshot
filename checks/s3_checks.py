def check_public_buckets(session):
    s3 = session.client("s3")
    buckets = s3.list_buckets()["Buckets"]

    public = []

    for b in buckets:
        name = b["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            if not all(config.values()):
                public.append(name)
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            public.append(name)

    if not public:
        return {
            "id": "S3-01",
            "title": "S3 public access blocked",
            "status": "PASS",
            "risk": "Low",
            "details": "All buckets block public access.",
            "recommendation": "None"
        }

    return {
        "id": "S3-01",
        "title": "S3 public access not fully blocked",
        "status": "FAIL",
        "risk": "High",
        "details": f"Buckets without full block: {public}",
        "recommendation": "Enable public access block on all S3 buckets."
    }
