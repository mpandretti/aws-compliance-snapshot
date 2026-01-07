# AWS Compliance Snapshot

Small, read-only AWS audit script using boto3.

Checks a handful of common AWS configuration issues that come up frequently in basic cloud security reviews. Intentionally scoped and not meant to be a full compliance tool.

---

## What it checks

- **Root account MFA**  
  Whether MFA is enabled on the AWS root account.

- **IAM access key age**  
  Flags access keys older than 90 days.

- **Open SSH access**  
  Finds security groups that allow SSH (port 22) from `0.0.0.0/0`.

- **S3 public access block**  
  Verifies that S3 Public Access Block is enabled on all buckets.

- **CloudTrail enabled**  
  Checks whether CloudTrail is enabled in the account.

Each check returns a simple PASS/FAIL result with basic context.

---

## What it isn't

- Not a full compliance scanner  
- Not a replacement for AWS Config, Security Hub, or GuardDuty  

This is a snapshot-style check meant for learning and demonstration.

---

## Project layout

aws-compliance-snapshot/
├── main.py
├── requirements.txt
└── checks/
├── iam_checks.py
├── ec2_checks.py
├── s3_checks.py
└── cloudtrail_checks.py


## Requirements

- Python 3.9+
- AWS CLI
- An AWS IAM user with ReadOnlyAccess
- AWS credentials configured locally

---

## Usage

**Install dependencies:**

    pip install -r requirements.txt

**Configure credentials (example profile name):**

    aws configure --profile compliance-audit

**Run:**
    python main.py



