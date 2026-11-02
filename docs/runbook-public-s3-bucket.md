# SOP: Publicly exposed S3 bucket

**Trigger:** pipeline P1/P2 finding `s3_bucket_public_access`, a CSPM alert, or the SIEM query
"bucket made public" (`detections/cloudtrail_hunts.spl`, query 5).
**Owner:** on-call security operations engineer. **Target time to contain:** 1 hour.

## 1. Triage (15 minutes)

1. Confirm the finding is real: is the bucket readable without credentials?
   `aws s3api get-bucket-policy-status --bucket BUCKET` and `aws s3api get-public-access-block --bucket BUCKET`
2. Is public access intended (for example a static website with approved, non-sensitive content)?
   Check the asset inventory and ask the owning team. If intended and approved: add a suppression
   with reason, owner and expiry, and stop here.
3. Classify the data: list a sample of objects; look for customer data, credentials, logs, backups.
4. Set severity: sensitive data exposed = critical incident (page the Incident Commander);
   non-sensitive = P2 ticket.

## 2. Contain (immediately for critical)

1. Turn on Block Public Access for the bucket:
   `aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
2. Preserve the old bucket policy and ACL in the incident ticket before changing anything else.
3. Notify the owning team in the incident channel.

## 3. Investigate

1. CloudTrail: who changed the policy/ACL, when, from where (query 5).
2. S3 server access logs or CloudTrail data events: were objects downloaded by unknown IPs while public?
3. Determine the exposure window: from the change that made it public to containment.

## 4. Eradicate and recover

1. Fix the root cause in code (Terraform), not just in the console.
2. Rotate any credentials found in the exposed objects.
3. Confirm with a fresh scan that the finding is resolved.

## 5. Follow-up

1. Postmortem for critical incidents (template: `postmortem-template.md`).
2. Prevent recurrence: account-level Block Public Access, enforced by a service control policy.
3. Close the ticket with evidence (scan result, change link).
