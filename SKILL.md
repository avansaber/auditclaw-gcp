---
name: auditclaw-gcp
description: GCP compliance evidence collection for auditclaw-grc
user-invocable: true
metadata: {"openclaw":{"requires":{"bins":["python3"],"env":["GCP_PROJECT_ID"]}}}
---
# GCP Evidence Collection

Companion skill for auditclaw-grc. Collects compliance evidence from Google Cloud Platform projects.

## Prerequisites
- GCP credentials configured (`gcloud auth application-default login` or service account JSON)
- `GCP_PROJECT_ID` environment variable set
- `pip install -r scripts/requirements.txt`
- auditclaw-grc skill installed and initialized

## Commands
- "Run GCP evidence sweep": Run all checks, store results in GRC database
- "Check GCP storage compliance": Run Cloud Storage checks
- "Check GCP firewall rules": Run firewall ingress checks
- "Check GCP IAM compliance": Run IAM service account checks
- "Check GCP logging status": Verify audit logging configuration
- "Check GCP KMS keys": Review KMS key rotation
- "Show GCP integration health": Last sync, errors, evidence count

## Usage
All evidence is stored in the shared GRC database at ~/.openclaw/grc/compliance.sqlite
via the auditclaw-grc skill's db_query.py script.

To run a full evidence sweep:
```
python3 scripts/gcp_evidence.py --db-path ~/.openclaw/grc/compliance.sqlite --all
```

To run specific checks:
```
python3 scripts/gcp_evidence.py --db-path ~/.openclaw/grc/compliance.sqlite --checks storage,firewall,iam
```

## Check Categories (9 files, 12 findings)

| Check | What It Verifies |
|-------|-----------------|
| **storage** | Uniform bucket-level access, public access prevention |
| **firewall** | No unrestricted ingress (0.0.0.0/0) to SSH/RDP/all |
| **iam** | Service account key rotation (90 days), SA admin privilege restriction |
| **logging** | Audit logging enabled (all services), log export sink exists |
| **kms** | KMS key rotation period <= 90 days |
| **dns** | DNSSEC enabled on public zones |
| **bigquery** | No public dataset access (allUsers/allAuthenticatedUsers) |
| **compute** | No default service account with cloud-platform scope |
| **cloudsql** | SSL enforcement, no public IP with 0.0.0.0/0 |

## Evidence Storage
Each check produces evidence items stored with:
- `source: "gcp"`
- `type: "automated"`
- `control_id`: Mapped to relevant SOC2/ISO/HIPAA controls
- `description`: Human-readable finding summary
- `file_content`: JSON details of the check result

## Required IAM Roles
- `roles/viewer`
- `roles/iam.securityReviewer`
- `roles/cloudsql.viewer`
- `roles/logging.viewer`
- `roles/dns.reader`
- `roles/cloudkms.viewer`

All checks use read-only access only.

## Setup Guide

When a user asks to set up GCP integration, guide them through these steps:

### Step 1: Create Service Account
```
gcloud iam service-accounts create auditclaw-scanner --display-name="AuditClaw Scanner"
```

### Step 2: Grant IAM Roles
Grant these 6 read-only roles:
```
for role in roles/viewer roles/iam.securityReviewer roles/cloudsql.viewer roles/logging.viewer roles/dns.reader roles/cloudkms.viewer; do
  gcloud projects add-iam-policy-binding PROJECT_ID \
    --member=serviceAccount:auditclaw-scanner@PROJECT_ID.iam.gserviceaccount.com \
    --role=$role
done
```

### Step 3: Generate JSON Key
```
gcloud iam service-accounts keys create key.json --iam-account=auditclaw-scanner@PROJECT_ID.iam.gserviceaccount.com
```

### Step 4: Configure Credentials
Set environment variables:
- GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
- GCP_PROJECT_ID=your-project-id

### Step 5: Verify Connection
Run: `python3 {baseDir}/scripts/gcp_evidence.py --test-connection`

The exact roles are documented in `scripts/gcp-roles.json`. Show with:
  python3 {baseDir}/../auditclaw-grc/scripts/db_query.py --action show-policy --provider gcp
