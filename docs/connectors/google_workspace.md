# Google Workspace Connector

How to wire mantissa-stance to a Google Workspace tenant. Stance is
**read-only and point-in-time** — there is no audit-log streaming here.
Event collection lives in mantissa-log (see `docs/saas_posture_overview.md`).

## What stance collects

The Workspace connector populates the following resource types (used by
the CIS Google Workspace Foundations benchmark and the cross-surface CIEM
graph):

| Module | Resource types |
|---|---|
| `gws_directory` | `gws_user`, `gws_group`, `gws_org_unit`, `gws_role_assignment` |
| `gws_security` | `gws_tenant_security` |
| `gws_drive_settings` | `gws_drive_settings`, `gws_shared_drive` |
| `gws_oauth_apps` | `gws_oauth_app` |
| `gws_gmail` | `gws_gmail_settings` |
| `gws_calendar` | `gws_calendar_settings` |
| `gws_chrome` | `gws_chrome_policy` |
| `gws_mobile` | `gws_mobile_settings` |
| `gws_vault` | `gws_vault_retention` |
| `gws_context_aware` | `gws_caa_access_level`, `gws_caa_binding`, `gws_caa_summary` |

## Prerequisites

- A Google Cloud project to host the service account (any project the
  workspace org owns is fine).
- A Workspace super-admin to delegate the service account's domain-wide
  delegation (DWD).
- Python 3.11+ and `mantissa-stance` installed.

## Setup

### 1. Create the service account

```bash
gcloud config set project <WORKSPACE_MGMT_PROJECT>
gcloud iam service-accounts create stance-workspace \
  --display-name "Mantissa Stance — Workspace posture"
gcloud iam service-accounts keys create stance-workspace.json \
  --iam-account stance-workspace@<WORKSPACE_MGMT_PROJECT>.iam.gserviceaccount.com
```

### 2. Enable the APIs

In the same project, enable:

- `admin.googleapis.com` (Admin SDK)
- `cloudidentity.googleapis.com` (Cloud Identity, for the Policy API)
- `vault.googleapis.com` (Google Vault, only if Vault is licensed)
- `drive.googleapis.com` (Drive — only required for DSPM scans, optional)

### 3. Grant domain-wide delegation

1. Open the Admin Console → **Security → Access and data control → API controls → Domain-wide delegation**.
2. Click **Add new**.
3. Paste the service account's *client ID* (not its email).
4. In the **OAuth scopes** field paste the comma-separated list below.
5. Save.

#### Read-only scopes (required)

```
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.group.member.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,
https://www.googleapis.com/auth/admin.directory.domain.readonly,
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,
https://www.googleapis.com/auth/cloud-identity.policies.readonly,
https://www.googleapis.com/auth/apps.licensing
```

#### Optional scopes (only if the corresponding feature is licensed)

```
https://www.googleapis.com/auth/ediscovery.readonly        # Vault retention rules
https://www.googleapis.com/auth/drive.readonly             # DSPM Drive scans
https://www.googleapis.com/auth/gmail.readonly             # DSPM Gmail scans (heavy)
```

### 4. Pick a delegated user

Stance impersonates a real Workspace super-admin to call the Admin SDK.
Create a dedicated low-traffic super-admin account (`stance-impersonator@example.com`)
and reference it in the connector config.

### 5. Generate a starter config

```bash
stance saas connect google-workspace --output config/gws-connector.json
```

Edit the generated file to point at your service account JSON path,
delegated user, and customer ID. Customer ID is `my_customer` for the
caller's tenant or the literal C-prefixed ID for a managed-from-elsewhere
tenant.

### 6. Run a scan

```bash
# Production wiring (with credentials) drives the collectors live and
# persists a snapshot JSON. The CLI then evaluates it.
stance saas scan --provider gws --snapshot snapshots/gws-2026-05-10.json
stance saas graph --include-saas --snapshot snapshots/gws-2026-05-10.json \
  --primary-domain example.com
```

## Terraform stub

A reference Terraform module that provisions the service account, the
required APIs, and an empty DWD allowlist (the DWD assignment itself must
happen in the Admin Console — there is no Terraform resource for it):

```hcl
# infrastructure/terraform/stance_workspace_sa/main.tf
resource "google_service_account" "stance_workspace" {
  account_id   = "stance-workspace"
  display_name = "Mantissa Stance — Workspace posture"
  project      = var.management_project
}

resource "google_project_service" "admin_sdk" {
  service = "admin.googleapis.com"
  project = var.management_project
}

resource "google_project_service" "cloud_identity" {
  service = "cloudidentity.googleapis.com"
  project = var.management_project
}

output "client_id" {
  description = "Paste this into Admin Console → Domain-wide delegation."
  value       = google_service_account.stance_workspace.unique_id
}
```

## Troubleshooting

### `403: Not Authorized to access this resource/api`

Usually means DWD is not configured for the scope you're using, or the
service account JSON key was rotated and the scope grant points at the old
client ID. Re-check the **client ID** in Admin Console → Domain-wide
delegation against the JSON you're using.

### Empty `gws_tenant_security` policies API response

The Cloud Identity Policy API setting types are not all GA. Stance falls
back to documented Workspace defaults and degrades gracefully — but check
the connector log for `policies.list unavailable`. If you see that, the
service account probably lacks `cloud-identity.policies.readonly`.

### `gws_oauth_app.verified` is `False` even for known apps

The Admin SDK does not expose Google's verification flag on the token
list. Stance treats Google-published apps (`*.apps.googleusercontent.com`)
as verified automatically; for other vendors, populate
`trusted_client_ids` in the connector config from your Admin Console
allowlist.

### Vault scopes 404 / "service not enabled"

You don't have a Vault license. The collector silently emits an empty
`gws_vault_retention` asset; the related policy
`vault/retention-rules-cover-core-services.yaml` will fire — that's the
correct posture for a tenant with no Vault coverage.
