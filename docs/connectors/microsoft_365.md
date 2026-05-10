# Microsoft 365 Connector

How to wire mantissa-stance to a Microsoft 365 tenant. Stance is
**read-only and point-in-time**; audit-log streaming (Unified Audit Log,
Defender alerts, sign-in logs) lives in mantissa-log.

## What stance collects

| Module | Resource types |
|---|---|
| `m365_entra_directory` | `entra_user`, `entra_group`, `entra_directory_role`, `entra_role_assignment`, `entra_directory_summary` |
| `m365_entra_apps` | `entra_app_registration`, `entra_service_principal` |
| `m365_entra_consent` | `entra_consent_policy`, `entra_oauth2_grant` |
| `m365_entra_auth_methods` | `entra_auth_methods_summary` |
| `m365_entra_conditional_access` | `entra_ca_policy`, `entra_ca_summary` |
| `m365_entra_pim` | `entra_pim_eligibility`, `entra_pim_role_setting`, `entra_pim_summary` |
| `m365_entra_security_defaults` | `entra_security_defaults`, `entra_tenant_baseline` |
| `m365_entra_identity_protection` | `entra_identity_protection_policies` |
| `m365_entra_external_identities` | `entra_external_identities`, `entra_cross_tenant_access` |
| `m365_entra_federation` | `entra_domain`, `entra_federation_summary` |
| `m365_sharepoint_tenant` | `sharepoint_tenant_settings` |
| `m365_sharepoint_sites` | `sharepoint_site` |
| `m365_onedrive` | `onedrive_settings` |
| `m365_exchange` | `exchange_org_config`, `exchange_transport_rule` |
| `m365_defender` | `defender_policy`, `defender_policy_summary` |
| `m365_teams` | `teams_settings` |
| `m365_intune_compliance` | `intune_compliance_policy`, `intune_compliance_summary` |
| `m365_dlp_policies` | `m365_dlp_policy`, `m365_dlp_summary` |
| `m365_sensitivity_labels` | `m365_sensitivity_label`, `m365_label_policy_summary` |
| `m365_secure_score` | `m365_secure_score` |
| `m365_power_platform` | `power_platform_dlp_policy`, `power_platform_dlp_summary` |

## Prerequisites

- A Global Administrator (or Privileged Role Administrator) to grant
  admin consent on the app registration.
- The tenant ID (GUID) and primary domain.

## Setup

### 1. Create the Entra app registration

1. Entra admin → **Identity → Applications → App registrations → New registration**.
2. Name it `mantissa-stance`.
3. Supported account types: **Accounts in this organizational directory only**.
4. Click **Register**. Note the **Application (client) ID** and **Directory (tenant) ID**.

### 2. Grant API permissions

Under **API permissions → Add a permission → Microsoft Graph →
Application permissions**, add the read-only set:

| Permission | Used by |
|---|---|
| `Directory.Read.All` | users, groups, roles |
| `Policy.Read.All` | CA policies, security defaults, authorization policy |
| `Application.Read.All` | app registrations, service principals, consents |
| `RoleManagement.Read.Directory` | role assignments + PIM |
| `RoleManagementPolicy.Read.Directory` | PIM activation rules |
| `IdentityRiskyUser.Read.All` | Identity Protection policy state |
| `IdentityProvider.Read.All` | federation / external identities |
| `Sites.FullControl.All` | SharePoint site + admin settings (read-only via Graph) |
| `SecurityEvents.Read.All` | Defender policy lists (anti-phish / safe-links / safe-attachments) |
| `DeviceManagementConfiguration.Read.All` | Intune compliance policies |
| `InformationProtectionPolicy.Read.All` | sensitivity labels, DLP policies |
| `SecureScores.Read.All` | tenant secure score |

After adding, click **Grant admin consent for <tenant>**.

### 3. Create a client secret (or certificate)

Under **Certificates & secrets → New client secret**, generate a secret
valid for at most 12 months. Store it as an environment variable on the
host that runs the connector:

```bash
export STANCE_M365_CLIENT_SECRET="<paste-secret>"
```

Certificates are preferred over secrets — stance's
`apps/service-principal-secret-rotation.yaml` policy will fire on the
stance app registration itself unless you rotate. Plan a rotation
calendar entry.

### 4. Generate a starter config

```bash
stance saas connect microsoft-365 --output config/m365-connector.json
```

Edit the config: paste the tenant ID, the application (client) ID, the
primary domain, and the env-var name. If you plan to enable the optional
Exchange mailbox DSPM scan, list the explicit UPNs in
`enable_mailbox_scan_for` — mailbox content scans are **opt-in per
mailbox** for privacy reasons.

### 5. Run a scan

```bash
stance saas scan --provider m365 --snapshot snapshots/m365-2026-05-10.json
stance saas graph --include-saas --snapshot snapshots/m365-2026-05-10.json \
  --primary-domain contoso.com
```

## Terraform stub

```hcl
# infrastructure/terraform/stance_m365_app_registration/main.tf
resource "azuread_application" "stance" {
  display_name     = "mantissa-stance"
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "stance" {
  client_id = azuread_application.stance.client_id
}

# Application permissions are configured as required_resource_access
# blocks on azuread_application — see Terraform docs. Admin consent must
# still be granted manually (or via azuread_app_role_assignment).

resource "azuread_application_password" "stance" {
  application_id = azuread_application.stance.id
  display_name   = "stance-secret"
  end_date_relative = "8760h"  # 365 days
}

output "client_id" {
  value = azuread_application.stance.client_id
}
```

## Troubleshooting

### `Authorization_RequestDenied` on a Graph call

The application permission isn't granted, or admin consent wasn't granted
after adding it. Double-check **API permissions → Status** column — every
row must say "Granted for <tenant>".

### Empty `entra_pim_*` resources

The tenant has no PIM license (Entra ID P2). The collector emits empty
summary records and the `pim-required-for-privileged-roles.yaml` /
`no-permanent-global-admin-assignments.yaml` policies will fire — that's
the correct posture; the remediation is to either license P2 or document
the exemption.

### `/beta/...` 404s

Some setting paths (`/beta/policies/passwordResetPolicies`,
`/beta/admin/exchange/...`) are not GA. The collector treats 404 as
"feature absent" and degrades to documented defaults. Confirm via the
connector log; nothing is silently fabricated.

### Sensitive Microsoft 365 features behind PowerShell

Exchange Online's transport rules, anti-spam policies, and most DLP
admin actions are exposed only via Exchange Online PowerShell. Stance
ships the `m365_exchange` collector against the Graph beta endpoints
that exist; for production-grade coverage, layer an EXO PowerShell
adapter behind the same `graph(path)` callable contract (the same
extension point used by the Graph collectors).

### DSPM mailbox scan won't run

By design — mailbox scans are opt-in. Add the explicit UPNs to
`enable_mailbox_scan_for` in the connector config. Never scan all
mailboxes by default.
