# CIS Google Workspace Foundations — Coverage Matrix

This is the coverage matrix for **CIS Google Workspace Foundations Benchmark v1.0.0**
in mantissa-stance. The framework string used by policies is
`cis-google-workspace-foundations`.

## Coverage Summary

| Section | Controls | Automated | Status |
|---|---:|---:|---|
| 1. Authentication & Account Management | 13 | 13 | ✅ shipping |
| 5. Drive, OAuth, and external sharing | 7 | 7 | ✅ shipping |
| 3. Gmail / mail-flow security | 4 | 4 | ✅ shipping |
| 6. Chrome posture | 3 | 3 | ✅ shipping |
| 7. Mobile management | 2 | 2 | ✅ shipping |
| 8. Vault / retention | 1 | 1 | ✅ shipping |
| Cross-surface CIEM | — | n/a | ✅ shipping (unmapped to CIS) |

## Control → Policy Mapping

Sourced from `policies/saas/google_workspace/**/*.yaml`. Each policy ships
its own `compliance.framework` block; the table below is the inverse view.

| CIS Control | Stance Policy ID | Resource Type |
|---|---|---|
| 1.1 | gws-auth-002 | gws_tenant_security |
| 1.2 | gws-admin-001 | gws_tenant_security |
| 1.3 | gws-admin-002 | gws_tenant_security |
| 1.4 | gws-auth-001 | gws_tenant_security |
| 1.5 | gws-auth-004 | gws_tenant_security |
| 1.6 | gws-auth-005 | gws_tenant_security |
| 1.7 | gws-auth-003 | gws_tenant_security |
| 1.10 | gws-admin-003 | gws_role_assignment |
| 1.11 | gws-admin-004 | gws_user |
| 1.12 | gws-user-001 | gws_user |
| 1.13 | gws-caa-001 | gws_caa_summary |
| 3.4 | gws-gmail-001 | gws_gmail_settings |
| 3.5 | gws-gmail-002 | gws_gmail_settings |
| 3.6 | gws-gmail-004 | gws_gmail_settings |
| 3.7 | gws-gmail-003 | gws_gmail_settings |
| 5.1 | gws-drive-001 | gws_drive_settings |
| 5.2 | gws-oauth-004 | gws_oauth_app |
| 5.3 | gws-oauth-001, gws-oauth-002 | gws_oauth_app |
| 5.4 | gws-drive-002 | gws_drive_settings |
| 5.5 | gws-drive-003 | gws_drive_settings |
| 5.6 | gws-drive-004 | gws_shared_drive |
| 5.7 | gws-oauth-003 | gws_oauth_app |
| 6.1 | gws-chrome-001 | gws_chrome_policy |
| 6.3 | gws-chrome-002 | gws_chrome_policy |
| 6.4 | gws-chrome-003 | gws_chrome_policy |
| 7.1 | gws-mobile-001 | gws_mobile_settings |
| 7.2 | gws-mobile-002 | gws_mobile_settings |
| 8.1 | gws-vault-001 | gws_vault_retention |

## Out of Scope (audit-log territory)

The following CIS controls require event-stream data (Reports / Audit API)
and live in **mantissa-log**, not stance:

- 4.x — login activity / audit-log forwarding
- Any control whose audit step starts with "review the last N days of …"

See `docs/saas_posture_overview.md` for the stance-vs-log split.
