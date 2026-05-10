# CIS Microsoft 365 Foundations — Coverage Matrix

Coverage matrix for **CIS Microsoft 365 Foundations Benchmark v3.0.0**.
Framework string: `cis-microsoft-365-foundations`.

## Coverage Summary

| Section | Controls | Automated | Status |
|---|---:|---:|---|
| 1.1 Identity baseline (CA / PIM / IDP / Federation) | 11 | 11 | ✅ shipping |
| 5.1 App registrations + service principals | 4 | 4 | ✅ shipping |
| 6.1 Exchange Online | 4 | 4 | ✅ shipping |
| 7.2 SharePoint sharing | 4 | 4 | ✅ shipping |
| 7.3 OneDrive | 2 | 2 | ✅ shipping |
| 2.1 Defender for Office 365 | 3 | 3 | ✅ shipping |
| 3.1 Information protection / labels | 2 | 2 | ✅ shipping |
| 3.2 Data Loss Prevention | 1 | 1 | ✅ shipping |
| 8.1 Teams | 3 | 3 | ✅ shipping |
| 9.1 Intune compliance | 1 | 1 | ✅ shipping |
| Cross-surface CIEM | — | n/a | ✅ shipping (unmapped to CIS) |

## Control → Policy Mapping

| CIS Control | Stance Policy ID | Resource Type |
|---|---|---|
| 1.1.1 | m365-entra-001 | entra_tenant_baseline |
| 1.1.2 | m365-entra-003 | entra_ca_summary |
| 1.1.3 | m365-entra-004 | entra_ca_summary |
| 1.1.4 | m365-entra-005 | entra_pim_summary |
| 1.1.5 | m365-entra-002 | entra_ca_summary |
| 1.1.6 | m365-entra-006 | entra_pim_role_setting |
| 1.1.7 | m365-entra-007 | entra_pim_summary |
| 1.1.8 | m365-entra-008 | entra_identity_protection_policies |
| 1.1.9 | m365-entra-009 | entra_auth_methods_summary |
| 1.1.10 | m365-entra-010 | entra_auth_methods_summary |
| 1.1.11 | m365-entra-011 | entra_federation_summary |
| 5.1.5 | m365-apps-001 | entra_consent_policy |
| 5.1.6 | m365-apps-002 | entra_app_registration |
| 5.1.7 | m365-apps-003 | entra_service_principal |
| 5.1.8 | m365-apps-004 | entra_app_registration |
| 6.1.1 | m365-exchange-001 | exchange_org_config |
| 6.1.2 | m365-exchange-002 | exchange_org_config |
| 6.1.3 | m365-exchange-003 | exchange_org_config |
| 6.1.4 | m365-exchange-004 | exchange_org_config |
| 7.2.1 | m365-sharepoint-001, saas-dspm-002 | sharepoint_tenant_settings, dspm_finding |
| 7.2.2 | m365-sharepoint-002, saas-dspm-001 | sharepoint_tenant_settings, dspm_finding |
| 7.2.3 | m365-sharepoint-003 | sharepoint_tenant_settings |
| 7.2.4 | m365-sharepoint-004 | sharepoint_tenant_settings |
| 7.3.1 | m365-onedrive-001 | onedrive_settings |
| 7.3.2 | m365-onedrive-002 | onedrive_settings |
| 2.1.1 | m365-defender-001 | defender_policy_summary |
| 2.1.2 | m365-defender-002 | defender_policy_summary |
| 2.1.3 | m365-defender-003 | defender_policy_summary |
| 3.1.1 | m365-info-001 | m365_label_policy_summary |
| 3.1.2 | m365-info-002 | m365_label_policy_summary |
| 3.2.1 | m365-dlp-001 | m365_dlp_summary |
| 8.1.1 | m365-teams-001 | teams_settings |
| 8.1.2 | m365-teams-002 | teams_settings |
| 8.1.3 | m365-teams-003 | teams_settings |
| 9.1.1 | m365-intune-001 | intune_compliance_summary |

## Out of Scope (mantissa-log territory)

- Unified audit log forwarding (every "review last N days" control)
- Identity Protection event stream (sign-in risks, user risks)
- Defender for Cloud Apps detections

See `docs/saas_posture_overview.md` for the split.
