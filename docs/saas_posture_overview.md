# SaaS Posture Overview — stance vs. log

mantissa-stance and mantissa-log split the SaaS security problem along a
single clean axis:

- **stance = point-in-time posture.** "Is 2SV enforced? Is the tenant
  externally shareable? Are there permanent Global Admins? Are app secrets
  about to expire?" Stance asks these questions every few hours and
  reports the answer in a CIS-style benchmark.
- **mantissa-log = streamed events.** "Who just signed in from a new
  country? Which user just clicked the OAuth-consent prompt? Did the new
  inbox rule auto-forward to an external domain?" Log subscribes to
  audit feeds, runs detections, and pages oncall.

If a question begins with "Has somebody …", "When did …", or "How many
events …", it belongs in log. If it begins with "Is …" or "How many
resources currently …", it belongs in stance.

## What stance covers (and where)

| Surface | Module prefix | Connector |
|---|---|---|
| Google Workspace identity | `gws_directory`, `gws_security` | [google_workspace.md](connectors/google_workspace.md) |
| Workspace Drive + OAuth apps | `gws_drive_settings`, `gws_oauth_apps` | same |
| Workspace operational surfaces | `gws_gmail`, `gws_calendar`, `gws_chrome`, `gws_mobile`, `gws_vault`, `gws_context_aware` | same |
| Entra identity | `m365_entra_*` | [microsoft_365.md](connectors/microsoft_365.md) |
| SharePoint / OneDrive | `m365_sharepoint_*`, `m365_onedrive` | same |
| Exchange Online posture | `m365_exchange` | same |
| Defender / Teams / Intune / DLP / Labels / Secure Score / Power Platform | `m365_defender`, `m365_teams`, `m365_intune_compliance`, `m365_dlp_policies`, `m365_sensitivity_labels`, `m365_secure_score`, `m365_power_platform` | same |
| Cross-surface CIEM graph | `identity.gws_mapper`, `identity.entra_mapper`, `identity.cross_surface` | both |
| DSPM (SharePoint / OneDrive / Exchange content) | `dspm.extended.m365_*` | both |

CIS benchmark coverage matrices: [google_workspace.md](cis_benchmarks/google_workspace.md), [microsoft_365.md](cis_benchmarks/microsoft_365.md).

## What lives in mantissa-log instead

| Question | Lives in |
|---|---|
| "List all OAuth tokens granted in the last hour" | log |
| "Alert on a new transport rule that forwards externally" | log |
| "Show sign-ins from impossible-travel origins" | log |
| "Who downloaded > 100 SharePoint files yesterday?" | log |
| "What configuration changed in the last 24 hours?" | log (config drift = events) |
| "Is mailbox auditing enabled by default?" | **stance** |
| "Is there a permanent Global Admin?" | **stance** |
| "Are confidential files shared externally right now?" | **stance** (via DSPM) |

## Decision tree

```
Is the question about *current state* (yes/no, count of resources)?
├─ Yes → stance
│        ├─ Is the answer a per-resource finding? → policies/saas/**/*.yaml
│        ├─ Is the answer a graph traversal?      → identity.cross_surface
│        └─ Is the answer a content classification? → dspm.extended.m365_*
└─ No → it's an event/trend question → mantissa-log
```

## Recommended connector cadence

| Connector | Default cadence | Reason |
|---|---|---|
| Workspace + Entra directory snapshots | every 6 hours | Catches drift fast, low cost |
| Drive / SharePoint / OneDrive settings | every 6 hours | Same |
| OAuth-app inventory (per-user tokens) | every 24 hours | High per-user cost; daily is enough |
| DSPM SharePoint / OneDrive | every 7 days | Content scans are expensive |
| DSPM Exchange (mailbox content) | on-demand, opt-in per mailbox | Privacy-sensitive |
| CIS benchmark roll-up + cross-surface graph | every scan | Cheap once snapshots exist |

## How findings flow

1. Connector calls the collectors → writes a JSON `snapshot` file.
2. `stance saas scan --provider gws|m365 --snapshot <file>` evaluates
   `policies/saas/**/*.yaml` against the snapshot.
3. `stance saas graph --include-saas --snapshot <file>` builds the
   cross-surface permission graph and runs the §5.2 queries.
4. Findings flow into the existing reporter (HTML / CSV / JSON) without
   any engine changes — that property is load-bearing for the spec.

## Read-only invariant

Stance never writes. Not to Workspace, not to Entra, not to SharePoint.
Every API call uses a `.readonly` scope where available; permissions that
have no read-only form (e.g. `Sites.FullControl.All` on Graph) are still
read-only in effect because the connector never invokes a write path.

If the spec ever proposes a remediation action, it gets a new top-level
module — it does not land in stance.
