# Alerting and Notifications

Configure alerts to be notified of security findings via Slack, PagerDuty, email, and more.

## Overview

Mantissa Stance supports multiple notification destinations:
- **Slack**: Webhook-based notifications with rich formatting
- **PagerDuty**: Incident creation with severity mapping
- **Email**: SMTP-based email notifications
- **Microsoft Teams**: Adaptive card notifications
- **Jira**: Automatic issue creation
- **Webhooks**: Generic HTTP webhooks for custom integrations

## Quick Setup

### Slack

1. Create a Slack webhook URL in your workspace
2. Configure Stance:

```bash
# Via CLI
stance notify configure slack \
  --name prod-alerts \
  --webhook-url https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX \
  --channel "#security-alerts"

# Test the configuration
stance notify test prod-alerts
```

### PagerDuty

```bash
stance notify configure pagerduty \
  --name oncall \
  --routing-key your-integration-key \
  --severity-map critical:critical,high:error,medium:warning

stance notify test oncall
```

### Email

```bash
stance notify configure email \
  --name security-team \
  --smtp-host smtp.example.com \
  --smtp-port 587 \
  --smtp-user alerts@example.com \
  --smtp-password your-password \
  --from alerts@example.com \
  --recipients security@example.com,admin@example.com \
  --use-tls

stance notify test security-team
```

## Configuration File

Create a configuration file for complex setups:

```yaml
# alerting-config.yaml
destinations:
  - name: slack-critical
    type: slack
    webhook_url: https://hooks.slack.com/services/xxx
    channel: "#critical-alerts"

  - name: slack-all
    type: slack
    webhook_url: https://hooks.slack.com/services/yyy
    channel: "#security-findings"

  - name: pagerduty-oncall
    type: pagerduty
    routing_key: your-routing-key
    severity_map:
      critical: critical
      high: error
      medium: warning

  - name: email-team
    type: email
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: alerts@example.com
    smtp_password: ${SMTP_PASSWORD}  # Environment variable
    from_address: security-alerts@example.com
    recipients:
      - security-team@example.com
      - compliance@example.com
    use_tls: true

routing:
  # Critical findings go to PagerDuty and Slack
  - severity: critical
    destinations:
      - pagerduty-oncall
      - slack-critical

  # High findings go to Slack
  - severity: high
    destinations:
      - slack-critical

  # All findings go to email digest
  - severity: "*"
    destinations:
      - email-team

settings:
  # Deduplicate alerts within this window
  deduplication_window_minutes: 60

  # Rate limit alerts per destination
  rate_limit_per_hour: 100

  # Include remediation in alerts
  include_remediation: true
```

Load the configuration:

```bash
stance notify load-config alerting-config.yaml
```

## Severity-Based Routing

Route alerts based on finding severity:

```bash
# Configure routing rules
stance notify route --severity critical --destination pagerduty-oncall
stance notify route --severity critical --destination slack-critical
stance notify route --severity high --destination slack-all
stance notify route --severity medium,low --destination email-team
```

## Alert Templates

Customize alert content with templates:

### Slack Template

```yaml
# templates/slack-template.yaml
template: |
  {
    "blocks": [
      {
        "type": "header",
        "text": {
          "type": "plain_text",
          "text": "{{ severity | upper }} Security Finding"
        }
      },
      {
        "type": "section",
        "fields": [
          {"type": "mrkdwn", "text": "*Rule:* {{ rule_id }}"},
          {"type": "mrkdwn", "text": "*Asset:* {{ asset_id }}"}
        ]
      },
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "*Description:*\n{{ description }}"
        }
      },
      {
        "type": "section",
        "text": {
          "type": "mrkdwn",
          "text": "*Remediation:*\n{{ remediation }}"
        }
      }
    ]
  }
```

### Email Template

```yaml
# templates/email-template.yaml
subject: "[{{ severity | upper }}] Security Finding: {{ rule_id }}"
body: |
  Security Finding Detected

  Severity: {{ severity }}
  Rule: {{ rule_id }}
  Asset: {{ asset_id }}

  Description:
  {{ description }}

  Remediation:
  {{ remediation }}

  ---
  Mantissa Stance Security Scanner
```

## Scan Completion Alerts

Get notified when scans complete:

```bash
# Enable scan completion notifications
stance notify settings --notify-on-scan-complete

# Configure what to include
stance notify settings \
  --notify-on-new-findings \
  --notify-on-resolved \
  --include-summary
```

## Integration Examples

### Slack with Rich Formatting

The Slack integration includes:
- Severity-based color coding (red/orange/yellow/blue)
- Finding details in expandable blocks
- Direct links to the dashboard
- Remediation guidance

### PagerDuty Integration

Features:
- Automatic incident creation
- Severity mapping to PagerDuty urgency
- Deduplication key to prevent duplicates
- Auto-resolve when findings are fixed

### Jira Integration

```bash
stance notify configure jira \
  --name jira-security \
  --url https://your-org.atlassian.net \
  --username your-email@example.com \
  --api-token your-api-token \
  --project-key SEC \
  --issue-type Bug
```

Issues include:
- Finding title as summary
- Full description with details
- Severity label
- Asset and rule information

### Microsoft Teams

```bash
stance notify configure teams \
  --name teams-security \
  --webhook-url https://outlook.webhook.office.com/xxx
```

Uses Adaptive Cards for rich formatting.

### Generic Webhook

For custom integrations:

```bash
stance notify configure webhook \
  --name custom-webhook \
  --url https://api.example.com/security-alerts \
  --method POST \
  --headers "Authorization: Bearer ${API_TOKEN}" \
  --headers "Content-Type: application/json"
```

## Dashboard Configuration

Configure alerts via the web dashboard:

1. Start the dashboard: `stance dashboard`
2. Navigate to Settings
3. Click "Notification Destinations"
4. Add and configure destinations
5. Set up routing rules

## Testing Alerts

```bash
# Test a specific destination
stance notify test slack-critical

# Send a test finding
stance notify send-test \
  --destination slack-critical \
  --severity high \
  --message "This is a test alert"

# Test all destinations
stance notify test --all
```

## Viewing Alert History

```bash
# List recent alerts
stance notify history

# Filter by destination
stance notify history --destination slack-critical

# Filter by time range
stance notify history --since 24h

# View failed alerts
stance notify history --status failed
```

## Rate Limiting and Deduplication

### Rate Limiting

Prevent alert storms:

```bash
stance notify settings --rate-limit 100 --rate-limit-window 3600
```

### Deduplication

Avoid duplicate alerts for the same finding:

```bash
# Set deduplication window (in seconds)
stance notify settings --dedup-window 3600
```

Deduplication key includes:
- Finding rule ID
- Asset ID
- Severity

## Best Practices

1. **Escalation Path**: Route critical to PagerDuty, others to Slack
2. **Rate Limit**: Prevent alert fatigue with rate limiting
3. **Deduplicate**: Avoid spamming with duplicate alerts
4. **Test Regularly**: Verify integrations are working
5. **Document Runbooks**: Include remediation steps in alerts
6. **Review History**: Check for failed alerts regularly

## Troubleshooting

### Alerts Not Sending

```bash
# Check destination configuration
stance notify show slack-critical

# Test connectivity
stance notify test slack-critical -v

# Check logs
stance notify history --destination slack-critical --status failed
```

### Rate Limited

If alerts are being rate limited:
- Increase rate limit threshold
- Aggregate alerts into digests
- Route lower severity to email

### Authentication Errors

- Verify API keys and tokens
- Check webhook URLs are valid
- Ensure credentials have required permissions

## Next Steps

- Return to [Quick Start](01-quick-start.md)
- Learn about [Custom Policies](04-custom-policies.md)
- Set up [Multi-Cloud Scanning](03-multi-cloud.md)
