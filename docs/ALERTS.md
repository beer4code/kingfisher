# Alert Webhooks

Kingfisher can POST a scan summary (and optionally per-finding details) to one
or more webhooks when a scan completes — Slack, Microsoft Teams, or any HTTPS
endpoint that accepts a JSON POST.

Alerting is **best-effort**. A bad webhook produces a `WARN` line on stderr and
*never* changes the scan exit code; this avoids breaking CI when paging
infrastructure is having a bad day.

## Quick start

```bash
# Slack incoming webhook (format inferred from the URL host).
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK"

# Teams + a generic webhook in one run.
kingfisher scan ./repo \
  --alert-webhook "$TEAMS_WEBHOOK" \
  --alert-webhook "https://siem.example.com/ingest" \
  --alert-format generic
```

The format is inferred from the URL host: `*.slack.com` → `slack`,
`*.office.com` → `teams`, otherwise `generic`. Set `--alert-format` to override.

## Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--alert-webhook URL` | *(none, repeatable)* | Destination URL; pass once per webhook. |
| `--alert-format slack\|teams\|generic` | inferred | Payload shape. |
| `--alert-on findings\|always` | `findings` | `always` posts even on a clean run. |
| `--alert-min-confidence low\|medium\|high` | `medium` | Findings below this are dropped from the payload. |
| `--alert-include-secret` | off | Include the (truncated to ~32 chars) secret value in the payload. |

Webhook URLs are sensitive: the host/path/query are redacted in logs. Pass them
via environment variables (`$SLACK_SECURITY_WEBHOOK`) or CI secrets, never
inline in committed files.

## Payload shapes

### Slack (Block Kit)

A header line, a "Top rules" section, an optional findings block (capped at 10
entries), and a context line with the Kingfisher version. Theme colour cues are
applied via the message structure itself.

### Microsoft Teams (MessageCard)

A coloured card — green if clean, amber if findings without active validation,
red if any active. Facts list active/inactive/unknown counts and the top rules.

### Generic JSON

```json
{
  "schema_version": "1",
  "kingfisher_version": "1.99.0",
  "summary": {
    "total": 3,
    "active": 1,
    "inactive": 1,
    "unknown": 1,
    "by_rule": [{"rule_id": "kingfisher.aws.1", "count": 2}],
    "target": "./repo"
  },
  "findings": [ /* array of FindingReporterRecord, capped at 200 */ ],
  "findings_omitted": 0
}
```

Findings are the same shape as `kingfisher scan --format json` produces, so
existing JSON consumers work unchanged.

## Configuring via `kingfisher.yaml`

CLI flags and config-file webhooks are concatenated. Per-webhook overrides live
in the config so you can mix one Slack channel for active findings with a
broader Teams channel that paged on every run:

```yaml
alerts:
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA
      format: slack
      on: findings
      min_confidence: high
    - url: https://outlook.office.com/webhook/XXX
      format: teams
      on: always
      min_confidence: medium
      include_secret: false
```

See [`docs/CONFIG.md`](CONFIG.md) for the full config schema.
