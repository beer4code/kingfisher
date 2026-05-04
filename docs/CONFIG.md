# Project Configuration (`kingfisher.yaml`)

Long CLI invocations are awkward in CI. Kingfisher loads a project-local
`kingfisher.yaml` to provide additional alert webhooks and filter lists. The
file is **additive**: list-typed values are concatenated onto matching CLI
flags so there are no surprising overrides.

## Discovery

- `--config FILE` overrides everything; an explicit path that fails to parse is fatal.
- Otherwise Kingfisher walks up from the current working directory looking for
  `kingfisher.yaml`. Missing config is silent.

## Schema

```yaml
alerts:
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA   # required
      format: slack                                      # slack | teams | generic
      on: findings                                       # findings | always
      min_confidence: medium                             # low | medium | high
      include_secret: false                              # default false

filters:
  skip_words:
    - EXAMPLE
    - PLACEHOLDER
  skip_regex:
    - '^DUMMY_[A-Z]+$'
  exclude:
    - vendor/
    - "**/node_modules/**"
```

Unknown fields are rejected (typo protection). Empty sections are fine.

## Merge precedence

1. CLI flags (highest)
2. Config file
3. Built-in defaults (lowest)

For list-typed values both sources are concatenated, so passing
`--skip-word EXAMPLE` and listing `EXAMPLE` again in `kingfisher.yaml` is safe
but redundant.

## Example: CI workflow

```yaml
# .github/workflows/secrets.yml
- uses: mongodb/kingfisher/.github/actions/kingfisher@main
  with:
    config: ./kingfisher.yaml
    alert-webhook: ${{ secrets.SLACK_SECURITY_WEBHOOK }}
```

Combined with [`docs/ALERTS.md`](ALERTS.md), this lets one repo own its
webhook configuration without baking secrets into command-line strings.

## What's intentionally not in v1

- Scalar-field overrides (rule selection, output format, baseline path) —
  needs explicit "was this CLI flag provided?" tracking; planned for v2.
- Per-rule policy and severity overrides.
- Multi-tenant / org-wide config distribution.
