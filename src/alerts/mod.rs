//! Alert sinks: post scan results to Slack / Microsoft Teams / a generic webhook.
//!
//! Activated via CLI (`--alert-webhook`) or `kingfisher.yaml`. The dispatch is
//! best-effort: failure to deliver an alert never changes the scan exit code,
//! it only emits a `warn!` on stderr. Every webhook URL is treated as a secret —
//! we redact path/query when logging.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::cli::commands::scan::ConfidenceLevel;
use crate::reporter::FindingReporterRecord;

pub mod generic;
pub mod slack;
pub mod teams;

/// Trigger condition for an alert.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum AlertOn {
    /// Only post when at least one finding is reported.
    Findings,
    /// Always post, even on a clean run.
    Always,
}

impl Default for AlertOn {
    fn default() -> Self {
        AlertOn::Findings
    }
}

/// Webhook payload format / target.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum AlertFormat {
    /// Slack incoming-webhook (Block Kit).
    Slack,
    /// Microsoft Teams incoming-webhook (Adaptive Card / MessageCard).
    Teams,
    /// Generic JSON envelope (`{ summary, findings }`).
    Generic,
}

impl AlertFormat {
    /// Heuristic: infer the format from the webhook host when the user did
    /// not pass `--alert-format`.
    pub fn infer_from_url(url: &str) -> Self {
        let host = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_lowercase));
        match host.as_deref() {
            Some(h) if h.contains("slack.com") => AlertFormat::Slack,
            Some(h) if h.contains("office.com") || h.contains("webhook.office") => {
                AlertFormat::Teams
            }
            _ => AlertFormat::Generic,
        }
    }
}

/// One configured webhook destination. `--alert-webhook` may be repeated to
/// produce more than one. The config-file equivalent is `alerts.webhooks[]`.
#[derive(Clone, Debug)]
pub struct AlertSink {
    pub url: String,
    pub format: AlertFormat,
    pub on: AlertOn,
    pub min_confidence: ConfidenceLevel,
    pub include_secret: bool,
}

/// Summary numbers we surface to every sink, regardless of format.
#[derive(Clone, Debug, Serialize)]
pub struct AlertSummary {
    pub total: usize,
    pub active: usize,
    pub inactive: usize,
    pub unknown: usize,
    pub by_rule: Vec<(String, usize)>,
    pub kingfisher_version: String,
    pub target: Option<String>,
}

impl AlertSummary {
    pub fn from_findings(findings: &[FindingReporterRecord], target: Option<String>) -> Self {
        let mut active = 0usize;
        let mut inactive = 0usize;
        let mut unknown = 0usize;
        let mut by_rule_map: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for f in findings {
            *by_rule_map.entry(f.rule.id.clone()).or_default() += 1;
            match f.finding.validation.status.as_str() {
                "Active Credential" => active += 1,
                "Inactive Credential" => inactive += 1,
                _ => unknown += 1,
            }
        }
        let mut by_rule: Vec<(String, usize)> = by_rule_map.into_iter().collect();
        by_rule.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        by_rule.truncate(5);

        Self {
            total: findings.len(),
            active,
            inactive,
            unknown,
            by_rule,
            kingfisher_version: env!("CARGO_PKG_VERSION").to_string(),
            target,
        }
    }
}

/// Build a reqwest client suitable for outbound webhook POSTs. Webhook hosts
/// are public services; we always run with strict TLS validation here even if
/// the user passed `--tls-mode=off` for credential validation, since the user
/// almost certainly does not intend to lower TLS for their own paging service.
fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("kingfisher/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build webhook reqwest::Client")
}

/// Redact the path/query of a webhook URL so we never log the full secret token
/// embedded by Slack/Teams/etc. e.g. `https://hooks.slack.com/services/...` →
/// `https://hooks.slack.com/<redacted>`.
pub fn redact_webhook(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let scheme = u.scheme();
            let host = u.host_str().unwrap_or("");
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{scheme}://{host}{port}/<redacted>")
        }
        Err(_) => "<unparseable webhook url>".to_string(),
    }
}

/// Dispatch the configured alerts. Best-effort: a bad webhook produces a
/// `warn!` and never propagates as an error to the caller.
pub async fn dispatch(
    sinks: &[AlertSink],
    findings: &[FindingReporterRecord],
    target: Option<String>,
) {
    if sinks.is_empty() {
        return;
    }
    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            warn!("alert dispatch: failed to build HTTP client: {}", e);
            return;
        }
    };

    let summary = AlertSummary::from_findings(findings, target);
    debug!(
        "alert dispatch: total={} active={} inactive={} unknown={} sinks={}",
        summary.total,
        summary.active,
        summary.inactive,
        summary.unknown,
        sinks.len()
    );

    for sink in sinks {
        if matches!(sink.on, AlertOn::Findings) && summary.total == 0 {
            debug!(
                "alert dispatch: skipping {} (on=findings, no findings)",
                redact_webhook(&sink.url)
            );
            continue;
        }
        let filtered: Vec<&FindingReporterRecord> = findings
            .iter()
            .filter(|f| matches_min_confidence(&f.finding.confidence, sink.min_confidence))
            .collect();

        let payload = match sink.format {
            AlertFormat::Slack => slack::build_payload(&summary, &filtered, sink.include_secret),
            AlertFormat::Teams => teams::build_payload(&summary, &filtered, sink.include_secret),
            AlertFormat::Generic => {
                generic::build_payload(&summary, &filtered, sink.include_secret)
            }
        };

        match post(&client, &sink.url, &payload).await {
            Ok(()) => {
                info!("alert posted to {}", redact_webhook(&sink.url));
            }
            Err(e) => {
                warn!("alert dispatch failed for {}: {}", redact_webhook(&sink.url), e);
            }
        }
    }
}

fn matches_min_confidence(finding_confidence: &str, threshold: ConfidenceLevel) -> bool {
    let level = match finding_confidence {
        "Low" => ConfidenceLevel::Low,
        "Medium" => ConfidenceLevel::Medium,
        "High" => ConfidenceLevel::High,
        _ => ConfidenceLevel::Medium,
    };
    level >= threshold
}

async fn post(client: &Client, url: &str, payload: &serde_json::Value) -> Result<()> {
    let resp = client
        .post(url)
        .json(payload)
        .send()
        .await
        .with_context(|| format!("POST to {} failed", redact_webhook(url)))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "webhook returned HTTP {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_webhook_keeps_host() {
        let r = redact_webhook("https://hooks.slack.com/services/T0/B0/XXX");
        assert_eq!(r, "https://hooks.slack.com/<redacted>");
    }

    #[test]
    fn redact_webhook_unparseable() {
        let r = redact_webhook("not a url");
        assert_eq!(r, "<unparseable webhook url>");
    }

    #[test]
    fn infer_format_slack() {
        assert_eq!(
            AlertFormat::infer_from_url("https://hooks.slack.com/services/T0/B0/XXX"),
            AlertFormat::Slack
        );
    }

    #[test]
    fn infer_format_teams() {
        assert_eq!(
            AlertFormat::infer_from_url(
                "https://outlook.office.com/webhook/abc/IncomingWebhook/def"
            ),
            AlertFormat::Teams
        );
    }

    #[test]
    fn infer_format_generic_fallback() {
        assert_eq!(
            AlertFormat::infer_from_url("https://example.com/webhook"),
            AlertFormat::Generic
        );
    }
}
