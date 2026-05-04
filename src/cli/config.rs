//! `kingfisher.yaml` project configuration.
//!
//! v1 is intentionally narrow. The config file is **additive**: list-typed
//! values are concatenated onto CLI flags so behavior is predictable when both
//! sources are present.
//!
//! ```yaml
//! alerts:
//!   webhooks:
//!     - url: https://hooks.slack.com/services/...
//!       format: slack          # slack | teams | generic | discord | mattermost | googlechat
//!       on: findings           # findings | always
//!       min_confidence: medium # low | medium | high
//!       include_secret: false
//!       report_url: https://github.com/org/repo/actions/runs/123  # optional pivot link
//!       detail: auto           # summary | detail | auto
//! filters:
//!   skip_words: ["EXAMPLE", "TEST"]
//!   skip_regex: ['^DUMMY_']
//!   exclude:    ["vendor/", "node_modules/"]
//! ```
//!
//! This module is parsing-only. The CLI entry point (main.rs) is responsible
//! for resolving paths and reading file contents, then passing the YAML text
//! into `parse_str`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::alerts::{AlertDetail, AlertFormat, AlertOn};
use crate::cli::commands::scan::ConfidenceLevel;

/// File name auto-discovered when the user does not pass `--config`.
pub const DEFAULT_CONFIG_NAME: &str = "kingfisher.yaml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KingfisherConfig {
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub filters: FiltersConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub format: Option<AlertFormat>,
    #[serde(default, rename = "on")]
    pub on: Option<AlertOn>,
    #[serde(default)]
    pub min_confidence: Option<ConfigConfidence>,
    #[serde(default)]
    pub include_secret: Option<bool>,
    /// Per-webhook override of the global `--alert-report-url`. Useful when
    /// chat sinks should carry a pivot link but a SIEM-bound generic webhook
    /// shouldn't.
    #[serde(default)]
    pub report_url: Option<String>,
    /// Per-webhook override of the global `--alert-detail` mode.
    #[serde(default)]
    pub detail: Option<AlertDetail>,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigConfidence {
    Low,
    Medium,
    High,
}

impl From<ConfigConfidence> for ConfidenceLevel {
    fn from(c: ConfigConfidence) -> Self {
        match c {
            ConfigConfidence::Low => ConfidenceLevel::Low,
            ConfigConfidence::Medium => ConfidenceLevel::Medium,
            ConfigConfidence::High => ConfidenceLevel::High,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiltersConfig {
    #[serde(default)]
    pub skip_words: Vec<String>,
    #[serde(default)]
    pub skip_regex: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Parse YAML text into a config struct.
pub fn parse_str(yaml: &str) -> Result<KingfisherConfig> {
    serde_yaml::from_str(yaml).context("failed to parse kingfisher.yaml")
}

/// Walk upward from `start` looking for a sibling `kingfisher.yaml`. Returns
/// the absolute path when found. Performs *no* file reads — the caller does
/// the read once it has decided which file to use.
pub fn discover_path(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join(DEFAULT_CONFIG_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_minimal_alerts() {
        let yaml = r#"
alerts:
  webhooks:
    - url: https://example.com/hook
      format: slack
      on: findings
"#;
        let cfg = parse_str(yaml).unwrap();
        assert_eq!(cfg.alerts.webhooks.len(), 1);
        assert_eq!(cfg.alerts.webhooks[0].url, "https://example.com/hook");
        assert_eq!(cfg.alerts.webhooks[0].format, Some(AlertFormat::Slack));
        assert_eq!(cfg.alerts.webhooks[0].on, Some(AlertOn::Findings));
    }

    #[test]
    fn parse_filters() {
        let yaml = r#"
filters:
  skip_words: ["EXAMPLE", "TEST"]
  exclude: ["vendor/", "**/node_modules/**"]
"#;
        let cfg = parse_str(yaml).unwrap();
        assert_eq!(cfg.filters.skip_words, vec!["EXAMPLE", "TEST"]);
        assert_eq!(cfg.filters.exclude.len(), 2);
    }

    #[test]
    fn empty_yaml_yields_default() {
        let cfg = parse_str("").unwrap_or_default();
        assert!(cfg.alerts.webhooks.is_empty());
        assert!(cfg.filters.skip_words.is_empty());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let yaml = "alerts:\n  webhooks: []\nbogus: 42\n";
        assert!(parse_str(yaml).is_err());
    }

    #[test]
    fn discover_walks_upward() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let cfg_path = temp.path().join(DEFAULT_CONFIG_NAME);
        std::fs::write(&cfg_path, "alerts: { webhooks: [] }\n").unwrap();
        let found = discover_path(&nested).unwrap();
        assert_eq!(
            std::fs::canonicalize(&found).unwrap(),
            std::fs::canonicalize(&cfg_path).unwrap()
        );
    }

    #[test]
    fn discover_returns_none_when_absent() {
        let temp = TempDir::new().unwrap();
        let found = discover_path(temp.path());
        assert!(found.is_none());
    }
}
