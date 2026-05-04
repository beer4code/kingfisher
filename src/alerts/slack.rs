//! Slack incoming-webhook payload (Block Kit).

use serde_json::{Value, json};

use crate::alerts::AlertSummary;
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let header_text = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        format!(
            "Kingfisher: {} finding{} ({} active, {} inactive, {} unknown)",
            summary.total,
            if summary.total == 1 { "" } else { "s" },
            summary.active,
            summary.inactive,
            summary.unknown
        )
    };

    let mut blocks: Vec<Value> = vec![json!({
        "type": "header",
        "text": { "type": "plain_text", "text": header_text }
    })];

    if let Some(target) = &summary.target {
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Target:* `{}`", escape_mrkdwn(target))
            }
        }));
    }

    if !summary.by_rule.is_empty() {
        let lines: Vec<String> = summary
            .by_rule
            .iter()
            .map(|(rule_id, count)| format!("• `{}` — {}", escape_mrkdwn(rule_id), count))
            .collect();
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Top rules*\n{}", lines.join("\n"))
            }
        }));
    }

    if !findings.is_empty() {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut detail_lines: Vec<String> = Vec::with_capacity(take);
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                truncate(&f.finding.snippet, 32)
            } else {
                "<redacted>".to_string()
            };
            detail_lines.push(format!(
                "• `{}` at `{}:{}` — {} (validation: {})",
                escape_mrkdwn(&f.rule.id),
                escape_mrkdwn(&f.finding.path),
                f.finding.line,
                snippet,
                escape_mrkdwn(&f.finding.validation.status)
            ));
        }
        if findings.len() > take {
            detail_lines.push(format!("_…{} more findings omitted_", findings.len() - take));
        }
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": detail_lines.join("\n") }
        }));
    }

    blocks.push(json!({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": format!("kingfisher v{}", summary.kingfisher_version)
        }]
    }));

    json!({ "text": header_text, "blocks": blocks })
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

/// Slack mrkdwn requires `<>&` escaping; backticks are fine inside code spans.
fn escape_mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_summary() -> AlertSummary {
        AlertSummary {
            total: 0,
            active: 0,
            inactive: 0,
            unknown: 0,
            by_rule: vec![],
            kingfisher_version: "test".to_string(),
            target: None,
        }
    }

    #[test]
    fn empty_payload_has_no_finding_block() {
        let p = build_payload(&empty_summary(), &[], false);
        let blocks = p["blocks"].as_array().unwrap();
        let header = &blocks[0]["text"]["text"].as_str().unwrap();
        assert!(header.contains("no findings"));
    }

    #[test]
    fn header_pluralization() {
        let summary = AlertSummary {
            total: 1,
            active: 1,
            inactive: 0,
            unknown: 0,
            by_rule: vec![("kingfisher.aws.1".into(), 1)],
            kingfisher_version: "test".to_string(),
            target: None,
        };
        let p = build_payload(&summary, &[], false);
        let header = p["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(header.contains("1 finding"));
        assert!(!header.contains("findings"), "should be singular");
    }
}
