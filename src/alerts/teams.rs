//! Microsoft Teams incoming-webhook payload (legacy MessageCard schema).
//!
//! Teams' `IncomingWebhook` connector still accepts the simpler MessageCard
//! schema in addition to Adaptive Cards. We use MessageCard for broader
//! compatibility with both classic O365 connectors and newer Power Automate
//! webhooks.

use serde_json::{Value, json};

use crate::alerts::AlertSummary;
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let title = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        format!("Kingfisher: {} finding{}", summary.total, plural(summary.total))
    };

    let theme_color = if summary.active > 0 {
        "C0392B" // red — active live secrets
    } else if summary.total > 0 {
        "F39C12" // amber — findings present but unverified
    } else {
        "27AE60" // green — clean
    };

    let mut facts: Vec<Value> = vec![
        json!({ "name": "Active",   "value": summary.active.to_string() }),
        json!({ "name": "Inactive", "value": summary.inactive.to_string() }),
        json!({ "name": "Unknown",  "value": summary.unknown.to_string() }),
    ];
    if let Some(t) = &summary.target {
        facts.push(json!({ "name": "Target", "value": t }));
    }
    for (rule, count) in &summary.by_rule {
        facts.push(json!({ "name": rule, "value": count.to_string() }));
    }

    let mut sections: Vec<Value> = vec![json!({
        "activityTitle": title,
        "activitySubtitle": format!("kingfisher v{}", summary.kingfisher_version),
        "facts": facts,
        "markdown": true,
    })];

    if !findings.is_empty() {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut details = String::new();
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                truncate(&f.finding.snippet, 32)
            } else {
                "<redacted>".to_string()
            };
            details.push_str(&format!(
                "- **{}** at `{}:{}` — `{}` (validation: {})\n",
                f.rule.id, f.finding.path, f.finding.line, snippet, f.finding.validation.status
            ));
        }
        if findings.len() > take {
            details.push_str(&format!("_…{} more findings omitted_\n", findings.len() - take));
        }
        sections.push(json!({
            "title": "Findings",
            "text": details,
        }));
    }

    json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": theme_color,
        "title": title,
        "sections": sections,
    })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(total: usize, active: usize) -> AlertSummary {
        AlertSummary {
            total,
            active,
            inactive: 0,
            unknown: 0,
            by_rule: vec![],
            kingfisher_version: "test".to_string(),
            target: None,
        }
    }

    #[test]
    fn theme_color_red_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        assert_eq!(p["themeColor"], "C0392B");
    }

    #[test]
    fn theme_color_green_when_empty() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["themeColor"], "27AE60");
    }

    #[test]
    fn theme_color_amber_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        assert_eq!(p["themeColor"], "F39C12");
    }
}
