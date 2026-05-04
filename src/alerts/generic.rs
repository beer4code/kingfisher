//! Generic JSON webhook payload — `{ summary, findings }`.
//!
//! This is the most-flexible sink: drop in any HTTPS endpoint that accepts a
//! JSON POST and you get the same shape Kingfisher's reporter produces, wrapped
//! in a stable envelope so consumers can version against `schema_version`.

use serde_json::{Value, json};

use crate::alerts::AlertSummary;
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 200;
const SCHEMA_VERSION: &str = "1";

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let take = findings.len().min(PER_FINDING_LIMIT);
    let included: Vec<Value> = findings
        .iter()
        .take(take)
        .map(|f| {
            let mut record = serde_json::to_value(f).unwrap_or(Value::Null);
            if !include_secret
                && let Some(obj) = record.get_mut("finding").and_then(|v| v.as_object_mut())
            {
                obj.insert("snippet".into(), Value::String("<redacted>".to_string()));
            }
            record
        })
        .collect();

    json!({
        "schema_version": SCHEMA_VERSION,
        "kingfisher_version": summary.kingfisher_version,
        "summary": {
            "total": summary.total,
            "active": summary.active,
            "inactive": summary.inactive,
            "unknown": summary.unknown,
            "by_rule": summary.by_rule.iter().map(|(r, c)| json!({"rule_id": r, "count": c})).collect::<Vec<_>>(),
            "target": summary.target,
        },
        "findings": included,
        "findings_omitted": findings.len().saturating_sub(take),
    })
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
    fn schema_version_present() {
        let p = build_payload(&empty_summary(), &[], false);
        assert_eq!(p["schema_version"], "1");
    }

    #[test]
    fn empty_findings_array() {
        let p = build_payload(&empty_summary(), &[], false);
        assert_eq!(p["findings"].as_array().unwrap().len(), 0);
        assert_eq!(p["findings_omitted"], 0);
    }
}
