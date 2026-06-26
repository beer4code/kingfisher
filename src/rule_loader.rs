use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use thiserror::Error;
use tracing::{debug, error, info, trace};

use crate::{
    cli,
    cli::commands::rules::RuleSpecifierArgs,
    defaults::get_builtin_rules,
    rules::{
        Rules,
        rule::{Confidence, Rule},
    },
    util::Counted,
};
#[derive(Error, Debug)]
pub enum RuleLoaderError {
    #[error("Failed to load builtin rules")]
    BuiltinLoadError,

    #[error("Failed to load rules from additional paths")]
    AdditionalPathLoadError,

    #[error("Unknown rule: `{0}`")]
    UnknownRule(String),
}
pub struct RuleLoader {
    load_builtins: bool,
    additional_load_paths: Vec<PathBuf>,
    enabled_rule_ids: Option<Vec<String>>,
    excluded_rule_ids: Vec<String>,
}

impl Default for RuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleLoader {
    pub fn new() -> Self {
        Self {
            load_builtins: true,
            additional_load_paths: Vec::new(),
            enabled_rule_ids: None, // None means "all rules enabled"
            excluded_rule_ids: Vec::new(),
        }
    }

    pub fn load_builtins(mut self, load_builtins: bool) -> Self {
        self.load_builtins = load_builtins;
        self
    }

    pub fn additional_rule_load_paths<P: AsRef<Path>, I: IntoIterator<Item = P>>(
        mut self,
        paths: I,
    ) -> Self {
        self.additional_load_paths.extend(paths.into_iter().map(|p| p.as_ref().to_owned()));
        self
    }

    pub fn enable_rule_ids<S: AsRef<str>, I: IntoIterator<Item = S>>(mut self, ids: I) -> Self {
        let ids: Vec<String> = ids.into_iter().map(|s| s.as_ref().to_string()).collect();
        if ids.iter().any(|id| id == "all") {
            self.enabled_rule_ids = None; // Reset to "all rules enabled"
        } else {
            self.enabled_rule_ids = Some(ids);
        }
        self
    }

    pub fn exclude_rule_ids<S: AsRef<str>, I: IntoIterator<Item = S>>(mut self, ids: I) -> Self {
        self.excluded_rule_ids.extend(ids.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn load(&self, args: &cli::commands::scan::ScanArgs) -> Result<LoadedRules> {
        let confidence = Confidence::from(args.confidence);
        let mut id_to_rule: BTreeMap<String, Rule> = BTreeMap::new();

        if self.load_builtins {
            let builtin_rules =
                get_builtin_rules(Some(confidence)).context(RuleLoaderError::BuiltinLoadError)?;
            for rule_syntax in builtin_rules {
                let id = rule_syntax.id.clone();
                id_to_rule.insert(id, Rule::new(rule_syntax));
            }
        }

        if !self.additional_load_paths.is_empty() {
            let custom_rules = Rules::from_paths(&self.additional_load_paths, confidence)
                .context(RuleLoaderError::AdditionalPathLoadError)?;
            for rule_syntax in custom_rules {
                let id = rule_syntax.id.clone();
                id_to_rule.insert(id, Rule::new(rule_syntax));
            }
        }

        Ok(LoadedRules {
            id_to_rule,
            enabled_rule_ids: self.enabled_rule_ids.clone(),
            excluded_rule_ids: self.excluded_rule_ids.clone(),
        })
    }

    pub fn from_rule_specifiers(specs: &RuleSpecifierArgs) -> Self {
        Self::new()
            .load_builtins(specs.load_builtins)
            .additional_rule_load_paths(specs.rules_path.as_slice())
            .enable_rule_ids(specs.rule.iter())
            .exclude_rule_ids(specs.exclude_rule.iter())
    }
}

pub struct LoadedRules {
    id_to_rule: BTreeMap<String, Rule>,
    enabled_rule_ids: Option<Vec<String>>,
    excluded_rule_ids: Vec<String>,
}

impl LoadedRules {
    #[inline]
    pub fn num_rules(&self) -> usize {
        self.id_to_rule.len()
    }

    #[inline]
    pub fn iter_rules(&self) -> impl Iterator<Item = &Rule> {
        self.id_to_rule.values()
    }

    /// Get a reference to the underlying rule map (rule ID -> Rule).
    #[inline]
    pub fn id_to_rule(&self) -> &BTreeMap<String, Rule> {
        &self.id_to_rule
    }

    fn selector_matches_rule(selector: &str, rule_id: &str) -> bool {
        selector == "all"
            || rule_id == selector
            || (rule_id.starts_with(selector)
                && rule_id.as_bytes().get(selector.len()) == Some(&b'.'))
    }

    fn resolve_rule_selectors(&self, selectors: &[String]) -> Result<Vec<&Rule>> {
        let mut resolved = Vec::new();
        let mut seen = HashSet::new();

        for selector in selectors {
            let mut matched_any = false;

            for (id, rule) in &self.id_to_rule {
                if Self::selector_matches_rule(selector, id) {
                    matched_any = true;
                    if seen.insert(id.clone()) {
                        resolved.push(rule);
                    }
                }
            }

            if !matched_any {
                error!("Unknown rule `{}` encountered", selector);
                bail!(RuleLoaderError::UnknownRule(selector.clone()));
            }
        }

        Ok(resolved)
    }

    pub fn resolve_enabled_rules(&self) -> Result<Vec<&Rule>> {
        let mut resolved_rules = match &self.enabled_rule_ids {
            // No selectors ⇒ every rule is enabled
            None => {
                debug!("Using all available rules");
                self.iter_rules().collect()
            }

            // At least one selector was given
            Some(selectors) => self.resolve_rule_selectors(selectors)?,
        };

        if !self.excluded_rule_ids.is_empty() {
            let excluded_ids: HashSet<String> = self
                .resolve_rule_selectors(&self.excluded_rule_ids)?
                .into_iter()
                .map(|rule| rule.id().to_string())
                .collect();
            let before = resolved_rules.len();
            resolved_rules.retain(|rule| !excluded_ids.contains(rule.id()));
            debug!("Excluded {} rule(s) by selector", before.saturating_sub(resolved_rules.len()));
        }

        info!("Loaded {}", Counted::regular(resolved_rules.len(), "rule"));
        for rule in &resolved_rules {
            trace!("Using rule `{}`: {}", rule.id(), rule.name());
        }
        Ok(resolved_rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Confidence, RuleSyntax};

    fn test_rule(id: &str) -> Rule {
        Rule::new(RuleSyntax {
            name: format!("Rule {id}"),
            id: id.to_string(),
            pattern: "(?x)(test_secret)".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Low,
            visible: true,
            examples: Vec::new(),
            negative_examples: Vec::new(),
            references: Vec::new(),
            validation: None,
            revocation: None,
            depends_on_rule: Vec::new(),
            pattern_requirements: None,
            tls_mode: None,
        })
    }

    fn loaded_rules(enabled: Option<Vec<&str>>, excluded: Vec<&str>) -> LoadedRules {
        let mut id_to_rule = BTreeMap::new();
        for id in ["kingfisher.demo.1", "kingfisher.demo.2", "kingfisher.other.1"] {
            id_to_rule.insert(id.to_string(), test_rule(id));
        }
        LoadedRules {
            id_to_rule,
            enabled_rule_ids: enabled.map(|ids| ids.into_iter().map(str::to_string).collect()),
            excluded_rule_ids: excluded.into_iter().map(str::to_string).collect(),
        }
    }

    #[test]
    fn resolves_all_rules_except_excluded_ids() {
        let loaded = loaded_rules(None, vec!["kingfisher.demo.1"]);
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["kingfisher.demo.2", "kingfisher.other.1"]);
    }

    #[test]
    fn applies_exclusions_after_enabled_selectors() {
        let loaded = loaded_rules(Some(vec!["kingfisher.demo"]), vec!["kingfisher.demo.1"]);
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["kingfisher.demo.2"]);
    }

    #[test]
    fn resolves_multiple_enabled_and_excluded_selectors() {
        let loaded = loaded_rules(
            Some(vec!["kingfisher.demo", "kingfisher.other"]),
            vec!["kingfisher.demo.1", "kingfisher.other.1"],
        );
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["kingfisher.demo.2"]);
    }

    #[test]
    fn unknown_exclusion_selector_is_an_error() {
        let loaded = loaded_rules(None, vec!["kingfisher.missing.1"]);

        assert!(loaded.resolve_enabled_rules().is_err());
    }
}
