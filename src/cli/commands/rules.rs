use std::path::PathBuf;

use clap::{ArgAction, Args, Subcommand, ValueEnum, ValueHint};
use strum::Display;

use crate::cli::commands::{output::OutputArgs, scan::ConfidenceLevel};

// -----------------------------------------------------------------------------
// Rule Specifiers
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone, Default)]
pub struct RuleSpecifierArgs {
    /// Load additional rules from file(s) or directories
    ///
    /// Directories are walked recursively for YAML files. This option
    /// can be repeated.
    #[arg(global = true, long, alias="rules", value_hint=ValueHint::AnyPath)]
    pub rules_path: Vec<PathBuf>,

    /// Enable the ruleset with the given ID (e.g. `all`, `default`, or custom)
    ///
    /// Repeating this disables the default set unless `default` is explicitly included.
    #[arg(global = true, long, default_values_t=["all".to_string()])]
    pub rule: Vec<String>,

    /// Load built-in rules
    #[arg(global = true, long, default_value_t=true, action=ArgAction::Set)]
    pub load_builtins: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct RuleCacheArgs {
    /// Cache the compiled Vectorscan rule database between runs (default)
    #[arg(
        global = true,
        long = "rule-cache",
        default_value_t = false,
        conflicts_with = "no_rule_cache",
        hide = true
    )]
    pub rule_cache: bool,

    /// Disable the compiled Vectorscan rule database cache
    #[arg(
        global = true,
        long = "no-rule-cache",
        default_value_t = false,
        conflicts_with = "rule_cache"
    )]
    pub no_rule_cache: bool,

    /// Directory for the compiled rule cache
    #[arg(
        global = true,
        long = "rule-cache-dir",
        env = "KF_RULE_CACHE_DIR",
        value_name = "PATH",
        value_hint = ValueHint::DirPath
    )]
    pub rule_cache_dir: Option<PathBuf>,
}

impl RuleCacheArgs {
    pub fn enabled(&self) -> bool {
        !self.no_rule_cache
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct RuleCacheDirArgs {
    /// Directory for the compiled rule cache
    #[arg(
        long = "rule-cache-dir",
        env = "KF_RULE_CACHE_DIR",
        value_name = "PATH",
        value_hint = ValueHint::DirPath
    )]
    pub rule_cache_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Subcommand, Debug)]
pub enum RulesCommand {
    /// Check rules for problems
    Check(RulesCheckArgs),

    /// Compile and store the Vectorscan rule cache
    #[command(name = "compile-cache")]
    CompileCache(RulesCompileCacheArgs),

    /// List available rules
    List(RulesListArgs),
}

#[derive(Args, Debug)]
pub struct RulesCheckArgs {
    /// Treat warnings as errors
    #[arg(long, short = 'W')]
    pub warnings_as_errors: bool,

    #[command(flatten)]
    pub rules: RuleSpecifierArgs,
}

#[derive(Args, Debug)]
pub struct RulesListArgs {
    #[command(flatten)]
    pub rules: RuleSpecifierArgs,

    #[command(flatten)]
    pub output_args: OutputArgs<RulesListOutputFormat>,
}

#[derive(Args, Debug)]
pub struct RulesCompileCacheArgs {
    #[command(flatten)]
    pub rules: RuleSpecifierArgs,

    /// Minimum confidence level for rules included in the cache
    #[arg(global = true, long, short = 'c', default_value = "medium")]
    pub confidence: ConfidenceLevel,

    #[command(flatten)]
    pub cache: RuleCacheDirArgs,
}

// -----------------------------------------------------------------------------
// Rules List Output Format
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum RulesListOutputFormat {
    /// A human-friendly text-based format
    Pretty,
    /// Pretty-printed JSON
    Json,
}
