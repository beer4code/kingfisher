// ────────────────────────────────────────────────────────────
// Global allocator setup
//   * Default  - mimalloc (`use-mimalloc`)
//   * Opt-in   - jemalloc (`use-jemalloc`) for one-off debugging
//   * Explicit - system allocator on Darwin (`system-alloc`)
// ────────────────────────────────────────────────────────────

#[cfg(all(feature = "use-jemalloc", feature = "system-alloc"))]
compile_error!("`use-jemalloc` and `system-alloc` are mutually exclusive");

#[cfg(all(feature = "use-jemalloc", feature = "use-mimalloc"))]
compile_error!("`use-jemalloc` and `use-mimalloc` are mutually exclusive");

#[cfg(all(feature = "system-alloc", not(target_os = "macos")))]
compile_error!("`system-alloc` is only supported on Darwin targets");

// --- jemalloc (opt-in) ---
#[cfg(feature = "use-jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// --- mimalloc (default) ---
#[cfg(all(
    not(feature = "use-jemalloc"),
    not(feature = "system-alloc"),
    any(feature = "use-mimalloc", target_os = "linux", target_os = "windows")
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// --- system allocator (fallback, explicit on Darwin) ---
#[cfg(any(
    feature = "system-alloc",
    all(
        not(feature = "use-jemalloc"),
        not(feature = "system-alloc"),
        not(any(feature = "use-mimalloc", target_os = "linux", target_os = "windows"))
    )
))]
use std::alloc::System;
#[cfg(any(
    feature = "system-alloc",
    all(
        not(feature = "use-jemalloc"),
        not(feature = "system-alloc"),
        not(any(feature = "use-mimalloc", target_os = "linux", target_os = "windows"))
    )
))]
#[global_allocator]
static GLOBAL: System = System;

use std::{
    io::{IsTerminal, Read, Write},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use console::Term;
use kingfisher::{
    access_map, azure, bitbucket,
    cli::{
        self, CommandLineArgs, GlobalArgs,
        commands::{
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::{
                RuleSpecifierArgs, RulesCheckArgs, RulesCommand, RulesListArgs,
                RulesListOutputFormat,
            },
        },
        global::Command,
    },
    direct_revoke, direct_validate, findings_store,
    findings_store::FindingsStore,
    gitea, github, huggingface,
    reporter::{DetailsReporter, ScanAuditContext, styles::Styles},
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::{load_and_record_rules, run_scan},
    update::{check_for_update_async, rewrite_argv_for_reexec},
    validation::set_user_agent_suffix,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::runtime::Builder;
use tracing::{error, info, warn};
use tracing_core::metadata::LevelFilter;
use tracing_subscriber::{
    self, fmt, prelude::__tracing_subscriber_SubscriberExt, registry, util::SubscriberInitExt,
};
use url::Url;

use crate::cli::commands::{
    azure::AzureRepoType,
    bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
    gitea::GiteaRepoType,
    gitlab::GitLabRepoType,
    scan::{ListRepositoriesCommand, ScanOperation},
    view,
};

fn main() -> anyhow::Result<()> {
    color_backtrace::install();

    // Run the real entry point on a thread with an explicit, larger stack so that
    // deeply-nested async state machines (validation pipeline) cannot overflow the
    // default main-thread stack.
    const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MiB
    let builder =
        std::thread::Builder::new().name("kingfisher-main".to_string()).stack_size(STACK_SIZE);

    let handler = builder.spawn(run).expect("failed to spawn main thread");
    handler.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// Outcome of `async_main`. Used to signal that the runtime should be torn down
/// and the process should re-exec into a freshly self-updated binary.
enum AsyncMainOutcome {
    Done,
    Reexec,
}

fn run() -> anyhow::Result<()> {
    // Rustls 0.23 requires an explicit crypto provider selection when multiple
    // providers are present in the dependency graph.
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => {}
        Err(_already_installed) => {
            // Another crate already installed a provider. This is unusual for a CLI, but
            // surfacing it makes later TLS issues much easier to diagnose.
            warn!("rustls crypto provider was already installed; keeping existing provider");
        }
    }
    // Parse command-line arguments
    let CommandLineArgs { command, global_args } = CommandLineArgs::parse_args();

    set_user_agent_suffix(global_args.user_agent_suffix.clone());

    let args = CommandLineArgs { command, global_args };

    // Determine the number of jobs, defaulting to the number of CPUs
    let num_jobs = match &args.command {
        Command::Scan(scan_args) => scan_args.scan_args.num_jobs,
        Command::SelfUpdate => 1, // Self-update doesn't need a thread pool
        Command::Rules(_) => std::thread::available_parallelism().map_or(1, |n| n.get()), // Default for Rules commands
        Command::Validate(_) => 1, // Single validation request
        Command::Revoke(_) => 1,   // Single revocation request
        Command::AccessMap(_) => 1,
        Command::View(_) => 1,
    };

    // Set up the Tokio runtime with the specified number of threads.
    // Worker threads need larger stacks because async state machines (validation
    // pipeline) can produce large poll stack frames. 8 MiB is sufficient now that
    // the validators are split into separate async fns.
    let runtime = Builder::new_multi_thread()
        .worker_threads(num_jobs)
        .thread_stack_size(8 * 1024 * 1024) // 8 MiB per worker
        .enable_all()
        .build()
        .context("Failed to create Tokio runtime")?;
    let outcome = runtime.block_on(async_main(args))?;
    // Drop the Tokio runtime before re-exec so background tasks, file descriptors,
    // and signal handlers are torn down cleanly. On Unix `exec()` replaces the process
    // image regardless, but draining the runtime first avoids surprising shutdown
    // ordering when the re-exec happens to fail.
    drop(runtime);

    match outcome {
        AsyncMainOutcome::Done => Ok(()),
        AsyncMainOutcome::Reexec => {
            // On Unix, a successful exec() never returns; on Windows, reexec_with_new_binary
            // calls process::exit. We only reach here if the re-exec failed before transferring
            // control. The on-disk binary is now the updated version, so re-running the same
            // command will work — but the original command has NOT executed, so we must not
            // exit 0 and let CI think the run succeeded.
            if let Err(e) = reexec_with_new_binary() {
                error!(
                    "Binary was updated but re-exec failed: {e}. The original command did not \
                     run. Re-run the command to use the new binary."
                );
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// Re-exec the current process into the binary at `current_exe()` so a freshly
/// self-updated binary takes over the current invocation.
///
/// Argv is rewritten via [`rewrite_argv_for_reexec`] to prevent loops and to skip the
/// next update check.
///
/// On Unix this calls `exec()` which replaces the process image — same PID, parent
/// shell sees the new binary's exit code directly.
///
/// On Windows there is no true `exec()`. Standard practice (rustup, cargo) is to spawn
/// the new binary, wait, and propagate its exit code. This adds a parent process layer
/// but preserves the parent shell's child-process tracking.
fn reexec_with_new_binary() -> std::io::Result<()> {
    use std::process::Command;

    let exe = std::env::current_exe()?;
    let argv: Vec<std::ffi::OsString> = rewrite_argv_for_reexec(std::env::args_os());

    // Defensive: rewrite_argv_for_reexec returns an empty Vec only when args_os() was empty,
    // which shouldn't happen for a real CLI invocation but would produce a child process with
    // no argv[0]. Bail rather than spawn something nonsensical.
    if argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cannot re-exec: process started with empty argv",
        ));
    }

    // Make sure prior stderr/stdout output (e.g. "Updated to version X") is committed
    // before we either replace the process image (Unix) or spawn the child (Windows). On
    // Windows the child inherits the same handles, so leftover buffered output from the
    // parent could otherwise interleave with the child's output unpredictably.
    let _ = std::io::stdout().flush();
    let _ = writeln!(std::io::stderr(), "Restarting with updated binary...");
    let _ = std::io::stderr().flush();

    // Safe by the is_empty() guard above.
    let argv0 = argv[0].clone();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&exe).args(argv.iter().skip(1)).arg0(&argv0).exec();
        // exec() returns only on failure.
        Err(err)
    }

    #[cfg(windows)]
    {
        // arg0 spoofing isn't available on Windows; the child sees the resolved exe path
        // as argv[0]. The user-visible difference is cosmetic.
        let _ = argv0;
        let status = Command::new(&exe).args(argv.iter().skip(1)).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (exe, argv0);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "re-exec is not supported on this platform",
        ))
    }
}

fn setup_logging(global_args: &GlobalArgs) {
    // Determine log level based on global verbosity
    let (level, all_targets) = if global_args.quiet {
        (LevelFilter::ERROR, false)
    } else {
        let level = match global_args.verbose {
            0 => LevelFilter::INFO,  // Default level if no `-v` is provided
            1 => LevelFilter::DEBUG, // `-v`
            2 => LevelFilter::TRACE, // `-vv`
            _ => LevelFilter::TRACE, // `-vvv` or more
        };
        let all_targets = global_args.verbose > 2; // Enable all targets for `-vvv` or more
        (level, all_targets)
    };
    // Create a filter for logging
    let filter = if all_targets {
        // Enable TRACE for all modules
        tracing_subscriber::filter::Targets::new().with_default(LevelFilter::TRACE)
    } else {
        // Per-target filtering, only TRACE for `kingfisher`
        tracing_subscriber::filter::Targets::new()
            .with_default(LevelFilter::ERROR) // Default for all modules
            .with_target("kingfisher", level) // Replace `kingfisher` with your
        // crate's name
    };
    // Configure the formatter layer
    let fmt_layer = fmt::layer()
        .with_writer(std::io::stderr) // Write logs to stderr
        .with_target(true) // Enable target filtering
        .with_ansi(std::io::stderr().is_terminal()) // Emit ANSI colours when stderr is a TTY
        .without_time(); // Remove timestamps
    // Build and initialize the registry
    registry()
        .with(fmt_layer) // Attach the formatter layer
        .with(filter) // Attach the filter
        .init();
}

/// Resolve and read a `kingfisher.yaml` project config.
/// - Explicit `--config <PATH>` is required to exist; missing/unreadable is an error.
/// - Otherwise we walk up from CWD looking for `kingfisher.yaml`. Missing is fine.
fn load_project_config(
    explicit: Option<&std::path::Path>,
) -> Result<Option<kingfisher::cli::config::KingfisherConfig>> {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => {
            let cwd = std::env::current_dir().context("read CWD for config discovery")?;
            kingfisher::cli::config::discover_path(&cwd)
        }
    };
    match path {
        Some(p) => {
            let bytes =
                std::fs::read(&p).with_context(|| format!("read config {}", p.display()))?;
            let yaml = String::from_utf8(bytes)
                .with_context(|| format!("config {} is not UTF-8", p.display()))?;
            let cfg = kingfisher::cli::config::parse_str(&yaml)
                .with_context(|| format!("parse config {}", p.display()))?;
            info!("loaded config from {}", p.display());
            Ok(Some(cfg))
        }
        None => Ok(None),
    }
}

/// Merge config-file values into clap-parsed args. Lists are concatenated.
fn apply_config(
    scan_args: &mut cli::commands::scan::ScanArgs,
    cfg: &kingfisher::cli::config::KingfisherConfig,
) {
    // Filters — append to whatever was passed on the CLI.
    scan_args.skip_word.extend(cfg.filters.skip_words.iter().cloned());
    scan_args.skip_regex.extend(cfg.filters.skip_regex.iter().cloned());
    scan_args.content_filtering_args.exclude.extend(cfg.filters.exclude.iter().cloned());

    // Alerts — append URLs. Per-webhook overrides are stored in
    // `pending_config_alert_sinks` so the dispatch site can use them.
    for w in &cfg.alerts.webhooks {
        scan_args.alert_webhook.push(w.url.clone());
        scan_args.config_webhook_overrides.push(
            kingfisher::cli::commands::scan::ConfigWebhookOverride {
                format: w.format,
                on: w.on,
                min_confidence: w.min_confidence.map(Into::into),
                include_secret: w.include_secret,
                report_url: w.report_url.clone(),
                detail: w.detail,
            },
        );
    }
}

/// Build a human-readable description of what the scan is targeting, for use
/// in alert payloads (`Target:` header). The previous implementation looked
/// only at the first local path, so scans that used git URLs, GitHub orgs,
/// S3 buckets, etc. produced an empty target line. This walks the input
/// specifiers in priority order and returns the first one that's set.
fn describe_scan_target(args: &InputSpecifierArgs) -> Option<String> {
    fn join_brief<T: std::fmt::Display>(items: &[T], label: &str) -> String {
        match items.len() {
            0 => String::new(),
            1 => items[0].to_string(),
            n if n <= 3 => items.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
            n => format!("{} {label}", n),
        }
    }

    // Local paths — the most common scan target.
    if !args.path_inputs.is_empty() {
        let s = if args.path_inputs.len() == 1 {
            args.path_inputs[0].display().to_string()
        } else if args.path_inputs.len() <= 3 {
            args.path_inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        } else {
            format!("{} paths", args.path_inputs.len())
        };
        return Some(s);
    }
    if !args.git_url.is_empty() {
        return Some(join_brief(&args.git_url, "git URLs"));
    }
    if !args.github_user.is_empty() {
        return Some(format!("github user: {}", join_brief(&args.github_user, "github users")));
    }
    if !args.github_organization.is_empty() {
        return Some(format!(
            "github org: {}",
            join_brief(&args.github_organization, "github orgs")
        ));
    }
    if args.all_github_organizations {
        return Some("all GitHub organizations".to_string());
    }
    if !args.gitlab_user.is_empty() {
        return Some(format!("gitlab user: {}", join_brief(&args.gitlab_user, "gitlab users")));
    }
    if !args.gitlab_group.is_empty() {
        return Some(format!("gitlab group: {}", join_brief(&args.gitlab_group, "gitlab groups")));
    }
    if !args.huggingface_user.is_empty() || !args.huggingface_organization.is_empty() {
        return Some("huggingface".to_string());
    }
    if !args.gitea_user.is_empty() || !args.gitea_organization.is_empty() {
        return Some("gitea".to_string());
    }
    if !args.bitbucket_user.is_empty() || !args.bitbucket_workspace.is_empty() {
        return Some("bitbucket".to_string());
    }
    if !args.azure_organization.is_empty() {
        return Some(format!("azure: {}", join_brief(&args.azure_organization, "azure orgs")));
    }
    if let Some(b) = &args.s3_bucket {
        return Some(format!("s3://{}{}", b, args.s3_prefix.as_deref().unwrap_or("")));
    }
    if let Some(b) = &args.gcs_bucket {
        return Some(format!("gs://{}{}", b, args.gcs_prefix.as_deref().unwrap_or("")));
    }
    if !args.docker_image.is_empty() {
        return Some(format!("docker: {}", join_brief(&args.docker_image, "images")));
    }
    if let Some(u) = &args.jira_url {
        return Some(format!("jira: {}", u));
    }
    if let Some(u) = &args.confluence_url {
        return Some(format!("confluence: {}", u));
    }
    if args.slack_query.is_some() {
        return Some("slack search".to_string());
    }
    if args.teams_query.is_some() {
        return Some("teams search".to_string());
    }
    if !args.postman_workspaces.is_empty()
        || !args.postman_collections.is_empty()
        || args.postman_all
    {
        return Some("postman".to_string());
    }
    None
}

/// Build the resolved list of alert sinks from CLI flags + config overrides.
/// `scan_args.config_webhook_overrides` aligns with the trailing entries of
/// `scan_args.alert_webhook` (those that came from `kingfisher.yaml`); CLI URLs
/// always come first and use the scalar CLI flags.
fn build_alert_sinks(
    scan_args: &cli::commands::scan::ScanArgs,
) -> Vec<kingfisher::alerts::AlertSink> {
    let cli_count = scan_args.alert_webhook.len() - scan_args.config_webhook_overrides.len();
    scan_args
        .alert_webhook
        .iter()
        .enumerate()
        .map(|(i, url)| {
            let override_ = if i >= cli_count {
                scan_args.config_webhook_overrides.get(i - cli_count).cloned().unwrap_or_default()
            } else {
                cli::commands::scan::ConfigWebhookOverride::default()
            };
            let format = override_
                .format
                .or(scan_args.alert_format)
                .unwrap_or_else(|| kingfisher::alerts::AlertFormat::infer_from_url(url));
            kingfisher::alerts::AlertSink {
                url: url.clone(),
                format,
                on: override_.on.unwrap_or(scan_args.alert_on),
                min_confidence: override_.min_confidence.unwrap_or(scan_args.alert_min_confidence),
                include_secret: override_.include_secret.unwrap_or(scan_args.alert_include_secret),
                report_url: override_
                    .report_url
                    .clone()
                    .or_else(|| scan_args.alert_report_url.clone()),
                detail: override_.detail.unwrap_or(scan_args.alert_detail),
            }
        })
        .collect()
}

pub fn determine_exit_code(datastore: &Arc<Mutex<findings_store::FindingsStore>>) -> i32 {
    // exit with code 200 if _any_ findings are discovered
    // exit with code 205 if VALIDATED findings are discovered
    // exit with code 0 if there are NO findings discovered
    let ds = datastore.lock().unwrap();
    // Get all matches
    // let all_matches = ds.get_matches();

    // Only consider visible matches when determining the exit code
    let all_matches = ds
        .get_matches()
        .iter()
        .filter(|msg| {
            let (_, _, match_item) = &***msg;
            match_item.visible
        })
        .collect::<Vec<_>>();

    if all_matches.is_empty() {
        // No findings discovered
        0
    } else {
        // Check if there are any validated findings
        let validated_matches = all_matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = &****msg;
                match_item.validation_success
            })
            .count();
        if validated_matches > 0 {
            // Validated findings discovered
            205
        } else {
            // Findings discovered, but not validated
            200
        }
    }
}

async fn async_main(args: CommandLineArgs) -> Result<AsyncMainOutcome> {
    setup_logging(&args.global_args);
    let global_args = args.global_args.clone();

    match args.command {
        Command::SelfUpdate => {
            // The explicit `kingfisher self-update` subcommand intentionally does NOT
            // re-exec after updating: it has no further work to do, so simply exiting
            // is the correct end-of-run behavior. The re-exec path is reserved for the
            // global `--self-update` flag combined with another command (e.g. `scan`).
            let mut g = global_args;
            g.self_update = true;
            g.no_update_check = false;
            let _ = check_for_update_async(&g, None).await;
            Ok(AsyncMainOutcome::Done)
        }
        Command::View(view_args) => view::run(view_args).await.map(|_| AsyncMainOutcome::Done),
        Command::AccessMap(identity_args) => {
            access_map::run(identity_args).await.map(|_| AsyncMainOutcome::Done)
        }
        Command::Validate(validate_args) => {
            let results =
                direct_validate::run_direct_validation(&validate_args, &global_args).await?;
            let use_color = global_args.use_color(std::io::stdout());
            direct_validate::print_results(&results, &validate_args.format, use_color);
            // Exit with code 0 if any result is valid, 1 if all invalid
            if direct_validate::any_valid(&results) {
                Ok(AsyncMainOutcome::Done)
            } else {
                std::process::exit(1);
            }
        }
        Command::Revoke(revoke_args) => {
            let results = direct_revoke::run_direct_revocation(&revoke_args, &global_args).await?;
            let use_color = global_args.use_color(std::io::stdout());
            direct_revoke::print_results(&results, &revoke_args.format, use_color);
            // Exit with code 0 if any result revoked, 1 if all failed
            if direct_revoke::any_revoked(&results) {
                Ok(AsyncMainOutcome::Done)
            } else {
                std::process::exit(1);
            }
        }
        command => {
            let update_status = check_for_update_async(&global_args, None).await;
            // If the on-disk binary was just replaced by --self-update, return early so
            // fn run() can drop the runtime and re-exec into the new binary. The current
            // invocation will resume with the new code (e.g. updated rule set).
            if update_status.was_self_updated {
                return Ok(AsyncMainOutcome::Reexec);
            }
            match command {
                Command::Scan(scan_command) => match scan_command.into_operation()? {
                    ScanOperation::Scan(mut scan_args) => {
                        // Resolve and merge kingfisher.yaml (additive: lists are concatenated
                        // onto CLI flags). Errors only when --config explicitly points at a
                        // file we cannot parse. Auto-discovery failures are silent.
                        let loaded_config = load_project_config(global_args.config.as_deref())?;
                        if let Some(cfg) = &loaded_config {
                            apply_config(&mut scan_args, cfg);
                        }
                        if scan_args.view_report {
                            view::ensure_port_available(
                                scan_args.view_report_port,
                                &scan_args.view_report_address,
                                "--view-report-port",
                            )?;
                        }
                        let view_scan_started_at = chrono::Local::now();
                        let view_scan_start_time = Instant::now();
                        let temp_dir =
                            TempDir::new().context("Failed to create temporary directory")?;
                        let temp_dir_path = temp_dir.path().to_path_buf();
                        let clone_dir = if let Some(clone_dir) =
                            scan_args.input_specifier_args.git_clone_dir.as_ref()
                        {
                            std::fs::create_dir_all(clone_dir)?;
                            clone_dir.to_path_buf()
                        } else {
                            temp_dir_path.clone()
                        };
                        let keep_clones = scan_args.input_specifier_args.keep_clones
                            && scan_args.input_specifier_args.git_clone_dir.is_none();
                        // When clones go into the temp dir and the user hasn't asked to
                        // keep them, delete each clone as soon as it has been scanned so
                        // disk usage stays bounded for very large fan-outs (e.g.
                        // --include-contributors expanding to thousands of repos).
                        let auto_cleanup_clones = !scan_args.input_specifier_args.keep_clones
                            && scan_args.input_specifier_args.git_clone_dir.is_none();

                        let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
                        info!(
                            "Launching with {} concurrent scan jobs. Use --num-jobs to override.",
                            &scan_args.num_jobs
                        );
                        let paths = &scan_args.input_specifier_args.path_inputs;
                        let is_dash = paths.iter().any(|p| p.as_os_str() == "-");
                        if (paths.is_empty() || is_dash) && !std::io::stdin().is_terminal() {
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            let stdin_file = temp_dir_path.join("stdin_input");
                            std::fs::write(&stdin_file, buf)?;
                            scan_args.input_specifier_args.path_inputs = vec![stdin_file.into()];
                        }

                        let rules_db = Arc::new(load_and_record_rules(
                            &scan_args,
                            &datastore,
                            global_args.use_progress(),
                        )?);
                        run_scan(
                            &global_args,
                            &scan_args,
                            &rules_db,
                            Arc::clone(&datastore),
                            &update_status,
                            auto_cleanup_clones,
                        )
                        .await?;
                        if update_status.is_outdated {
                            if let Some(styled) = &update_status.styled_message {
                                let _ = writeln!(std::io::stderr(), "{}", styled);
                            }
                        }
                        let exit_code = determine_exit_code(&datastore);

                        // Dispatch alert webhooks (best-effort; failures are warned, not fatal).
                        if !scan_args.alert_webhook.is_empty() {
                            let alert_reporter = DetailsReporter {
                                datastore: Arc::clone(&datastore),
                                styles: Styles::new(global_args.use_color(std::io::stdout())),
                                only_valid: scan_args.only_valid,
                                audit_context: None,
                            };
                            match alert_reporter.build_finding_records(&scan_args) {
                                Ok(records) => {
                                    let target =
                                        describe_scan_target(&scan_args.input_specifier_args);
                                    let sinks = build_alert_sinks(&scan_args);
                                    kingfisher::alerts::dispatch(&sinks, &records, target).await;
                                }
                                Err(e) => warn!("alert dispatch: failed to build findings: {}", e),
                            }
                        }

                        if scan_args.view_report {
                            let audit_context = ScanAuditContext {
                                scan_timestamp: Some(view_scan_started_at.to_rfc3339()),
                                scan_duration_seconds: Some(
                                    view_scan_start_time.elapsed().as_secs_f64(),
                                ),
                                rules_applied: Some(rules_db.num_rules()),
                                successful_validations: None,
                                failed_validations: None,
                                skipped_validations: None,
                                blobs_scanned: None,
                                bytes_scanned: None,
                                running_version: Some(update_status.running_version.clone()),
                                latest_version: update_status.latest_version.clone(),
                                update_check_status: Some(
                                    update_status.check_status.as_str().to_string(),
                                ),
                            };
                            let reporter = DetailsReporter {
                                datastore: Arc::clone(&datastore),
                                styles: Styles::new(global_args.use_color(std::io::stdout())),
                                only_valid: scan_args.only_valid,
                                audit_context: Some(audit_context),
                            };
                            let envelope = reporter.build_report_envelope(&scan_args)?;
                            let report_bytes = serde_json::to_vec_pretty(&envelope)?;
                            let view_args = view::ViewArgs {
                                reports: vec![],
                                port: scan_args.view_report_port,
                                address: scan_args.view_report_address.clone(),
                                open_browser: true,
                                report_bytes: Some(report_bytes),
                            };
                            view::run(view_args).await?;
                        }

                        if keep_clones {
                            let _kept_path = temp_dir.keep(); // consumes TempDir; prevents auto-delete
                        } else if let Err(e) = temp_dir.close() {
                            eprintln!("Failed to close temporary directory: {}", e);
                        }

                        std::process::exit(exit_code);
                    }
                    ScanOperation::ListRepositories(list_command) => match list_command {
                        ListRepositoriesCommand::Github { api_url, specifiers } => {
                            github::list_repositories(
                                api_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.organization,
                                specifiers.all_organizations,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Gitlab { api_url, specifiers } => {
                            kingfisher::gitlab::list_repositories(
                                api_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.group,
                                specifiers.all_groups,
                                specifiers.include_subgroups,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Gitea { api_url, specifiers } => {
                            gitea::list_repositories(
                                api_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.organization,
                                specifiers.all_organizations,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Bitbucket { api_url, specifiers } => {
                            let auth_config = bitbucket::AuthConfig::from_env();
                            bitbucket::list_repositories(
                                api_url,
                                auth_config,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.workspace,
                                &specifiers.project,
                                specifiers.all_workspaces,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Azure { base_url, specifiers } => {
                            azure::list_repositories(
                                base_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.organization,
                                &specifiers.project,
                                specifiers.all_projects,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Huggingface { specifiers } => {
                            let repo_specifiers = huggingface::RepoSpecifiers {
                                user: specifiers.user.clone(),
                                organization: specifiers.organization.clone(),
                                model: specifiers.model.clone(),
                                dataset: specifiers.dataset.clone(),
                                space: specifiers.space.clone(),
                                exclude: specifiers.exclude.clone(),
                            };
                            let auth = huggingface::AuthConfig::from_env();
                            huggingface::list_repositories(
                                &repo_specifiers,
                                &auth,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                            )
                            .await?;
                        }
                    },
                },
                Command::Rules(ref rule_args) => match &rule_args.command {
                    RulesCommand::Check(check_args) => {
                        run_rules_check(&check_args)?;
                    }
                    RulesCommand::List(list_args) => {
                        run_rules_list(&list_args)?;
                    }
                },
                Command::View(_) => {
                    anyhow::bail!("View command should not reach this branch")
                }
                Command::AccessMap(_) => {
                    anyhow::bail!("AccessMap command should not reach this branch")
                }
                Command::Validate(_) => {
                    anyhow::bail!("Validate command should not reach this branch")
                }
                Command::Revoke(_) => {
                    anyhow::bail!("Revoke command should not reach this branch")
                }
                Command::SelfUpdate => {
                    anyhow::bail!("SelfUpdate command should not reach this branch")
                }
            }
            if let Some(message) = &update_status.message {
                info!("{}", message);
            }
            Ok(AsyncMainOutcome::Done)
        }
    }
}

/// Create a default ScanArgs instance for rule loading
fn create_default_scan_args() -> cli::commands::scan::ScanArgs {
    use cli::commands::scan::*;
    ScanArgs {
        num_jobs: 1,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: Vec::new(),
            git_clone_dir: None,
            keep_clones: false,
            repo_clone_limit: None,
            include_contributors: false,
            github_user: Vec::new(),
            github_organization: Vec::new(),
            github_exclude: Vec::new(),
            all_github_organizations: false,
            github_api_url: url::Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            // new GitLab defaults
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::All,
            gitlab_include_subgroups: false,

            huggingface_user: Vec::new(),
            huggingface_organization: Vec::new(),
            huggingface_model: Vec::new(),
            huggingface_dataset: Vec::new(),
            huggingface_space: Vec::new(),
            huggingface_exclude: Vec::new(),

            gitea_user: Vec::new(),
            gitea_organization: Vec::new(),
            gitea_exclude: Vec::new(),
            all_gitea_organizations: false,
            gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
            gitea_repo_type: GiteaRepoType::Source,

            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),

            azure_organization: Vec::new(),
            azure_project: Vec::new(),
            azure_exclude: Vec::new(),
            all_azure_projects: false,
            azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
            azure_repo_type: AzureRepoType::Source,

            jira_url: None,
            jql: None,
            jira_include_comments: false,
            jira_include_changelog: false,
            confluence_url: None,
            cql: None,
            max_results: 100,

            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            gcs_bucket: None,
            gcs_prefix: None,
            gcs_service_account: None,
            // Slack query
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            // Teams query
            teams_query: None,
            teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),

            postman_workspaces: Vec::new(),
            postman_collections: Vec::new(),
            postman_environments: Vec::new(),
            postman_all: false,
            postman_include_mocks_monitors: false,
            postman_api_url: Url::parse("https://api.getpostman.com/").unwrap(),
            // Docker image scanning
            docker_image: Vec::new(),

            // git clone / history options
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            commit_metadata: true,
            repo_artifacts: false,
            scan_nested_repos: true,
            since_commit: None,
            branch: None,
            branch_root: false,
            branch_root_commit: None,
            staged: false,
        },
        extra_ignore_comments: Vec::new(),
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            no_extract_archives: true,
            extraction_depth: 2,
            exclude: Vec::new(), // Exclude patterns
            no_binary: true,
        },
        confidence: ConfidenceLevel::Medium,
        no_validate: true,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800,
        no_dedup: false,
        view_report: false,
        baseline_file: None,
        manage_baseline: false,
        skip_regex: Vec::new(),
        skip_word: Vec::new(),
        skip_aws_account: Vec::new(),
        skip_aws_account_file: None,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_base64: false,
        turbo: false,
        no_inline_ignore: false,
        no_ignore_if_contains: false,
        view_report_port: view::DEFAULT_PORT,
        view_report_address: view::DEFAULT_ADDRESS.to_string(),
        validation_timeout: 10,
        validation_retries: 1,
        validation_rps: None,
        validation_rps_rule: Vec::new(),
        full_validation_response: false,
        max_validation_response_length: 2048,
        alert_webhook: Vec::new(),
        alert_format: None,
        alert_on: kingfisher::alerts::AlertOn::Findings,
        alert_min_confidence: kingfisher::cli::commands::scan::ConfidenceLevel::Medium,
        alert_include_secret: false,
        alert_report_url: None,
        alert_detail: kingfisher::alerts::AlertDetail::Auto,
        config_webhook_overrides: Vec::new(),
    }
}
/// Run the rules check command
pub fn run_rules_check(args: &RulesCheckArgs) -> Result<()> {
    let mut num_errors = 0;
    let mut num_warnings = 0;
    // Load and check rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args())?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?;

    // Check each rule
    for (rule_index, rule) in rules_db.rules().iter().enumerate() {
        let rule_syntax = rule.syntax();
        // Basic rule validation checks
        if rule.name().len() < 3 {
            warn!("Rule '{}' has a very short name", rule.name());
            num_warnings += 1;
        }
        if rule.syntax().pattern.len() < 5 {
            warn!("Rule '{}' has a very short pattern", rule.name());
            num_warnings += 1;
        }
        if rule.syntax().examples.is_empty() {
            warn!("Rule '{}' has no examples", rule.name());
            num_warnings += 1;
            continue;
        }
        // Check regex compilation
        if let Err(e) = rule.syntax().as_regex() {
            error!("Rule '{}' has invalid regex: {}", rule.name(), e);
            num_errors += 1;
            continue;
        }
        // Test each example against regex and pattern_requirements
        for (example_index, example) in rule_syntax.examples.iter().enumerate() {
            // Get the regex using the public method
            let re =
                rules_db.get_regex_by_rule_id(rule.id()).expect("Failed to get regex for rule");

            // Check if the example matches the pattern
            let example_bytes = example.as_bytes();
            let regex_matched = re.is_match(example_bytes);

            if !regex_matched {
                println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                println!("  Processing example {}", example_index + 1);
                println!("    [!] Pattern mismatch detected for example: {}", example);
                println!("    Regex match: {}", regex_matched);
                num_errors += 1;
                continue;
            }

            // If the rule has pattern_requirements, validate them against the match
            if let Some(pattern_reqs) = rule.pattern_requirements() {
                // Get the captures from the match
                if let Some(captures) = re.captures(example_bytes) {
                    // Get the full match (group 0)
                    let full_capture = captures.get(0).expect("Group 0 should always exist");
                    let full_bytes = full_capture.as_bytes();

                    // Determine which bytes to validate (same logic as in matcher.rs)
                    // Find the primary capture group for validation
                    let matching_input_for_validation = 'block: {
                        // 1. Look for a named capture "secret" (case-insensitive).
                        if let Some(secret_cap) =
                            captures.name("secret").or_else(|| captures.name("SECRET"))
                        {
                            break 'block secret_cap;
                        }

                        // 2. Look for any other named capture.
                        if let Some(named_cap) = (1..captures.len()).find_map(|i| {
                            let name_opt = re.capture_names().nth(i).and_then(|n| n);
                            name_opt.and_then(|_| captures.get(i))
                        }) {
                            break 'block named_cap;
                        }

                        // 3. Fall back to first positional capture (group 1) if it exists.
                        if let Some(pos_cap) = captures.get(1) {
                            break 'block pos_cap;
                        }

                        // 4. Finally, fall back to the full match (group 0).
                        break 'block full_capture;
                    };

                    let validation_bytes = matching_input_for_validation.as_bytes();

                    // Create context for pattern requirements validation
                    use kingfisher_rules::PatternRequirementContext;
                    let context = PatternRequirementContext {
                        regex: re,
                        captures: &captures,
                        full_match: full_bytes,
                    };

                    // Validate pattern requirements (without respect_ignore_if_contains for examples)
                    use kingfisher_rules::PatternValidationResult;
                    match pattern_reqs.validate(validation_bytes, Some(context), false) {
                        PatternValidationResult::Passed => {
                            // All requirements met
                        }
                        PatternValidationResult::Failed => {
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!(
                                "    [!] Pattern requirements not met for example: {}",
                                example
                            );
                            println!(
                                "    The match does not satisfy the character requirements (min_digits, min_uppercase, etc.)"
                            );
                            num_errors += 1;
                        }
                        PatternValidationResult::FailedChecksum { actual_len, expected_len } => {
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!("    [!] Checksum validation failed for example: {}", example);
                            println!(
                                "    Actual checksum length: {}, Expected checksum length: {}",
                                actual_len, expected_len
                            );
                            num_errors += 1;
                        }
                        PatternValidationResult::IgnoredBySubstring { matched_term } => {
                            // For examples, we don't want to treat this as an error in check mode
                            // since ignore_if_contains is meant for runtime filtering
                            // But we can warn about it
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!(
                                "    [!] Example would be ignored due to containing term: {}",
                                matched_term
                            );
                            println!("    Example: {}", example);
                            num_warnings += 1;
                        }
                    }
                }
            }
        }
    }
    // Print summary
    if num_errors > 0 || num_warnings > 0 {
        println!("\nCheck Summary:");
        println!("  Errors: {}", num_errors);
        println!("  Warnings: {}", num_warnings);
        println!("\nError types include:");
        println!("  - Invalid regex patterns");
        println!("  - Examples that don't match their patterns");
        println!("\nWarning types include:");
        println!("  - Rules with very short names");
        println!("  - Rules with very short patterns");
        println!("  - Rules without examples");
    } else {
        println!("\nAll rules passed validation successfully!");
    }
    // Exit with error if there are errors or if warnings are treated as errors
    if num_errors > 0 || (args.warnings_as_errors && num_warnings > 0) {
        std::process::exit(1);
    }
    Ok(())
}
/// Run the rules list command
pub fn run_rules_list(args: &RulesListArgs) -> Result<()> {
    // Load rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args())?;
    let resolved = loaded.resolve_enabled_rules()?;
    let mut writer = args.output_args.get_writer()?;
    match args.output_args.format {
        RulesListOutputFormat::Pretty => {
            // Determine terminal width if possible, otherwise use default
            let term_width = usize::from(Term::stdout().size().1);
            // First pass: calculate column widths
            let max_name_width = resolved.iter().map(|r| r.name().len()).max().unwrap_or(0).max(4); // "Rule" header
            let max_id_width = resolved.iter().map(|r| r.id().len()).max().unwrap_or(0).max(2); // "ID" header
            let max_conf_width = resolved
                .iter()
                .map(|r| format!("{:?}", r.confidence()).len())
                .max()
                .unwrap_or(0)
                .max(10); // "Confidence" header
            // Calculate pattern width based on terminal width
            let reserved_width = max_name_width + max_id_width + max_conf_width + 10;
            let pattern_width = term_width.saturating_sub(reserved_width);
            // Format pattern on a single line
            let format_pattern = |pattern: &str| {
                let single_line = pattern
                    .replace('\n', " ")
                    .replace('\r', " ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if single_line.len() > pattern_width {
                    format!("{}...", &single_line[..pattern_width.saturating_sub(3)])
                } else {
                    single_line
                }
            };
            // Print header
            writeln!(
                writer,
                "\n{:name_width$} │ {:id_width$} │ {:conf_width$} │ Pattern",
                "Rule",
                "ID",
                "Confidence",
                name_width = max_name_width,
                id_width = max_id_width,
                conf_width = max_conf_width
            )?;
            // Print separator
            writeln!(
                writer,
                "{0:─<name_width$} ┼ {0:─<id_width$} ┼ {0:─<conf_width$} ┼ {0:─<pattern_width$}",
                "",
                name_width = max_name_width,
                id_width = max_id_width,
                conf_width = max_conf_width,
                pattern_width = pattern_width
            )?;
            // Print each rule
            for rule in resolved {
                let formatted_pattern = format_pattern(&rule.syntax().pattern);
                writeln!(
                    writer,
                    "{:name_width$} │ {:id_width$} │ {:conf_width$} │ {}",
                    rule.name(),
                    rule.id(),
                    format!("{:?}", rule.confidence()),
                    formatted_pattern,
                    name_width = max_name_width,
                    id_width = max_id_width,
                    conf_width = max_conf_width
                )?;
            }
            writeln!(writer)?;
        }
        RulesListOutputFormat::Json => {
            // Create JSON format
            let rules_json: Vec<_> = resolved
                .iter()
                .map(|rule| {
                    json!({
                        "name": rule.name(),
                        "id": rule.id(),
                        "pattern": rule.syntax().pattern,
                        "confidence": rule.confidence(),
                        "examples": rule.syntax().examples,
                        "visible": rule.visible(),
                    })
                })
                .collect();
            serde_json::to_writer_pretty(&mut writer, &rules_json)?;
            writeln!(writer)?;
        }
    }
    Ok(())
}
