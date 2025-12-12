use avena_testbed::{Scenario, TestRunner};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "avena-testbed")]
#[command(about = "Avena overlay network test harness")]
struct Cli {
    /// Enable verbose output (shows tracing logs)
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a test scenario
    Run {
        /// Path to scenario TOML file
        scenario: PathBuf,

        /// Output path for metrics jsonl (use /tmp/... for non-root execution)
        #[arg(short, long, default_value = "/tmp/avena-metrics.jsonl")]
        output: PathBuf,

        /// Keep namespaces after test (for debugging)
        #[arg(long)]
        keep_namespaces: bool,

        /// Internal flag: already inside user namespace
        #[arg(long, hide = true)]
        in_namespace: bool,
    },

    /// Validate a scenario file syntax and semantics
    Validate {
        /// Path to scenario TOML file
        scenario: PathBuf,
    },

    /// List bundled example scenarios
    Examples,
}

fn is_in_user_namespace() -> bool {
    std::fs::read_to_string("/proc/self/uid_map")
        .map(|content| {
            // In a user namespace, uid_map has a mapping like "0 1000 1"
            // In root namespace, it's typically "0 0 4294967295"
            let first_line = content.lines().next().unwrap_or("");
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            // Check if this is a narrow mapping (user namespace) vs full range
            if parts.len() >= 3 {
                // If the range is small, we're in a user namespace
                parts[2].parse::<u64>().map(|range| range < 1000).unwrap_or(false)
            } else {
                false
            }
        })
        .unwrap_or(false)
}

fn reexec_in_namespace(scenario: &PathBuf, output: &PathBuf, keep_namespaces: bool, verbose: bool) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to get current exe path: {e}");
            return ExitCode::FAILURE;
        }
    };

    let scenario_abs = std::fs::canonicalize(scenario).unwrap_or_else(|_| scenario.clone());
    let output_abs = if output.is_absolute() {
        output.clone()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(output))
            .unwrap_or_else(|_| output.clone())
    };

    let mut cmd = std::process::Command::new("unshare");
    cmd.args(["--kill-child", "-rmn"]);
    cmd.arg(&exe);
    cmd.args(["run", "--in-namespace"]);
    cmd.arg(&scenario_abs);
    cmd.args(["-o"]);
    cmd.arg(&output_abs);
    if keep_namespaces {
        cmd.arg("--keep-namespaces");
    }
    if verbose {
        cmd.arg("--verbose");
    }

    for (key, value) in std::env::vars() {
        if key.starts_with("RUST_") {
            cmd.env(&key, &value);
        }
    }

    match cmd.status() {
        Ok(status) => {
            if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(status.code().unwrap_or(1) as u8)
            }
        }
        Err(e) => {
            eprintln!("Failed to execute unshare: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("avena=debug,avena_testbed=debug")),
            )
            .init();
    }

    match cli.command {
        Commands::Run {
            scenario,
            output,
            keep_namespaces,
            in_namespace,
        } => {
            // If not already in a user namespace and not root, re-exec inside one
            // Root doesn't need user namespace - it already has permissions
            let is_root = unsafe { libc::geteuid() } == 0;
            if !in_namespace && !is_in_user_namespace() && !is_root {
                return reexec_in_namespace(&scenario, &output, keep_namespaces, cli.verbose);
            }

            let runner = TestRunner::new().keep_namespaces(keep_namespaces);

            match runner.run_scenario(&scenario, &output).await {
                Ok(result) => {
                    println!();
                    if result.passed {
                        println!("✓ Scenario passed");
                    } else {
                        println!("✗ Scenario failed");
                    }
                    println!(
                        "  Assertions: {}/{} passed",
                        result.assertions_passed, result.assertions_run
                    );
                    println!("  Events executed: {}", result.events_executed);
                    println!("  Duration: {:.2}s", result.duration_secs);
                    println!("  Metrics written to: {}", output.display());

                    if result.passed {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("✗ Scenario execution failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Validate { scenario } => match Scenario::load(&scenario) {
            Ok(s) => {
                println!("✓ Scenario '{}' is valid", s.name);
                println!("  {} nodes, {} links", s.nodes.len(), s.links.len());
                println!("  {} events, {} assertions", s.events.len(), s.assertions.len());
                println!("  Duration: {}s", s.duration_secs);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("✗ Scenario validation failed: {e}");
                ExitCode::FAILURE
            }
        },
        Commands::Examples => {
            println!("Bundled example scenarios:");
            println!();
            println!("  two_node_basic.toml     - Two nodes with direct link");
            println!("  linear_three_hop.toml   - Three nodes in a line (A-B-C)");
            println!("  star_gateway.toml       - Star topology with central gateway");
            println!("  mobile_relay.toml       - DTN store-and-forward via mobile relay");
            ExitCode::SUCCESS
        }
    }
}
