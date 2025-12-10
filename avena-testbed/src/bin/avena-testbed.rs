use avena_testbed::{Scenario, TestRunner};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "avena-testbed")]
#[command(about = "Avena overlay network test harness")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a test scenario
    Run {
        /// Path to scenario TOML file
        scenario: PathBuf,

        /// Output path for metrics jsonl
        #[arg(short, long, default_value = "metrics.jsonl")]
        output: PathBuf,

        /// Keep namespaces after test (for debugging)
        #[arg(long)]
        keep_namespaces: bool,
    },

    /// Validate a scenario file syntax and semantics
    Validate {
        /// Path to scenario TOML file
        scenario: PathBuf,
    },

    /// List bundled example scenarios
    Examples,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            scenario,
            output,
            keep_namespaces,
        } => {
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
