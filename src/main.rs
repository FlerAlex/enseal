use anyhow::Result;
use clap::Parser;

mod cli;
mod config;
mod crypto;
mod env;
mod keys;
mod transfer;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    let args = cli::Cli::parse();

    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else if args.quiet {
        tracing::Level::ERROR
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .without_time()
        .init();

    match args.command {
        cli::Command::Share(args) => cli::share::run(args).await,
        cli::Command::Receive(args) => cli::receive::run(args).await,
        cli::Command::Check(args) => cli::check::run(args),
        cli::Command::Diff(args) => cli::diff::run(args),
        cli::Command::Redact(args) => cli::redact::run(args),
        cli::Command::Keys(args) => cli::keys::run(args),
    }
}
