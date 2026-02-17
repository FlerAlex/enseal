use anyhow::Result;
use clap::Parser;

mod cli;
mod config;
mod crypto;
mod env;
mod keys;
#[cfg(feature = "server")]
mod server;
mod transfer;
mod ui;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

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
        cli::Command::Inject(args) => cli::inject::run(args).await,
        cli::Command::Check(args) => cli::check::run(args),
        cli::Command::Diff(args) => cli::diff::run(args),
        cli::Command::Redact(args) => cli::redact::run(args),
        cli::Command::Validate(args) => cli::validate::run(args),
        cli::Command::Template(args) => cli::template::run(args),
        cli::Command::Encrypt(args) => cli::encrypt::run(args),
        cli::Command::Decrypt(args) => cli::decrypt::run(args),
        cli::Command::Keys(args) => cli::keys::run(args),
        #[cfg(feature = "server")]
        cli::Command::Serve(args) => cli::serve::run(args).await,
        cli::Command::Completions { shell } => {
            let mut cmd = <cli::Cli as clap::CommandFactory>::command();
            clap_complete::generate(shell, &mut cmd, "enseal", &mut std::io::stdout());
            Ok(())
        }
    }
}
