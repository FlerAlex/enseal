#[cfg(feature = "server")]
use anyhow::Result;

#[cfg(feature = "server")]
use clap::Args;

#[cfg(feature = "server")]
use crate::server;
#[cfg(feature = "server")]
use crate::ui::display;

#[cfg(feature = "server")]
#[derive(Args)]
pub struct ServeArgs {
    /// Listen port
    #[arg(long, default_value = "4443")]
    pub port: u16,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,

    /// Max concurrent channels
    #[arg(long, default_value = "100")]
    pub max_mailboxes: usize,

    /// How long idle channels survive in seconds
    #[arg(long, default_value = "300")]
    pub channel_ttl: u64,

    /// Max WebSocket message size in bytes
    #[arg(long, default_value = "1048576")]
    pub max_payload: usize,

    /// Max new connections per minute per IP
    #[arg(long, default_value = "10")]
    pub rate_limit: usize,

    /// Print server health check and exit
    #[arg(long)]
    pub health: bool,
}

#[cfg(feature = "server")]
pub async fn run(args: ServeArgs) -> Result<()> {
    if args.health {
        return check_health(&args).await;
    }

    let addr = format!("{}:{}", args.bind, args.port);

    let config = server::ServerConfig {
        port: args.port,
        bind: args.bind.clone(),
        max_channels: args.max_mailboxes,
        channel_ttl_secs: args.channel_ttl,
        max_payload_bytes: args.max_payload,
        rate_limit_per_min: args.rate_limit,
    };

    let app = server::build_router(config);

    display::ok(&format!("enseal relay listening on {}", addr));
    eprintln!("  max channels:  {}", args.max_mailboxes);
    eprintln!("  channel TTL:   {}s", args.channel_ttl);
    eprintln!("  max payload:   {} bytes", args.max_payload);
    eprintln!("  rate limit:    {}/min per IP", args.rate_limit);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(feature = "server")]
async fn check_health(args: &ServeArgs) -> Result<()> {
    let _url = format!("http://{}:{}/health", args.bind, args.port);
    // Use a simple TCP check since we don't want to add reqwest as a dep
    match tokio::net::TcpStream::connect(format!("{}:{}", args.bind, args.port)).await {
        Ok(_) => {
            display::ok(&format!(
                "relay is reachable at {}:{}",
                args.bind, args.port
            ));
            Ok(())
        }
        Err(e) => {
            display::error(&format!(
                "cannot connect to {}:{}: {}",
                args.bind, args.port, e
            ));
            std::process::exit(1);
        }
    }
}
