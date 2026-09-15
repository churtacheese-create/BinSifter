//! BinSifter Ingot - `ingot` binary.
//!
//! Starts the local HTTP service, serves the embedded browser UI, and (by
//! default) opens it in the user's browser. Loopback only, no auth.

mod api;
mod assets;

use std::sync::Arc;

use anyhow::Context;
use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tokio::sync::{broadcast, Notify};
use tower_http::trace::TraceLayer;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

use api::AppState;

#[derive(Parser, Debug)]
#[command(
    name = "ingot",
    version,
    about = "BinSifter Ingot - local binary-triage service + web UI"
)]
struct Args {
    /// TCP port to listen on (loopback only).
    #[arg(long, env = "INGOT_PORT", default_value_t = 8477)]
    port: u16,

    /// Do not open the UI in a browser on startup.
    #[arg(long)]
    no_open: bool,
}

/// A `tracing` writer that fans every formatted log line out to the
/// `/api/logs/events` SSE stream in addition to stderr.
#[derive(Clone)]
struct BroadcastMakeWriter(broadcast::Sender<String>);

struct BroadcastWriter(broadcast::Sender<String>);

impl std::io::Write for BroadcastWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            let line = s.trim_end_matches(['\n', '\r']);
            if !line.is_empty() {
                let _ = self.0.send(line.to_string());
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for BroadcastMakeWriter {
    type Writer = BroadcastWriter;
    fn make_writer(&'a self) -> Self::Writer {
        BroadcastWriter(self.0.clone())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let (log_tx, _) = broadcast::channel::<String>(2048);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,ingot_core=info,ingot_server=info")
    });
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(BroadcastMakeWriter(log_tx.clone())),
        )
        .init();

    let config = ingot_core::build_default_config();
    tracing::info!(
        "{} {} - data root {}",
        ingot_core::PRODUCT_NAME,
        ingot_core::VERSION,
        ingot_core::config::data_root().display()
    );

    let shutdown = Arc::new(Notify::new());
    let state = AppState::new(config, log_tx, shutdown.clone());

    let app = Router::new()
        .route("/api/health", get(api::health))
        .route("/api/config", get(api::get_config).put(api::put_config))
        .route("/api/browse", get(api::browse))
        .route("/api/tools", get(api::get_tools))
        .route("/api/tools/install/{tool}", post(api::install_tool))
        .route("/api/launch-tools", get(api::get_launch_tools))
        .route(
            "/api/launch-tools/install/{id}",
            post(api::install_launch_tool),
        )
        .route("/api/launch", post(api::launch))
        .route("/api/ghidra", post(api::launch_ghidra))
        .route("/api/ai-export", post(api::ai_export))
        .route("/api/av", get(api::get_av))
        .route("/api/av/exclude", post(api::av_exclude))
        .route("/api/update/check", get(api::check_update))
        .route("/api/update/install", post(api::install_update))
        .route("/api/scan", post(api::start_scan))
        .route("/api/scan/current", get(api::scan_status))
        .route("/api/scan/current/events", get(api::scan_events))
        .route("/api/scan/current/report/{kind}", get(api::scan_report))
        .route("/api/disposition", axum::routing::put(api::set_disposition))
        .route("/api/reports", get(api::list_reports))
        .route("/api/logs/events", get(api::log_events))
        .route("/", get(assets::index))
        .route("/{*path}", get(assets::asset))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", args.port))
        .await
        .with_context(|| format!("could not bind 127.0.0.1:{}", args.port))?;
    let addr = listener.local_addr()?;
    let url = format!("http://{addr}");
    println!(
        "{} {} -> {url}",
        ingot_core::PRODUCT_NAME,
        ingot_core::VERSION
    );
    println!("Press Ctrl+C to stop.");

    if !args.no_open {
        if let Err(e) = webbrowser::open(&url) {
            tracing::warn!("Could not open a browser automatically ({e}); open {url} yourself.");
        }
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await?;

    Ok(())
}

/// Waits for either Ctrl+C or a proactive shutdown request (the self-update
/// flow, which has already spawned the new binary and just needs this
/// instance to release the port).
async fn shutdown_signal(shutdown: Arc<Notify>) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = shutdown.notified() => {}
    }
    tracing::info!("Shutting down.");
}
