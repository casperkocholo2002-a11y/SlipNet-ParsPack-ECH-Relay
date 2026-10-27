use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::Serialize;
use tokio::{
    net::{lookup_host, TcpStream},
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{
    client_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message as TungsteniteMessage},
    WebSocketStream,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const SERVICE: &str = "slipnet-rust-relay-r2";
const VERSION: &str = "1.0.0";
const PUBLIC_RELAY_PATH: &str = "/pd/62ad74fca82c63c4643acd61ce16d0348fc7c2e7c076b6e5";
const WORKER_HOST: &str = "slipnet-route2-b-20261024t182334z.edgebackup-b758f896b4.workers.dev";
const WORKER_PATH: &str = "/w/986b32e37335922c2faab7ce2153a8c9f9c6aff9de334f28";
const WORKER_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct AppState;

#[derive(Serialize)]
struct Health {
    ok: bool,
    ready: bool,
    service: &'static str,
    version: &'static str,
    ech: bool,
    upstream_tls: &'static str,
    route_mode: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,slipnet_rust_relay_r2=info")),
        )
        .compact()
        .init();

    let app = Router::new()
        .route("/health", get(health))
        .route(PUBLIC_RELAY_PATH, get(relay_upgrade))
        .fallback(not_found)
        .with_state(AppState);

    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8080);

    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;

    info!(
        service = SERVICE,
        version = VERSION,
        port,
        ech = false,
        upstream = WORKER_HOST,
        "SlipNet Route 2 Rust relay started"
    );

    axum::serve(listener, app)
        .await
        .context("HTTP server failed")?;
    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health {
        ok: true,
        ready: true,
        service: SERVICE,
        version: VERSION,
        ech: false,
        upstream_tls: "strict",
        route_mode: "worker-b-direct-with-fixed-origin-fallback",
    })
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "not_found")
}

async fn relay_upgrade(ws: WebSocketUpgrade, State(_): State<AppState>) -> Response {
    ws.max_message_size(MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| async move {
            if let Err(err) = relay_session(socket).await {
                warn!(error = %err, "route2 relay session ended with error");
            }
        })
}

async fn relay_session(client: WebSocket) -> Result<()> {
    let upstream = open_upstream().await?;

    info!(
        upstream = WORKER_HOST,
        ech = false,
        "upstream standard TLS WebSocket established"
    );

    bridge(client, upstream).await
}

async fn open_upstream() -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let tcp = connect_worker().await?;
    tcp.set_nodelay(true).ok();

    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to enable default TLS protocol versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name =
        ServerName::try_from(WORKER_HOST.to_owned()).context("invalid Worker B hostname")?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls = timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")?;

    let url = format!("wss://{}:{}{}", WORKER_HOST, WORKER_PORT, WORKER_PATH);
    let mut request = url
        .into_client_request()
        .context("failed to build Worker B WebSocket request")?;
    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_static("SlipNet-Rust-Relay-R2/1.0"),
    );

    let (ws, response) = timeout(CONNECT_TIMEOUT, client_async(request, tls))
        .await
        .context("Worker B WebSocket handshake timed out")?
        .context("Worker B WebSocket handshake failed")?;

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        bail!("unexpected Worker B WebSocket status {}", response.status());
    }

    Ok(ws)
}

async fn connect_worker() -> Result<TcpStream> {
    let mut errors = Vec::new();
    let addrs = timeout(CONNECT_TIMEOUT, lookup_host((WORKER_HOST, WORKER_PORT)))
        .await
        .context("Worker B DNS lookup timed out")?
        .context("Worker B DNS lookup failed")?;

    for addr in addrs {
        match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => errors.push(format!("{addr}: {err}")),
            Err(_) => errors.push(format!("{addr}: connect timed out")),
        }
    }

    bail!(
        "all Worker B connection attempts failed: {}",
        errors.join(" | ")
    )
}

async fn bridge(client: WebSocket, upstream: WebSocketStream<TlsStream<TcpStream>>) -> Result<()> {
    let (mut client_tx, mut client_rx) = client.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();

    let client_to_upstream = async {
        while let Some(item) = client_rx.next().await {
            let message = item.context("incoming WebSocket read failed")?;
            if let Some(message) = axum_to_tungstenite(message) {
                let is_close = matches!(message, TungsteniteMessage::Close(_));
                upstream_tx
                    .send(message)
                    .await
                    .context("Worker B WebSocket write failed")?;
                if is_close {
                    break;
                }
            }
        }
        Result::<()>::Ok(())
    };

    let upstream_to_client = async {
        while let Some(item) = upstream_rx.next().await {
            let message = item.context("Worker B WebSocket read failed")?;
            if let Some(message) = tungstenite_to_axum(message) {
                let is_close = matches!(message, AxumMessage::Close(_));
                client_tx
                    .send(message)
                    .await
                    .context("incoming WebSocket write failed")?;
                if is_close {
                    break;
                }
            }
        }
        Result::<()>::Ok(())
    };

    tokio::select! {
        result = client_to_upstream => result?,
        result = upstream_to_client => result?,
    }

    Ok(())
}

fn axum_to_tungstenite(message: AxumMessage) -> Option<TungsteniteMessage> {
    match message {
        AxumMessage::Text(text) => Some(TungsteniteMessage::Text(text.to_string())),
        AxumMessage::Binary(data) => Some(TungsteniteMessage::Binary(data)),
        AxumMessage::Ping(data) => Some(TungsteniteMessage::Ping(data)),
        AxumMessage::Pong(data) => Some(TungsteniteMessage::Pong(data)),
        AxumMessage::Close(_) => Some(TungsteniteMessage::Close(None)),
    }
}

fn tungstenite_to_axum(message: TungsteniteMessage) -> Option<AxumMessage> {
    match message {
        TungsteniteMessage::Text(text) => Some(AxumMessage::Text(text.to_string())),
        TungsteniteMessage::Binary(data) => Some(AxumMessage::Binary(data)),
        TungsteniteMessage::Ping(data) => Some(AxumMessage::Ping(data)),
        TungsteniteMessage::Pong(data) => Some(AxumMessage::Pong(data)),
        TungsteniteMessage::Close(_) => Some(AxumMessage::Close(None)),
        TungsteniteMessage::Frame(_) => None,
    }
}
