use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
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
use futures_util::{stream::FuturesUnordered, SinkExt, StreamExt};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{
        rdata::svcb::{SvcParamKey, SvcParamValue},
        RData, RecordType,
    },
    TokioAsyncResolver,
};
use rustls::{
    client::{EchConfig, EchMode, EchStatus},
    crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    pki_types::{EchConfigListBytes, ServerName},
    ClientConfig, RootCertStore,
};
use serde::Serialize;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::{
    client_async,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message as TungsteniteMessage},
    WebSocketStream,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const SERVICE: &str = "slipnet-ech-relay";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PUBLIC_RELAY_PATH: &str = "/p/92943149c56048dda2b2123e591f9e7de9d79ae7d0d086db";
const DEFAULT_WORKER_HOST: &str =
    "slipnet-route1-a-20261024t182334z.edgecache-628bbe41dc.workers.dev";
const DEFAULT_WORKER_PATH: &str = "/o/2eb8ae8480741e9c9fc01cb5fa2b4550d2650e48c6e2e437";

#[derive(Clone, Debug)]
struct Config {
    port: u16,
    public_relay_path: String,
    worker_host: String,
    worker_path: String,
    worker_port: u16,
    connect_timeout: Duration,
    max_message_size: usize,
}

impl Config {
    fn from_env() -> Result<Self> {
        let port = env_u16("PORT", 8080)?;
        let public_relay_path =
            env::var("PUBLIC_RELAY_PATH").unwrap_or_else(|_| DEFAULT_PUBLIC_RELAY_PATH.to_owned());
        validate_path("PUBLIC_RELAY_PATH", &public_relay_path)?;
        let worker_host = env::var("WORKER_HOST")
            .unwrap_or_else(|_| DEFAULT_WORKER_HOST.to_owned())
            .trim()
            .to_owned();
        validate_host(&worker_host)?;
        let worker_path =
            env::var("WORKER_PATH").unwrap_or_else(|_| DEFAULT_WORKER_PATH.to_owned());
        validate_path("WORKER_PATH", &worker_path)?;
        let worker_port = env_u16("WORKER_PORT", 443)?;
        let connect_timeout = Duration::from_millis(env_u64("CONNECT_TIMEOUT_MS", 6000)?);
        let max_message_size = env_usize("MAX_MESSAGE_BYTES", 64 * 1024 * 1024)?;

        let ech_mode = env::var("ECH_MODE").unwrap_or_else(|_| "hard".to_owned());
        if ech_mode != "hard" {
            bail!("ECH_MODE must be exactly 'hard'; plaintext-SNI fallback is intentionally unsupported");
        }

        if public_relay_path == "/health" {
            bail!("PUBLIC_RELAY_PATH must not be /health");
        }

        Ok(Self {
            port,
            public_relay_path,
            worker_host,
            worker_path,
            worker_port,
            connect_timeout,
            max_message_size,
        })
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    resolvers: Arc<Vec<TokioAsyncResolver>>,
}

#[derive(Serialize)]
struct Health {
    ok: bool,
    service: &'static str,
    version: &'static str,
    ech_mode: &'static str,
    dns: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,slipnet_ech_relay=info")),
        )
        .compact()
        .init();

    let config = Arc::new(Config::from_env()?);

    let resolvers = vec![
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), ResolverOpts::default()),
        TokioAsyncResolver::tokio(ResolverConfig::google_https(), ResolverOpts::default()),
        TokioAsyncResolver::tokio(ResolverConfig::quad9_https(), ResolverOpts::default()),
    ];

    let state = AppState {
        config: config.clone(),
        resolvers: Arc::new(resolvers),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route(&config.public_relay_path, get(relay_upgrade))
        .fallback(not_found)
        .with_state(state);

    let bind = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;

    info!(
        service = SERVICE,
        version = VERSION,
        port = config.port,
        relay_path_configured = true,
        ech_mode = "hard",
        "SlipNet ECH relay started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health {
        ok: true,
        service: SERVICE,
        version: VERSION,
        ech_mode: "hard",
        dns: "encrypted-doh-failover",
    })
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "not_found")
}

async fn relay_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    let max_message_size = state.config.max_message_size;
    ws.max_message_size(max_message_size)
        .on_upgrade(move |socket| async move {
            if let Err(err) = relay_session(socket, state).await {
                warn!(error = %err, "relay session ended with error");
            }
        })
}

async fn relay_session(client: WebSocket, state: AppState) -> Result<()> {
    let upstream = open_upstream(&state).await?;

    info!(
        upstream = %state.config.worker_host,
        ech = "accepted",
        "upstream ECH WebSocket established"
    );

    bridge(client, upstream).await
}

async fn open_upstream(state: &AppState) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let mut attempts = FuturesUnordered::new();

    for resolver in state.resolvers.iter() {
        let cfg = state.config.clone();
        attempts.push(async move { open_upstream_with_resolver(resolver, &cfg).await });
    }

    let mut errors = Vec::new();

    while let Some(result) = attempts.next().await {
        match result {
            Ok(ws) => return Ok(ws),
            Err(err) => errors.push(err.to_string()),
        }
    }

    bail!(
        "all encrypted DNS upstream attempts failed: {}",
        errors.join(" | ")
    )
}

async fn open_upstream_with_resolver(
    resolver: &TokioAsyncResolver,
    cfg: &Config,
) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let ech_lists = timeout(
        cfg.connect_timeout,
        lookup_ech_configs(resolver, &cfg.worker_host, cfg.worker_port),
    )
    .await
    .context("ECH DNS lookup timed out")??;

    let ech_config = ech_lists
        .into_iter()
        .find_map(|list| EchConfig::new(list, ALL_SUPPORTED_SUITES).ok())
        .ok_or_else(|| anyhow!("no compatible ECHConfigList returned by DNS-over-HTTPS"))?;

    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::from(ech_config))
        .context("failed to enable ECH")?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let tcp = connect_via_doh(
        resolver,
        &cfg.worker_host,
        cfg.worker_port,
        cfg.connect_timeout,
    )
    .await?;

    tcp.set_nodelay(true).ok();

    let server_name = ServerName::try_from(cfg.worker_host.clone())
        .context("WORKER_HOST is not a valid DNS name")?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls = timeout(cfg.connect_timeout, connector.connect(server_name, tcp))
        .await
        .context("ECH TLS handshake timed out")?
        .context("ECH TLS handshake failed")?;

    let ech_status = tls.get_ref().1.ech_status();
    if ech_status != EchStatus::Accepted {
        bail!("ECH hard-fail: server did not accept ECH (status={ech_status:?})");
    }

    let url = format!(
        "wss://{}:{}{}",
        cfg.worker_host, cfg.worker_port, cfg.worker_path
    );
    let mut request = url
        .into_client_request()
        .context("failed to build upstream WebSocket request")?;

    request.headers_mut().insert(
        "User-Agent",
        HeaderValue::from_static("SlipNet-ECH-Relay/1.0"),
    );

    let (ws, response) = timeout(cfg.connect_timeout, client_async(request, tls))
        .await
        .context("upstream WebSocket handshake timed out")?
        .context("upstream WebSocket handshake failed")?;

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        bail!("unexpected upstream WebSocket status {}", response.status());
    }

    Ok(ws)
}

async fn connect_via_doh(
    resolver: &TokioAsyncResolver,
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let lookup = timeout(connect_timeout, resolver.lookup_ip(host))
        .await
        .context("DoH address lookup timed out")?
        .context("DoH address lookup failed")?;

    let mut last_error = None;

    for ip in lookup.iter() {
        let addr = SocketAddr::new(ip, port);
        match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => last_error = Some(anyhow!("{addr}: {err}")),
            Err(_) => last_error = Some(anyhow!("{addr}: connect timed out")),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow!("DoH returned no usable IP address")))
}

async fn lookup_ech_configs(
    resolver: &TokioAsyncResolver,
    domain: &str,
    port: u16,
) -> Result<Vec<EchConfigListBytes<'static>>> {
    let qname = if port == 443 {
        domain.to_owned()
    } else {
        format!("_{port}._https.{domain}")
    };

    let lookup = resolver
        .lookup(qname, RecordType::HTTPS)
        .await
        .context("HTTPS DNS record lookup failed")?;

    let mut ech_lists = Vec::new();

    for answer in lookup.iter() {
        let RData::HTTPS(svcb) = answer else {
            continue;
        };

        if let Some((_, SvcParamValue::EchConfig(value))) = svcb
            .svc_params()
            .iter()
            .find(|(key, _)| *key == SvcParamKey::EchConfig)
        {
            // Hickory 0.24 strips the ECHConfigList's two-byte vector length
            // while decoding the SVCB parameter. rustls expects the complete
            // TLS vector encoding, so restore that prefix before parsing.
            let payload = &value.0;
            let payload_len =
                u16::try_from(payload.len()).context("ECHConfigList exceeds u16 length")?;
            let mut wire = Vec::with_capacity(payload.len() + 2);
            wire.extend_from_slice(&payload_len.to_be_bytes());
            wire.extend_from_slice(payload);
            ech_lists.push(EchConfigListBytes::from(wire));
        }
    }

    Ok(ech_lists)
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
                    .context("upstream WebSocket write failed")?;
                if is_close {
                    break;
                }
            }
        }
        Result::<()>::Ok(())
    };

    let upstream_to_client = async {
        while let Some(item) = upstream_rx.next().await {
            let message = item.context("upstream WebSocket read failed")?;
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

fn validate_path(name: &str, value: &str) -> Result<()> {
    if !value.starts_with('/') || value.starts_with("//") || value.contains("..") {
        bail!("{name} must be an absolute single-slash path without '..'");
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    if host.is_empty()
        || host.contains("://")
        || host.contains('/')
        || host.contains(char::is_whitespace)
    {
        bail!("WORKER_HOST must be a bare DNS hostname");
    }
    Ok(())
}

fn env_u16(name: &str, default: u16) -> Result<u16> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be a valid u16")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("failed reading {name}")),
    }
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be a valid u64")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("failed reading {name}")),
    }
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be a valid usize")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("failed reading {name}")),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
