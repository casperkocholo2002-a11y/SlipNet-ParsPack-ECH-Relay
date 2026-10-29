use std::{
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

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
use tokio::{
    net::{lookup_host, TcpStream},
    sync::RwLock,
    time::{sleep, timeout},
};
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
const LEGACY_PUBLIC_RELAY_PATH: &str = "/pf/d9b9b6e3aee49cb4b71687404a911c20626846fc8ae14f01";
const DEFAULT_WORKER_HOST: &str =
    "slipnet-route3-c-20261024t182334z.edgebackup-77bd94daf93c.workers.dev";
const DEFAULT_WORKER_PATH: &str = "/f/dcd6903ab84475e65a296be5aeb7a895ac62cb0ca9ec3b9e";

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

        // ECH is preferred, but availability on the upstream CDN can change.
        // If ECH is absent or rejected, the relay falls back to normal TLS.
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
struct Bootstrap {
    ech_lists: Vec<EchConfigListBytes<'static>>,
    ips: Vec<IpAddr>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    bootstrap: Arc<RwLock<Option<Bootstrap>>>,
}

#[derive(Serialize)]
struct Health {
    ok: bool,
    ready: bool,
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

    let resolvers = Arc::new(vec![
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), ResolverOpts::default()),
        TokioAsyncResolver::tokio(ResolverConfig::google_https(), ResolverOpts::default()),
        TokioAsyncResolver::tokio(ResolverConfig::quad9_https(), ResolverOpts::default()),
    ]);
    let initial_bootstrap = match resolve_system_bootstrap(&config).await {
        Ok(bootstrap) => {
            info!(
                upstream = %config.worker_host,
                "system DNS bootstrap ready; ECH discovery will continue in background"
            );
            Some(bootstrap)
        }
        Err(err) => {
            warn!(
                error = %err,
                upstream = %config.worker_host,
                "system DNS bootstrap failed; waiting for encrypted DNS bootstrap"
            );
            None
        }
    };
    let bootstrap = Arc::new(RwLock::new(initial_bootstrap));

    {
        let resolvers = resolvers.clone();
        let config = config.clone();
        let bootstrap = bootstrap.clone();
        tokio::spawn(async move {
            loop {
                let had_cache = bootstrap.read().await.is_some();
                let delay = match resolve_bootstrap(&resolvers, &config).await {
                    Ok(next) => {
                        *bootstrap.write().await = Some(next);
                        info!("encrypted DNS bootstrap cache refreshed");
                        Duration::from_secs(120)
                    }
                    Err(err) => {
                        warn!(error = %err, "encrypted DNS bootstrap refresh failed");
                        if had_cache {
                            Duration::from_secs(15)
                        } else {
                            Duration::from_secs(5)
                        }
                    }
                };
                sleep(delay).await;
            }
        });
    }

    let state = AppState {
        config: config.clone(),
        bootstrap,
    };

    let mut app = Router::new()
        .route("/health", get(health))
        .route(&config.public_relay_path, get(relay_upgrade));

    if config.public_relay_path != LEGACY_PUBLIC_RELAY_PATH {
        app = app.route(LEGACY_PUBLIC_RELAY_PATH, get(relay_upgrade));
    }

    let app = app.fallback(not_found).with_state(state);

    let bind = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind {bind}"))?;

    info!(
        service = SERVICE,
        version = VERSION,
        port = config.port,
        relay_path_configured = true,
        ech_mode = "optional",
        "SlipNet ECH relay started"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;

    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        ok: true,
        ready: state.bootstrap.read().await.is_some(),
        service: SERVICE,
        version: VERSION,
        ech_mode: "optional",
        dns: "system-ready-doh-upgrade",
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
        "upstream WebSocket established"
    );

    bridge(client, upstream).await
}

async fn open_upstream(state: &AppState) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let cfg = &state.config;
    let bootstrap = timeout(Duration::from_secs(20), async {
        loop {
            if let Some(bootstrap) = state.bootstrap.read().await.clone() {
                break bootstrap;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("encrypted DNS bootstrap cache did not become ready")?;

    if let Some(ech_config) = bootstrap
        .ech_lists
        .iter()
        .cloned()
        .find_map(|list| EchConfig::new(list, ALL_SUPPORTED_SUITES).ok())
    {
        match open_upstream_ech(cfg, &bootstrap, ech_config).await {
            Ok(ws) => {
                info!(
                    upstream = %cfg.worker_host,
                    ech = "accepted",
                    "upstream ECH WebSocket established"
                );
                return Ok(ws);
            }
            Err(err) => {
                warn!(
                    error = %err,
                    upstream = %cfg.worker_host,
                    "ECH failed; falling back to normal TLS"
                );
            }
        }
    } else {
        info!(
            upstream = %cfg.worker_host,
            "no compatible ECHConfigList; using normal TLS fallback"
        );
    }

    let ws = open_upstream_plain(cfg, &bootstrap).await?;
    info!(
        upstream = %cfg.worker_host,
        ech = "fallback",
        "upstream TLS WebSocket established without ECH"
    );
    Ok(ws)
}

async fn open_upstream_ech(
    cfg: &Config,
    bootstrap: &Bootstrap,
    ech_config: EchConfig,
) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = ClientConfig::builder_with_provider(provider)
        .with_ech(EchMode::from(ech_config))
        .context("failed to enable ECH")?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let tcp = connect_cached_ips(&bootstrap.ips, cfg.worker_port, cfg.connect_timeout).await?;
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
        bail!("server did not accept ECH (status={ech_status:?})");
    }

    open_websocket(cfg, tls).await
}

async fn open_upstream_plain(
    cfg: &Config,
    bootstrap: &Bootstrap,
) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let tcp = connect_cached_ips(&bootstrap.ips, cfg.worker_port, cfg.connect_timeout).await?;
    tcp.set_nodelay(true).ok();

    let server_name = ServerName::try_from(cfg.worker_host.clone())
        .context("WORKER_HOST is not a valid DNS name")?;
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tls = timeout(cfg.connect_timeout, connector.connect(server_name, tcp))
        .await
        .context("TLS fallback handshake timed out")?
        .context("TLS fallback handshake failed")?;

    open_websocket(cfg, tls).await
}

async fn open_websocket(
    cfg: &Config,
    tls: TlsStream<TcpStream>,
) -> Result<WebSocketStream<TlsStream<TcpStream>>> {
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

async fn resolve_system_bootstrap(cfg: &Config) -> Result<Bootstrap> {
    let lookup = timeout(
        cfg.connect_timeout,
        lookup_host((cfg.worker_host.as_str(), cfg.worker_port)),
    )
    .await
    .context("system DNS lookup timed out")?
    .context("system DNS lookup failed")?;

    let mut ips: Vec<IpAddr> = lookup.map(|addr| addr.ip()).collect();
    ips.sort_by_key(|ip| ip.is_ipv6());
    ips.dedup();

    if ips.is_empty() {
        bail!("system DNS bootstrap returned no usable IP address");
    }

    Ok(Bootstrap {
        ech_lists: Vec::new(),
        ips,
    })
}

async fn resolve_bootstrap(resolvers: &[TokioAsyncResolver], cfg: &Config) -> Result<Bootstrap> {
    let mut attempts = FuturesUnordered::new();

    for resolver in resolvers {
        attempts.push(resolve_bootstrap_with_resolver(resolver, cfg));
    }

    let mut errors = Vec::new();
    while let Some(result) = attempts.next().await {
        match result {
            Ok(bootstrap) => return Ok(bootstrap),
            Err(err) => errors.push(err.to_string()),
        }
    }

    bail!(
        "all encrypted DNS bootstrap attempts failed: {}",
        errors.join(" | ")
    )
}

async fn resolve_bootstrap_with_resolver(
    resolver: &TokioAsyncResolver,
    cfg: &Config,
) -> Result<Bootstrap> {
    let bootstrap_timeout = Duration::from_secs(20);

    let ech_lists = match timeout(
        bootstrap_timeout,
        lookup_ech_configs(resolver, &cfg.worker_host, cfg.worker_port),
    )
    .await
    {
        Ok(Ok(lists)) => lists,
        Ok(Err(err)) => {
            warn!(
                error = %err,
                upstream = %cfg.worker_host,
                "ECH DNS lookup unavailable; normal TLS fallback remains available"
            );
            Vec::new()
        }
        Err(_) => {
            warn!(
                upstream = %cfg.worker_host,
                "ECH DNS lookup timed out; normal TLS fallback remains available"
            );
            Vec::new()
        }
    };

    let lookup = timeout(bootstrap_timeout, resolver.lookup_ip(&cfg.worker_host))
        .await
        .context("encrypted address bootstrap timed out")?
        .context("encrypted address bootstrap failed")?;

    let mut ips: Vec<IpAddr> = lookup.iter().collect();
    ips.sort_by_key(|ip| ip.is_ipv6());
    ips.dedup();

    if ips.is_empty() {
        bail!("encrypted DNS bootstrap returned no usable IP address");
    }

    Ok(Bootstrap { ech_lists, ips })
}

async fn connect_cached_ips(
    ips: &[IpAddr],
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream> {
    let per_ip_timeout = connect_timeout.min(Duration::from_secs(2));
    let mut errors = Vec::new();

    for ip in ips {
        let addr = SocketAddr::new(*ip, port);
        match timeout(per_ip_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => errors.push(format!("{addr}: {err}")),
            Err(_) => errors.push(format!("{addr}: connect timed out")),
        }
    }

    bail!(
        "all cached IP connection attempts failed: {}",
        errors.join(" | ")
    )
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
