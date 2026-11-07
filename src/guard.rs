use std::{
    env,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use aws_lc_rs::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use axum::{
    extract::ws::{Message, WebSocket},
    http::HeaderMap,
};
use futures_util::StreamExt;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream},
    time::{interval, timeout},
};
use tokio_rustls::TlsConnector;

const DEFAULT_TELEMETRY_URL: &str = "https://monitor.reoos.ir/api/direct-session/telemetry";
const HEARTBEAT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_millis(1800);
const INITIAL_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_LIMIT: usize = 64 * 1024;

#[derive(Clone)]
pub struct SessionGuard {
    enabled: bool,
    route: String,
    telemetry_url: String,
    tls_config: Arc<ClientConfig>,
}

#[derive(Clone, Debug)]
pub struct SessionMeta {
    uuid: String,
    uuid_hash: String,
    source_ip: String,
    session_id: String,
}

pub struct GuardStart {
    pub meta: Option<SessionMeta>,
    pub buffered: Vec<Message>,
    pub locked: bool,
}

#[derive(Debug, Default, Deserialize)]
struct TelemetryResponse {
    #[serde(default)]
    known: bool,
    session_known: Option<bool>,
    #[serde(default)]
    locked: bool,
}

#[derive(Serialize)]
struct TelemetryPayload<'a> {
    uuid_hash: &'a str,
    source_ip: &'a str,
    route: &'a str,
    event: &'a str,
    ts: i64,
    session_id: &'a str,
    proof: String,
}

impl SessionGuard {
    pub fn new(default_route: &str) -> Result<Self> {
        let enabled = env::var("CONCURRENCY_GUARD")
            .map(|v| v.trim() != "0")
            .unwrap_or(true);
        let route = env::var("CONCURRENCY_ROUTE")
            .unwrap_or_else(|_| default_route.to_owned())
            .trim()
            .to_ascii_lowercase();
        if !matches!(route.as_str(), "direct-r1" | "direct-r2" | "direct-r3") {
            bail!("invalid CONCURRENCY_ROUTE");
        }

        let telemetry_url =
            env::var("SESSION_TELEMETRY_URL").unwrap_or_else(|_| DEFAULT_TELEMETRY_URL.to_owned());
        parse_https_url(&telemetry_url).context("invalid SESSION_TELEMETRY_URL")?;

        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            enabled,
            route,
            telemetry_url,
            tls_config: Arc::new(tls_config),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn route(&self) -> &str {
        &self.route
    }

    pub async fn begin(
        &self,
        client: &mut WebSocket,
        source_ip: Option<String>,
    ) -> Result<GuardStart> {
        if !self.enabled || source_ip.is_none() {
            return Ok(GuardStart {
                meta: None,
                buffered: Vec::new(),
                locked: false,
            });
        }

        let (buffered, header) = read_initial(client).await?;
        let uuid = uuid_from_header(&header).context("invalid VLESS UUID header")?;
        let source_ip = source_ip.expect("checked above");
        let session_id = random_session_id()?;
        let meta = SessionMeta {
            uuid_hash: sha256_hex(uuid.as_bytes()),
            uuid,
            source_ip,
            session_id,
        };

        let opened = self.emit(&meta, "open").await;
        let locked = opened.as_ref().map(|r| r.locked).unwrap_or(false);

        Ok(GuardStart {
            meta: Some(meta),
            buffered,
            locked,
        })
    }

    pub async fn watch(&self, meta: SessionMeta) -> Result<()> {
        let mut ticker = interval(HEARTBEAT);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let mut state = self.emit(&meta, "heartbeat").await;
            if state
                .as_ref()
                .map(|r| r.known && r.session_known == Some(false))
                .unwrap_or(false)
            {
                state = self.emit(&meta, "open").await;
            }
            if state.as_ref().map(|r| r.locked).unwrap_or(false) {
                bail!("concurrency_locked");
            }
        }
    }

    pub fn close_async(&self, meta: SessionMeta) {
        if !self.enabled {
            return;
        }
        let guard = self.clone();
        tokio::spawn(async move {
            let _ = guard.emit(&meta, "close").await;
        });
    }

    async fn emit(&self, meta: &SessionMeta, event: &str) -> Option<TelemetryResponse> {
        if !self.enabled {
            return None;
        }

        let ts = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
        let proof = telemetry_proof(
            &meta.uuid,
            &meta.uuid_hash,
            &meta.source_ip,
            &self.route,
            event,
            ts,
            &meta.session_id,
        );

        let payload = TelemetryPayload {
            uuid_hash: &meta.uuid_hash,
            source_ip: &meta.source_ip,
            route: &self.route,
            event,
            ts,
            session_id: &meta.session_id,
            proof,
        };
        let body = serde_json::to_vec(&payload).ok()?;
        self.post_json(&body).await
    }

    async fn post_json(&self, body: &[u8]) -> Option<TelemetryResponse> {
        let (host, port, path) = parse_https_url(&self.telemetry_url)?;
        let addrs = timeout(IO_TIMEOUT, lookup_host((host.as_str(), port)))
            .await
            .ok()?
            .ok()?;

        let mut tcp = None;
        for addr in addrs {
            match timeout(IO_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    tcp = Some(stream);
                    break;
                }
                _ => continue,
            }
        }
        let tcp = tcp?;
        tcp.set_nodelay(true).ok();

        let server_name = ServerName::try_from(host.clone()).ok()?;
        let connector = TlsConnector::from(self.tls_config.clone());
        let mut tls = timeout(IO_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .ok()?
            .ok()?;

        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SlipNet-Direct-Guard/1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );

        let io = async {
            tls.write_all(request.as_bytes()).await?;
            tls.write_all(body).await?;
            tls.flush().await?;
            let mut raw = Vec::with_capacity(4096);
            (&mut tls).take(64 * 1024).read_to_end(&mut raw).await?;
            std::io::Result::Ok(raw)
        };
        let raw = timeout(IO_TIMEOUT, io).await.ok()?.ok()?;
        parse_http_json(&raw)
    }
}

pub fn source_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(ip) = signed_bridge_ip(headers) {
        return Some(ip);
    }

    for name in ["x-real-ip", "x-client-ip", "ar-real-ip"] {
        let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
            continue;
        };
        for candidate in value.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            if let Some(ip) = normalize_ip(candidate) {
                if is_public_ip(&ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }

    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for candidate in value
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .rev()
        {
            if let Some(ip) = normalize_ip(candidate) {
                if is_public_ip(&ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }

    None
}

fn signed_bridge_ip(headers: &HeaderMap) -> Option<String> {
    let secret = env::var("REALIP_BRIDGE_SECRET").ok()?;
    if secret.len() < 32 {
        return None;
    }

    let raw_ip = headers.get("x-slipnet-real-ip")?.to_str().ok()?;
    let ts = headers
        .get("x-slipnet-real-ip-ts")?
        .to_str()
        .ok()?
        .parse::<i64>()
        .ok()?;
    let proof = headers.get("x-slipnet-real-ip-proof")?.to_str().ok()?;

    let ip = normalize_ip(raw_ip)?;
    if !is_public_ip(&ip) {
        return None;
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    if (now - ts).abs() > 30 {
        return None;
    }

    let message = format!("{}|{}", ip, ts);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let expected = hex_bytes(hmac::sign(&key, message.as_bytes()).as_ref());
    if expected.len() != proof.len()
        || !expected
            .bytes()
            .zip(proof.bytes())
            .fold(true, |acc, (a, b)| acc & (a == b))
    {
        return None;
    }

    Some(ip.to_string())
}

fn normalize_ip(raw: &str) -> Option<IpAddr> {
    let mut value = raw.trim();
    if let Some(v) = value.strip_prefix("::ffff:") {
        value = v;
    }
    if let Some((v, _)) = value.split_once('%') {
        value = v;
    }
    value.parse::<IpAddr>().ok()
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || o[0] >= 224)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

async fn read_initial(client: &mut WebSocket) -> Result<(Vec<Message>, Vec<u8>)> {
    timeout(INITIAL_TIMEOUT, async {
        let mut buffered = Vec::new();
        let mut prefix = Vec::new();

        while prefix.len() < 17 {
            let message = client
                .next()
                .await
                .context("client closed before VLESS header")?
                .context("failed reading initial WebSocket message")?;

            match &message {
                Message::Binary(data) => prefix.extend_from_slice(data),
                Message::Text(text) => prefix.extend_from_slice(text.as_bytes()),
                Message::Close(_) => bail!("client closed before VLESS header"),
                Message::Ping(_) | Message::Pong(_) => {}
            }

            if prefix.len() > INITIAL_LIMIT {
                bail!("initial VLESS payload too large");
            }
            buffered.push(message);
        }

        Ok((buffered, prefix))
    })
    .await
    .context("timed out waiting for VLESS header")?
}

fn uuid_from_header(header: &[u8]) -> Option<String> {
    if header.len() < 17 {
        return None;
    }
    let bytes = &header[1..17];
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").ok()?;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn sha256_hex(input: &[u8]) -> String {
    let value = digest::digest(&digest::SHA256, input);
    hex_bytes(value.as_ref())
}

fn random_session_id() -> Result<String> {
    let mut bytes = [0u8; 12];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("secure random failed"))?;
    Ok(hex_bytes(&bytes))
}

fn telemetry_proof(
    uuid: &str,
    uuid_hash: &str,
    source_ip: &str,
    route: &str,
    event: &str,
    ts: i64,
    session_id: &str,
) -> String {
    let message = format!("{uuid_hash}|{source_ip}|{route}|{event}|{ts}|{session_id}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, uuid.as_bytes());
    let tag = hmac::sign(&key, message.as_bytes());
    hex_bytes(tag.as_ref())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn parse_https_url(raw: &str) -> Option<(String, u16, String)> {
    let rest = raw.trim().strip_prefix("https://")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return None;
        }
        (h.to_owned(), p.parse::<u16>().ok()?)
    } else {
        (authority.to_owned(), 443)
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path))
}

fn parse_http_json(raw: &[u8]) -> Option<TelemetryResponse> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&raw[..split]).ok()?;
    let status = headers.lines().next()?;
    if !status.contains(" 200 ") {
        return None;
    }
    let body = &raw[split + 4..];

    if headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let decoded = decode_chunked(body)?;
        serde_json::from_slice(&decoded).ok()
    } else {
        serde_json::from_slice(body).ok()
    }
}

fn decode_chunked(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&input[..line_end]).ok()?;
        let size_hex = line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return None;
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn extracts_uuid_from_vless_header() {
        let mut header = vec![0u8];
        header.extend_from_slice(&[
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x43, 0x33, 0x84, 0x44, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55,
        ]);
        assert_eq!(
            uuid_from_header(&header).as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );
    }

    #[test]
    fn parses_forwarded_ip_like_legacy_guard() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("192.0.2.1, 198.51.100.9"),
        );
        assert_eq!(source_ip(&headers).as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn proof_matches_backend_contract() {
        let uuid = "11111111-2222-4333-8444-555555555555";
        let uuid_hash = "cf4c4732fd3b8f8a55b60871950a2f22c893ea7afd75d2146826534e3f67cc49";
        assert_eq!(
            telemetry_proof(
                uuid,
                uuid_hash,
                "192.0.2.10",
                "direct-r1",
                "open",
                1_700_000_000,
                "00112233445566778899aabb",
            ),
            "830706f96f6e1f0ec5a9139f8ba20b569fc1b07e681e3e9a7fdd382b509f2734"
        );
    }

    #[test]
    fn parses_monitor_url() {
        assert_eq!(
            parse_https_url(DEFAULT_TELEMETRY_URL),
            Some((
                "monitor.reoos.ir".to_owned(),
                443,
                "/api/direct-session/telemetry".to_owned()
            ))
        );
    }
}
