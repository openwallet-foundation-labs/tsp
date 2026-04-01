use clap::{Subcommand, ValueEnum};
use futures::StreamExt;
use serde::Serialize;
use std::time::{Duration, Instant};
use tsp_sdk::{
    AsyncSecureStore, Error, OwnedVid, ReceivedTspMessage, RelationshipStatus, VerifiedVid,
    transport,
};
use url::Url;

const FRAME_MAGIC: [u8; 4] = *b"TSPB";
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_LEN: usize = 16;
const LOCAL_TCP_SERVER_VID: &str = "bob";
const LOCAL_TCP_CLIENT_SENDER: &str = "alice";
const LOCAL_TCP_CLIENT_RECEIVER: &str = "bob";
const HOSTED_HTTP_SERVER_VID: &str = "b";
const HOSTED_HTTP_CLIENT_SENDER: &str = "a";
const HOSTED_HTTP_CLIENT_RECEIVER: &str = "b";
const BUILTIN_ALICE_PIV: &str = include_str!("../test/alice/piv.json");
const BUILTIN_BOB_PIV: &str = include_str!("../test/bob/piv.json");
const BUILTIN_A_PIV: &str = include_str!("../test/a/piv.json");
const BUILTIN_B_PIV: &str = include_str!("../test/b/piv.json");
const LOCAL_QUIC_SERVER_VID: &str = "quic-bob";
const LOCAL_QUIC_CLIENT_SENDER: &str = "quic-alice";
const LOCAL_QUIC_CLIENT_RECEIVER: &str = "quic-bob";
const BUILTIN_QUIC_ALICE_PIV: &str = include_str!("../test/quic-alice/piv.json");
const BUILTIN_QUIC_BOB_PIV: &str = include_str!("../test/quic-bob/piv.json");
const LOCAL_TLS_SERVER_VID: &str = "tls-bob";
const LOCAL_TLS_CLIENT_SENDER: &str = "tls-alice";
const LOCAL_TLS_CLIENT_RECEIVER: &str = "tls-bob";
const BUILTIN_TLS_ALICE_PIV: &str = include_str!("../test/tls-alice/piv.json");
const BUILTIN_TLS_BOB_PIV: &str = include_str!("../test/tls-bob/piv.json");
const SERVER_SESSION_IDLE_GAP_MULTIPLIER: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameKind {
    ThroughputData = 1,
    LatencyRequest = 2,
    LatencyAck = 3,
}

impl FrameKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::ThroughputData),
            2 => Some(Self::LatencyRequest),
            3 => Some(Self::LatencyAck),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum BenchProfile {
    LocalTcp,
    HostedHttp,
    LocalQuic,
    LocalTls,
}

impl BenchProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalTcp => "local-tcp",
            Self::HostedHttp => "hosted-http",
            Self::LocalQuic => "local-quic",
            Self::LocalTls => "local-tls",
        }
    }

    fn default_server_vid(self) -> &'static str {
        match self {
            Self::LocalTcp => LOCAL_TCP_SERVER_VID,
            Self::HostedHttp => HOSTED_HTTP_SERVER_VID,
            Self::LocalQuic => LOCAL_QUIC_SERVER_VID,
            Self::LocalTls => LOCAL_TLS_SERVER_VID,
        }
    }

    fn default_client_sender(self) -> &'static str {
        match self {
            Self::LocalTcp => LOCAL_TCP_CLIENT_SENDER,
            Self::HostedHttp => HOSTED_HTTP_CLIENT_SENDER,
            Self::LocalQuic => LOCAL_QUIC_CLIENT_SENDER,
            Self::LocalTls => LOCAL_TLS_CLIENT_SENDER,
        }
    }

    fn default_client_receiver(self) -> &'static str {
        match self {
            Self::LocalTcp => LOCAL_TCP_CLIENT_RECEIVER,
            Self::HostedHttp => HOSTED_HTTP_CLIENT_RECEIVER,
            Self::LocalQuic => LOCAL_QUIC_CLIENT_RECEIVER,
            Self::LocalTls => LOCAL_TLS_CLIENT_RECEIVER,
        }
    }

    fn default_sender_piv(self) -> &'static str {
        match self {
            Self::LocalTcp => BUILTIN_ALICE_PIV,
            Self::HostedHttp => BUILTIN_A_PIV,
            Self::LocalQuic => BUILTIN_QUIC_ALICE_PIV,
            Self::LocalTls => BUILTIN_TLS_ALICE_PIV,
        }
    }

    fn default_receiver_piv(self) -> &'static str {
        match self {
            Self::LocalTcp => BUILTIN_BOB_PIV,
            Self::HostedHttp => BUILTIN_B_PIV,
            Self::LocalQuic => BUILTIN_QUIC_BOB_PIV,
            Self::LocalTls => BUILTIN_TLS_BOB_PIV,
        }
    }
}

impl std::fmt::Display for BenchProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum BenchSubcommand {
    #[command(about = "run a bench receiver")]
    Server {
        #[arg(
            long,
            default_value_t = BenchProfile::LocalTcp,
            help = "Built-in profile: local-tcp, local-tls, local-quic, or hosted-http"
        )]
        profile: BenchProfile,
        #[arg(long, help = "Receiver VID or alias (default depends on --profile)")]
        vid: Option<String>,
        #[arg(long, default_value = "1s", help = "Report interval")]
        interval: String,
        #[arg(long, help = "Stop after first benchmark message")]
        one_shot: bool,
        #[arg(long, help = "Emit machine-readable summary JSON")]
        json: bool,
    },
    #[command(arg_required_else_help = true, about = "run a bench sender")]
    Client {
        #[arg(
            long,
            default_value_t = BenchProfile::LocalTcp,
            help = "Built-in profile: local-tcp, local-tls, local-quic, or hosted-http"
        )]
        profile: BenchProfile,
        #[arg(long, help = "Sender VID or alias (default depends on --profile)")]
        sender: Option<String>,
        #[arg(long, help = "Receiver VID or alias (default depends on --profile)")]
        receiver: Option<String>,
        #[arg(long, help = "Transport endpoint (default: use receiver VID endpoint)")]
        transport: Option<String>,
        #[arg(long, help = "Payload size (e.g. 128B, 1KiB, 64KiB)")]
        payload_size: String,
        #[arg(long, help = "Test duration (e.g. 10s, 500ms, 2m)")]
        duration: String,
        #[arg(
            long,
            default_value = "throughput",
            help = "Benchmark mode: throughput or latency"
        )]
        mode: String,
        #[arg(long, default_value = "1s", help = "Report interval")]
        interval: String,
        #[arg(long, default_value = "0s", help = "Warmup time excluded from metrics")]
        warmup: String,
        #[arg(long, default_value = "5s", help = "ACK timeout for latency mode")]
        ack_timeout: String,
        #[arg(long, help = "Emit machine-readable summary JSON")]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchMode {
    Throughput,
    Latency,
}

impl BenchMode {
    fn parse(mode: &str) -> Result<Self, Error> {
        match mode {
            "throughput" => Ok(Self::Throughput),
            "latency" => Ok(Self::Latency),
            _ => Err(Error::Relationship(format!(
                "invalid --mode '{mode}', expected 'throughput' or 'latency'"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Latency => "latency",
        }
    }
}

#[derive(Default, Clone)]
struct ThroughputStats {
    transfer_bytes: u64,
    messages: u64,
    seal_us: Vec<f64>,
    open_us: Vec<f64>,
}

impl ThroughputStats {
    fn is_empty(&self) -> bool {
        self.messages == 0
    }

    fn record_send(&mut self, bytes: u64, seal_us: f64) {
        self.transfer_bytes += bytes;
        self.messages += 1;
        self.seal_us.push(seal_us);
    }

    fn record_recv(&mut self, bytes: u64, open_us: f64) {
        self.transfer_bytes += bytes;
        self.messages += 1;
        self.open_us.push(open_us);
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default, Clone)]
struct LatencyStats {
    messages: u64,
    transfer_bytes: u64,
    seal_us: Vec<f64>,
    rtt_us: Vec<f64>,
    jitter_us: Vec<f64>,
}

impl LatencyStats {
    fn is_empty(&self) -> bool {
        self.messages == 0
    }

    fn record(&mut self, bytes: u64, seal_us: f64, rtt_us: f64, jitter_us: Option<f64>) {
        self.transfer_bytes += bytes;
        self.messages += 1;
        self.seal_us.push(seal_us);
        self.rtt_us.push(rtt_us);
        if let Some(v) = jitter_us {
            self.jitter_us.push(v);
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Serialize)]
struct Percentiles {
    avg: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

#[derive(Serialize)]
struct PercentilesWithStddev {
    avg: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    stddev: f64,
}

#[derive(Serialize)]
struct JitterMetrics {
    avg: f64,
    p95: f64,
}

#[derive(Serialize)]
struct ThroughputMetricsJson {
    transfer_bytes: u64,
    messages: u64,
    msg_per_sec: f64,
    bandwidth_bps: f64,
    seal_us: Percentiles,
    open_us: Percentiles,
}

#[derive(Serialize)]
struct LatencyMetricsJson {
    messages: u64,
    transfer_bytes: u64,
    msg_per_sec: f64,
    bandwidth_bps: f64,
    seal_us: Percentiles,
    rtt_us: PercentilesWithStddev,
    jitter_us: JitterMetrics,
}

#[derive(Serialize)]
struct BenchJson<T: Serialize> {
    mode: String,
    role: String,
    sender: Option<String>,
    receiver: Option<String>,
    transport: Option<String>,
    payload_size_bytes: Option<usize>,
    session_id: Option<u64>,
    session_duration_ms: Option<u64>,
    duration_ms: u64,
    interval_ms: u64,
    timestamp_utc: String,
    metrics: T,
}

#[derive(Debug, Clone, Copy)]
struct ParsedFrame {
    kind: FrameKind,
    seq: u64,
}

pub(crate) async fn run(
    command: BenchSubcommand,
    store: &AsyncSecureStore,
    wallet_name: &str,
) -> Result<(), Error> {
    match command {
        BenchSubcommand::Server {
            profile,
            vid,
            interval,
            one_shot,
            json,
        } => {
            let vid = vid.unwrap_or_else(|| profile.default_server_vid().to_string());
            maybe_bootstrap_server_profile_defaults(store, profile, &vid)?;
            let interval = parse_duration_nonzero(&interval, "interval")?;
            run_server(store, &vid, interval, one_shot, json).await
        }
        BenchSubcommand::Client {
            profile,
            sender,
            receiver,
            transport,
            payload_size,
            duration,
            mode,
            interval,
            warmup,
            ack_timeout,
            json,
        } => {
            let sender = sender.unwrap_or_else(|| profile.default_client_sender().to_string());
            let receiver =
                receiver.unwrap_or_else(|| profile.default_client_receiver().to_string());
            maybe_bootstrap_client_profile_defaults(store, profile, &sender, &receiver)?;
            let payload_size = parse_payload_size(&payload_size)?;
            let duration = parse_duration_nonzero(&duration, "duration")?;
            let interval = parse_duration_nonzero(&interval, "interval")?;
            let warmup = parse_duration_allow_zero(&warmup, "warmup")?;
            let ack_timeout = parse_duration_nonzero(&ack_timeout, "ack-timeout")?;
            let mode = BenchMode::parse(&mode)?;

            match mode {
                BenchMode::Throughput => {
                    run_client_throughput(
                        store,
                        wallet_name,
                        &sender,
                        &receiver,
                        transport.as_deref(),
                        payload_size,
                        duration,
                        interval,
                        warmup,
                        json,
                    )
                    .await
                }
                BenchMode::Latency => {
                    run_client_latency(
                        store,
                        wallet_name,
                        &sender,
                        &receiver,
                        transport.as_deref(),
                        payload_size,
                        duration,
                        interval,
                        warmup,
                        ack_timeout,
                        json,
                    )
                    .await
                }
            }
        }
    }
}

fn parse_builtin_owned_vid(alias: &str, piv_json: &str) -> Result<OwnedVid, Error> {
    serde_json::from_str(piv_json).map_err(|e| {
        Error::Relationship(format!("failed to load built-in identity '{alias}': {e}"))
    })
}

#[derive(Clone, Copy)]
enum BuiltinAliasKind {
    Private,
    Verified,
}

fn ensure_builtin_alias(
    store: &AsyncSecureStore,
    alias: &str,
    piv_json: &str,
    kind: BuiltinAliasKind,
) -> Result<String, Error> {
    if let Some(vid) = store.resolve_alias(alias)? {
        let present = match kind {
            BuiltinAliasKind::Private => store.has_private_vid(&vid)?,
            BuiltinAliasKind::Verified => store.has_verified_vid(&vid)?,
        };

        if present {
            return Ok(vid);
        }

        return Err(match kind {
            BuiltinAliasKind::Private => Error::MissingPrivateVid(format!(
                "alias '{alias}' is not a private VID; pass --sender/--vid explicitly"
            )),
            BuiltinAliasKind::Verified => Error::UnverifiedVid(format!(
                "alias '{alias}' is not a verified VID; pass --receiver explicitly"
            )),
        });
    }

    let owned = parse_builtin_owned_vid(alias, piv_json)?;
    let vid = owned.identifier().to_string();

    match kind {
        BuiltinAliasKind::Private => {
            if !store.has_private_vid(&vid)? {
                store.add_private_vid(owned, None)?;
            }
        }
        BuiltinAliasKind::Verified => {
            if !store.has_verified_vid(&vid)? {
                store.add_verified_vid(owned.vid().clone(), None)?;
            }
        }
    }

    store.set_alias(alias.to_string(), vid.clone())?;
    Ok(vid)
}

fn ensure_bidirectional_relation(
    store: &AsyncSecureStore,
    local_vid: &str,
    remote_vid: &str,
) -> Result<(), Error> {
    match store.get_relation_status_for_vid_pair(local_vid, remote_vid) {
        Ok(RelationshipStatus::Unrelated) | Err(Error::Relationship(_)) => {
            store.set_relation_and_status_for_vid(
                remote_vid,
                RelationshipStatus::Bidirectional {
                    thread_id: [0; 32],
                    outstanding_nested_thread_ids: vec![],
                },
                local_vid,
            )?;
        }
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    Ok(())
}

fn maybe_bootstrap_server_profile_defaults(
    store: &AsyncSecureStore,
    profile: BenchProfile,
    vid_alias_or_id: &str,
) -> Result<(), Error> {
    if vid_alias_or_id != profile.default_server_vid() {
        return Ok(());
    }

    let local = ensure_builtin_alias(
        store,
        profile.default_server_vid(),
        profile.default_receiver_piv(),
        BuiltinAliasKind::Private,
    )?;
    let peer = ensure_builtin_alias(
        store,
        profile.default_client_sender(),
        profile.default_sender_piv(),
        BuiltinAliasKind::Verified,
    )?;
    ensure_bidirectional_relation(store, &local, &peer)
}

fn maybe_bootstrap_client_profile_defaults(
    store: &AsyncSecureStore,
    profile: BenchProfile,
    sender_alias_or_vid: &str,
    receiver_alias_or_vid: &str,
) -> Result<(), Error> {
    let mut sender_vid = None;
    let mut receiver_vid = None;

    if sender_alias_or_vid == profile.default_client_sender() {
        sender_vid = Some(ensure_builtin_alias(
            store,
            profile.default_client_sender(),
            profile.default_sender_piv(),
            BuiltinAliasKind::Private,
        )?);
    }

    if receiver_alias_or_vid == profile.default_client_receiver() {
        receiver_vid = Some(ensure_builtin_alias(
            store,
            profile.default_client_receiver(),
            profile.default_receiver_piv(),
            BuiltinAliasKind::Verified,
        )?);
    }

    if let (Some(sender), Some(receiver)) = (sender_vid.as_deref(), receiver_vid.as_deref()) {
        ensure_bidirectional_relation(store, sender, receiver)?;
    }

    Ok(())
}

fn validate_transport_scheme(url: &Url, source: &str) -> Result<(), Error> {
    if !matches!(url.scheme(), "tcp" | "tls" | "quic" | "http" | "https") {
        return Err(Error::Relationship(format!(
            "unsupported transport scheme '{}' in {source} (supported: tcp, tls, quic, http, https)",
            url.scheme()
        )));
    }

    Ok(())
}

fn parse_transport(transport: &str) -> Result<Url, Error> {
    let url = Url::parse(transport)
        .map_err(|e| Error::Relationship(format!("invalid --transport '{transport}': {e}")))?;

    validate_transport_scheme(&url, "--transport")?;

    Ok(url)
}

fn parse_payload_size(value: &str) -> Result<usize, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::Relationship(
            "--payload-size cannot be empty".to_string(),
        ));
    }

    let size = byte_unit::Byte::parse_str(trimmed, true)
        .map_err(|e| Error::Relationship(format!("invalid --payload-size '{value}': {e}")))?
        .as_u64();

    if size == 0 {
        return Err(Error::Relationship(
            "--payload-size must be > 0".to_string(),
        ));
    }

    if size < FRAME_HEADER_LEN as u64 {
        return Err(Error::Relationship(format!(
            "--payload-size must be at least {FRAME_HEADER_LEN} bytes"
        )));
    }

    usize::try_from(size).map_err(|_| {
        Error::Relationship("--payload-size is too large for this platform".to_string())
    })
}

fn parse_duration_allow_zero(value: &str, field: &str) -> Result<Duration, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::Relationship(format!("{field} cannot be empty")));
    }

    let duration = humantime::parse_duration(trimmed)
        .map_err(|e| Error::Relationship(format!("invalid {field} '{value}': {e}")))?;

    Ok(duration)
}

fn parse_duration_nonzero(value: &str, field: &str) -> Result<Duration, Error> {
    let duration = parse_duration_allow_zero(value, field)?;
    if duration.is_zero() {
        return Err(Error::Relationship(format!("{field} must be > 0")));
    }

    Ok(duration)
}

fn resolve_vid_transport(
    store: &AsyncSecureStore,
    alias_or_vid: &str,
) -> Result<(String, Url), Error> {
    let vid = store.try_resolve_alias(alias_or_vid)?;
    let (vids, _, _) = store.export()?;

    let local = vids
        .iter()
        .find(|v| v.id == vid)
        .ok_or_else(|| Error::MissingVid(vid.clone()))?;

    let mut transport = local.transport.clone();
    let path = transport.path().replace("[vid_placeholder]", &vid);
    transport.set_path(&path);
    validate_transport_scheme(&transport, "VID transport")?;

    Ok((vid, transport))
}

fn resolve_private_transport(store: &AsyncSecureStore, alias_or_vid: &str) -> Result<Url, Error> {
    let (vid, transport) = resolve_vid_transport(store, alias_or_vid)?;
    if !store.has_private_vid(&vid)? {
        return Err(Error::MissingPrivateVid(vid));
    }

    Ok(transport)
}

fn resolve_client_transport(
    store: &AsyncSecureStore,
    receiver_vid: &str,
    transport_override: Option<&str>,
) -> Result<Url, Error> {
    let (_, receiver_transport) = resolve_vid_transport(store, receiver_vid)?;

    if let Some(override_transport) = transport_override {
        let parsed = parse_transport(override_transport)?;
        if parsed != receiver_transport {
            return Err(Error::Relationship(format!(
                "--transport '{parsed}' does not match receiver endpoint '{receiver_transport}' from VID {receiver_vid}"
            )));
        }

        Ok(parsed)
    } else {
        Ok(receiver_transport)
    }
}

fn build_frame(payload_size: usize, kind: FrameKind, seq: u64) -> Vec<u8> {
    let mut payload = vec![0u8; payload_size];
    payload[0..4].copy_from_slice(&FRAME_MAGIC);
    payload[4] = FRAME_VERSION;
    payload[5] = kind.as_u8();
    payload[6..8].copy_from_slice(&0u16.to_le_bytes());
    payload[8..16].copy_from_slice(&seq.to_le_bytes());

    for (idx, byte) in payload[16..].iter_mut().enumerate() {
        *byte = (idx % 251) as u8;
    }

    payload
}

fn parse_frame(data: &[u8]) -> Option<ParsedFrame> {
    if data.len() < FRAME_HEADER_LEN {
        return None;
    }
    if data[0..4] != FRAME_MAGIC {
        return None;
    }
    if data[4] != FRAME_VERSION {
        return None;
    }

    let kind = FrameKind::from_u8(data[5])?;

    let mut seq_buf = [0u8; 8];
    seq_buf.copy_from_slice(&data[8..16]);
    let seq = u64::from_le_bytes(seq_buf);

    Some(ParsedFrame { kind, seq })
}

fn summarize(values: &[f64]) -> Percentiles {
    if values.is_empty() {
        return Percentiles {
            avg: 0.0,
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
        };
    }

    Percentiles {
        avg: mean(values),
        p50: percentile(values, 50.0),
        p95: percentile(values, 95.0),
        p99: percentile(values, 99.0),
    }
}

fn summarize_with_stddev(values: &[f64]) -> PercentilesWithStddev {
    if values.is_empty() {
        return PercentilesWithStddev {
            avg: 0.0,
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
            stddev: 0.0,
        };
    }

    PercentilesWithStddev {
        avg: mean(values),
        p50: percentile(values, 50.0),
        p95: percentile(values, 95.0),
        p99: percentile(values, 99.0),
        stddev: stddev(values),
    }
}

fn summarize_jitter(values: &[f64]) -> JitterMetrics {
    if values.is_empty() {
        return JitterMetrics { avg: 0.0, p95: 0.0 };
    }

    JitterMetrics {
        avg: mean(values),
        p95: percentile(values, 95.0),
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().copied().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64]) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }

    let avg = mean(values);
    let variance = values
        .iter()
        .map(|v| {
            let d = *v - avg;
            d * d
        })
        .sum::<f64>()
        / (values.len() as f64 - 1.0);

    variance.sqrt()
}

fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));

    let rank = (p / 100.0) * (sorted.len().saturating_sub(1) as f64);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        sorted[lower]
    } else {
        let weight = rank - lower as f64;
        sorted[lower] * (1.0 - weight) + sorted[upper] * weight
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    format!("{value:.1} {}", UNITS[unit])
}

fn format_bits_per_sec(bps: f64) -> String {
    let mut value = bps;
    let mut unit = "bits/s";

    if value >= 1_000_000_000.0 {
        value /= 1_000_000_000.0;
        unit = "Gbits/s";
    } else if value >= 1_000_000.0 {
        value /= 1_000_000.0;
        unit = "Mbits/s";
    } else if value >= 1_000.0 {
        value /= 1_000.0;
        unit = "Kbits/s";
    }

    format!("{value:.2} {unit}")
}

fn print_throughput_header() {
    println!(
        "[ ID] {:>12}  {:>6}  {:>12}  {:>8}  {:>10}  {:>15}  {:>12}  {:>12}",
        "Interval",
        "Proto",
        "Transfer",
        "Messages",
        "Msg/s",
        "Bandwidth",
        "Seal_us(p50)",
        "Open_us(p50)"
    );
}

fn print_latency_header() {
    println!(
        "[ ID] {:>12} {:>6} {:>8} {:>11} {:>7} {:>7} {:>7} {:>10} {:>10} {:>10}",
        "Interval",
        "Proto",
        "Messages",
        "RTT_avg(us)",
        "RTT_p50",
        "RTT_p95",
        "RTT_p99",
        "RTT_stddev",
        "Jitter_avg",
        "Jitter_p95"
    );
}

fn print_throughput_line(id: u32, interval: Duration, stats: &ThroughputStats, protocol: &str) {
    let elapsed = interval.as_secs_f64().max(f64::EPSILON);
    let msg_per_sec = stats.messages as f64 / elapsed;
    let bps = stats.transfer_bytes as f64 * 8.0 / elapsed;
    let seal = summarize(&stats.seal_us);
    let open = summarize(&stats.open_us);

    println!(
        "[{id:>3}] {:>8.1} sec  {:>6}  {:>12}  {:>8}  {:>10.2}  {:>15}  {:>12.1}  {:>12.1}",
        interval.as_secs_f64(),
        protocol,
        format_bytes(stats.transfer_bytes),
        stats.messages,
        msg_per_sec,
        format_bits_per_sec(bps),
        seal.p50,
        open.p50,
    );
}

fn print_latency_line(id: u32, interval: Duration, stats: &LatencyStats, protocol: &str) {
    let rtt = summarize_with_stddev(&stats.rtt_us);
    let jitter = summarize_jitter(&stats.jitter_us);

    println!(
        "[{id:>3}] {:>8.1} sec {:>6} {:>8} {:>11.1} {:>7.1} {:>7.1} {:>7.1} {:>10.1} {:>10.1} {:>10.1}",
        interval.as_secs_f64(),
        protocol,
        stats.messages,
        rtt.avg,
        rtt.p50,
        rtt.p95,
        rtt.p99,
        rtt.stddev,
        jitter.avg,
        jitter.p95,
    );
}

fn timestamp_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ts.to_string()
}

fn ensure_client_ready(
    store: &AsyncSecureStore,
    sender: &str,
    receiver: &str,
    wallet_name: &str,
) -> Result<(), Error> {
    if !store.has_private_vid(sender)? {
        return Err(Error::MissingPrivateVid(sender.to_string()));
    }

    if !store.has_verified_vid(receiver)? {
        return Err(Error::UnverifiedVid(format!(
            "receiver {receiver} is not verified in wallet {wallet_name}; run 'tsp verify' first"
        )));
    }

    match store.get_relation_status_for_vid_pair(sender, receiver) {
        Ok(RelationshipStatus::Unrelated) | Err(Error::Relationship(_)) => {
            return Err(Error::Relationship(format!(
                "no relationship between {sender} and {receiver}; run 'tsp request'/'tsp accept' before bench"
            )));
        }
        Ok(_) => {}
        Err(e) => return Err(e),
    }

    Ok(())
}

#[derive(Default)]
struct ServerSession {
    id: u64,
    started_at: Option<Instant>,
    last_message_at: Option<Instant>,
    last_report_elapsed: Duration,
    total: ThroughputStats,
    window: ThroughputStats,
}

impl ServerSession {
    fn new(id: u64) -> Self {
        Self {
            id,
            ..Self::default()
        }
    }

    fn is_active(&self) -> bool {
        self.started_at.is_some()
    }
}

fn server_idle_gap_threshold(interval: Duration) -> Duration {
    interval.saturating_mul(SERVER_SESSION_IDLE_GAP_MULTIPLIER)
}

fn should_split_server_session(idle_for: Duration, interval: Duration) -> bool {
    idle_for >= server_idle_gap_threshold(interval)
}

fn should_emit_server_window(
    window: &ThroughputStats,
    window_elapsed: Duration,
    interval: Duration,
) -> bool {
    !window.is_empty() && window_elapsed >= interval
}

fn start_server_session(session: &mut ServerSession, started_at: Instant, protocol: &str) {
    session.started_at = Some(started_at);
    session.last_message_at = Some(started_at);
    session.last_report_elapsed = Duration::ZERO;
    session.total.reset();
    session.window.reset();

    println!();
    println!("Session {} started ({protocol})", session.id);
    print_throughput_header();
}

fn maybe_emit_server_window(
    session: &mut ServerSession,
    now: Instant,
    interval: Duration,
    protocol: &str,
) {
    let Some(started_at) = session.started_at else {
        return;
    };

    let elapsed = now.duration_since(started_at);
    let window_elapsed = elapsed.saturating_sub(session.last_report_elapsed);

    if should_emit_server_window(&session.window, window_elapsed, interval) {
        print_throughput_line(0, window_elapsed, &session.window, protocol);
        session.window.reset();
        session.last_report_elapsed = elapsed;
    }
}

fn finalize_server_session(
    session: &mut ServerSession,
    measured_end_at: Instant,
    interval: Duration,
    protocol: &str,
    vid: &str,
    transport: &Url,
    json: bool,
) -> Result<(), Error> {
    let Some(started_at) = session.started_at else {
        return Ok(());
    };

    let total_elapsed = measured_end_at.duration_since(started_at);
    if !session.window.is_empty() {
        let window_elapsed = total_elapsed.saturating_sub(session.last_report_elapsed);
        print_throughput_line(0, window_elapsed, &session.window, protocol);
        session.window.reset();
    }

    let seal = summarize(&session.total.seal_us);
    let open = summarize(&session.total.open_us);
    let elapsed = total_elapsed.as_secs_f64().max(f64::EPSILON);
    let msg_per_sec = session.total.messages as f64 / elapsed;
    let bandwidth_bps = session.total.transfer_bytes as f64 * 8.0 / elapsed;

    println!("Session {} summary:", session.id);
    println!(
        "[SUM] {:>5.1} sec  {:>6}  {:>12}  {:>8}  {:>10.2}  {:>15}  {:>11.1}  {:>11.1}",
        total_elapsed.as_secs_f64(),
        protocol,
        format_bytes(session.total.transfer_bytes),
        session.total.messages,
        msg_per_sec,
        format_bits_per_sec(bandwidth_bps),
        seal.p50,
        open.p50,
    );

    if json {
        let metrics = ThroughputMetricsJson {
            transfer_bytes: session.total.transfer_bytes,
            messages: session.total.messages,
            msg_per_sec,
            bandwidth_bps,
            seal_us: seal,
            open_us: open,
        };

        let payload = BenchJson {
            mode: "server".to_string(),
            role: "server".to_string(),
            sender: None,
            receiver: Some(vid.to_string()),
            transport: Some(transport.to_string()),
            payload_size_bytes: None,
            session_id: Some(session.id),
            session_duration_ms: Some(total_elapsed.as_millis() as u64),
            duration_ms: total_elapsed.as_millis() as u64,
            interval_ms: interval.as_millis() as u64,
            timestamp_utc: timestamp_utc(),
            metrics,
        };

        println!(
            "{}",
            serde_json::to_string(&payload).map_err(|_| Error::Internal)?
        );
    }

    Ok(())
}

async fn run_server(
    store: &AsyncSecureStore,
    vid_alias_or_id: &str,
    interval: Duration,
    one_shot: bool,
    json: bool,
) -> Result<(), Error> {
    let vid = store.try_resolve_alias(vid_alias_or_id)?;

    if !store.has_private_vid(&vid)? {
        return Err(Error::MissingPrivateVid(vid));
    }

    let transport = resolve_private_transport(store, &vid)?;
    let protocol = transport.scheme().to_ascii_uppercase();
    let mut incoming = transport::receive_messages(&transport).await?;

    let mut session = ServerSession::new(1);
    let mut next_session_id = 2;
    let mut observed_any_message = false;

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if session.is_active()
                    && let Some(last_message_at) = session.last_message_at
                    && !should_split_server_session(last_message_at.elapsed(), interval)
                {
                    maybe_emit_server_window(&mut session, Instant::now(), interval, &protocol);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            msg = incoming.next() => {
                let Some(msg) = msg else {
                    break;
                };
                let mut raw = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("bench server transport error: {e}");
                        continue;
                    }
                };
                let raw_len = raw.len() as u64;

                let open_started = Instant::now();
                let opened = match store.open_message(&mut raw) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("bench server decode error: {e}");
                        continue;
                    }
                };
                let open_us = open_started.elapsed().as_secs_f64() * 1_000_000.0;

                if let ReceivedTspMessage::GenericMessage { sender, message, .. } = opened
                    && let Some(frame) = parse_frame(message)
                {
                    let now = Instant::now();

                    if session.is_active()
                        && let Some(last_message_at) = session.last_message_at
                    {
                        let idle_for = now.duration_since(last_message_at);
                        if should_split_server_session(idle_for, interval) {
                            finalize_server_session(
                                &mut session,
                                last_message_at,
                                interval,
                                &protocol,
                                &vid,
                                &transport,
                                json,
                            )?;
                            session = ServerSession::new(next_session_id);
                            next_session_id += 1;
                        }
                    }

                    if !session.is_active() {
                        start_server_session(&mut session, now, &protocol);
                    }

                    observed_any_message = true;
                    session.last_message_at = Some(now);
                    session.total.record_recv(raw_len, open_us);
                    session.window.record_recv(raw_len, open_us);
                    maybe_emit_server_window(&mut session, now, interval, &protocol);

                    if frame.kind == FrameKind::LatencyRequest {
                        let ack_payload =
                            build_frame(message.len().max(FRAME_HEADER_LEN), FrameKind::LatencyAck, frame.seq);
                        let (ack_transport, ack_message) =
                            store.seal_message(&vid, &sender, None, &ack_payload)?;
                        if let Err(e) = transport::send_message(&ack_transport, &ack_message).await {
                            eprintln!("bench server failed to send ack: {e}");
                        }
                    }

                    if one_shot {
                        break;
                    }
                }
            }
        }
    }

    if !observed_any_message {
        eprintln!("bench server: no benchmark messages received");

        if json {
            let metrics = ThroughputMetricsJson {
                transfer_bytes: 0,
                messages: 0,
                msg_per_sec: 0.0,
                bandwidth_bps: 0.0,
                seal_us: summarize(&[]),
                open_us: summarize(&[]),
            };

            let payload = BenchJson {
                mode: "server".to_string(),
                role: "server".to_string(),
                sender: None,
                receiver: Some(vid),
                transport: Some(transport.to_string()),
                payload_size_bytes: None,
                session_id: Some(0),
                session_duration_ms: Some(0),
                duration_ms: 0,
                interval_ms: interval.as_millis() as u64,
                timestamp_utc: timestamp_utc(),
                metrics,
            };

            println!(
                "{}",
                serde_json::to_string(&payload).map_err(|_| Error::Internal)?
            );
        }

        return Ok(());
    }

    if let Some(last_message_at) = session.last_message_at {
        finalize_server_session(
            &mut session,
            last_message_at,
            interval,
            &protocol,
            &vid,
            &transport,
            json,
        )?;
    }

    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn run_client_throughput(
    store: &AsyncSecureStore,
    wallet_name: &str,
    sender_alias_or_vid: &str,
    receiver_alias_or_vid: &str,
    transport_override: Option<&str>,
    payload_size: usize,
    duration: Duration,
    interval: Duration,
    warmup: Duration,
    json: bool,
) -> Result<(), Error> {
    let sender = store.try_resolve_alias(sender_alias_or_vid)?;
    let receiver = store.try_resolve_alias(receiver_alias_or_vid)?;

    ensure_client_ready(store, &sender, &receiver, wallet_name)?;
    let transport_url = resolve_client_transport(store, &receiver, transport_override)?;
    let protocol = transport_url.scheme().to_ascii_uppercase();

    print_throughput_header();

    let started_at = Instant::now();
    let mut last_report_at = Duration::ZERO;
    let mut total = ThroughputStats::default();
    let mut window = ThroughputStats::default();
    let mut seq = 0u64;

    while started_at.elapsed() < duration {
        seq = seq.wrapping_add(1);
        let payload = build_frame(payload_size, FrameKind::ThroughputData, seq);

        let seal_started = Instant::now();
        let (_, message) = store.seal_message(&sender, &receiver, None, &payload)?;
        let seal_us = seal_started.elapsed().as_secs_f64() * 1_000_000.0;

        transport::send_message(&transport_url, &message).await?;

        let elapsed = started_at.elapsed();
        if elapsed > warmup {
            total.record_send(message.len() as u64, seal_us);
            window.record_send(message.len() as u64, seal_us);

            let measured_elapsed = elapsed.saturating_sub(warmup);
            if measured_elapsed.saturating_sub(last_report_at) >= interval && !window.is_empty() {
                let window_elapsed = measured_elapsed.saturating_sub(last_report_at);
                print_throughput_line(0, window_elapsed, &window, &protocol);
                window.reset();
                last_report_at = measured_elapsed;
            }
        }
    }

    let measured_total_elapsed = started_at.elapsed().saturating_sub(warmup);
    if !window.is_empty() {
        let window_elapsed = measured_total_elapsed.saturating_sub(last_report_at);
        if !window_elapsed.is_zero() {
            print_throughput_line(0, window_elapsed, &window, &protocol);
        }
    }

    let seal = summarize(&total.seal_us);
    let open = summarize(&total.open_us);
    let measured_elapsed_secs = measured_total_elapsed.as_secs_f64().max(f64::EPSILON);
    let msg_per_sec = total.messages as f64 / measured_elapsed_secs;
    let bandwidth_bps = total.transfer_bytes as f64 * 8.0 / measured_elapsed_secs;

    println!(
        "[SUM] {:>5.1} sec  {:>6}  {:>12}  {:>8}  {:>10.2}  {:>15}  {:>11.1}  {:>11}",
        measured_elapsed_secs,
        protocol,
        format_bytes(total.transfer_bytes),
        total.messages,
        msg_per_sec,
        format_bits_per_sec(bandwidth_bps),
        seal.p50,
        "-",
    );

    if json {
        let metrics = ThroughputMetricsJson {
            transfer_bytes: total.transfer_bytes,
            messages: total.messages,
            msg_per_sec,
            bandwidth_bps,
            seal_us: seal,
            open_us: open,
        };

        let payload = BenchJson {
            mode: BenchMode::Throughput.as_str().to_string(),
            role: "client".to_string(),
            sender: Some(sender),
            receiver: Some(receiver),
            transport: Some(transport_url.to_string()),
            payload_size_bytes: Some(payload_size),
            session_id: None,
            session_duration_ms: None,
            duration_ms: duration.as_millis() as u64,
            interval_ms: interval.as_millis() as u64,
            timestamp_utc: timestamp_utc(),
            metrics,
        };

        println!(
            "{}",
            serde_json::to_string(&payload).map_err(|_| Error::Internal)?
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_client_latency(
    store: &AsyncSecureStore,
    wallet_name: &str,
    sender_alias_or_vid: &str,
    receiver_alias_or_vid: &str,
    transport_override: Option<&str>,
    payload_size: usize,
    duration: Duration,
    interval: Duration,
    warmup: Duration,
    ack_timeout: Duration,
    json: bool,
) -> Result<(), Error> {
    let sender = store.try_resolve_alias(sender_alias_or_vid)?;
    let receiver = store.try_resolve_alias(receiver_alias_or_vid)?;

    ensure_client_ready(store, &sender, &receiver, wallet_name)?;
    let transport_url = resolve_client_transport(store, &receiver, transport_override)?;
    let protocol = transport_url.scheme().to_ascii_uppercase();

    let listen_transport = resolve_private_transport(store, &sender)?;
    let mut incoming = transport::receive_messages(&listen_transport).await?;

    print_latency_header();

    let started_at = Instant::now();
    let mut last_report_at = Duration::ZERO;
    let mut total = LatencyStats::default();
    let mut window = LatencyStats::default();
    let mut seq = 0u64;
    let mut previous_rtt = None::<f64>;

    while started_at.elapsed() < duration {
        seq = seq.wrapping_add(1);

        let payload = build_frame(payload_size, FrameKind::LatencyRequest, seq);
        let seal_started = Instant::now();
        let (_, message) = store.seal_message(&sender, &receiver, None, &payload)?;
        let seal_us = seal_started.elapsed().as_secs_f64() * 1_000_000.0;
        let sent_bytes = message.len() as u64;

        let sent_at = Instant::now();
        transport::send_message(&transport_url, &message).await?;

        let ack = tokio::time::timeout(ack_timeout, incoming.next())
            .await
            .map_err(|_| {
                Error::Relationship(format!(
                    "timed out waiting for latency ACK after {}s",
                    ack_timeout.as_secs_f64()
                ))
            })?;

        let Some(ack) = ack else {
            return Err(Error::Relationship(
                "latency ACK stream closed unexpectedly".to_string(),
            ));
        };

        let mut raw = ack?;
        let opened = store.open_message(&mut raw)?;

        let mut accepted = false;
        if let ReceivedTspMessage::GenericMessage {
            sender: ack_sender,
            message,
            ..
        } = opened
            && ack_sender == receiver
            && let Some(frame) = parse_frame(message)
            && frame.kind == FrameKind::LatencyAck
            && frame.seq == seq
        {
            accepted = true;
        }

        if !accepted {
            continue;
        }

        let rtt_us = sent_at.elapsed().as_secs_f64() * 1_000_000.0;
        let jitter = previous_rtt.map(|prev| (rtt_us - prev).abs());
        previous_rtt = Some(rtt_us);

        let elapsed = started_at.elapsed();
        if elapsed > warmup {
            total.record(sent_bytes, seal_us, rtt_us, jitter);
            window.record(sent_bytes, seal_us, rtt_us, jitter);

            let measured_elapsed = elapsed.saturating_sub(warmup);
            if measured_elapsed.saturating_sub(last_report_at) >= interval && !window.is_empty() {
                let window_elapsed = measured_elapsed.saturating_sub(last_report_at);
                print_latency_line(0, window_elapsed, &window, &protocol);
                window.reset();
                last_report_at = measured_elapsed;
            }
        }
    }

    let total_elapsed = started_at.elapsed();
    let measured_elapsed = total_elapsed.saturating_sub(warmup);
    if !window.is_empty() {
        let window_elapsed = measured_elapsed.saturating_sub(last_report_at);
        if !window_elapsed.is_zero() {
            print_latency_line(0, window_elapsed, &window, &protocol);
        }
    }

    let elapsed_s = measured_elapsed.as_secs_f64().max(f64::EPSILON);
    let msg_per_sec = total.messages as f64 / elapsed_s;
    let bandwidth_bps = total.transfer_bytes as f64 * 8.0 / elapsed_s;
    let seal = summarize(&total.seal_us);
    let rtt = summarize_with_stddev(&total.rtt_us);
    let jitter = summarize_jitter(&total.jitter_us);

    println!(
        "[SUM] {:>5.1} sec {:>6} {:>8} RTT avg/p95/p99 {:>7.1}/{:>7.1}/{:>7.1} us jitter p95 {:>7.1} us",
        measured_elapsed.as_secs_f64(),
        protocol,
        total.messages,
        rtt.avg,
        rtt.p95,
        rtt.p99,
        jitter.p95,
    );

    if json {
        let metrics = LatencyMetricsJson {
            messages: total.messages,
            transfer_bytes: total.transfer_bytes,
            msg_per_sec,
            bandwidth_bps,
            seal_us: seal,
            rtt_us: rtt,
            jitter_us: jitter,
        };

        let payload = BenchJson {
            mode: BenchMode::Latency.as_str().to_string(),
            role: "client".to_string(),
            sender: Some(sender),
            receiver: Some(receiver),
            transport: Some(transport_url.to_string()),
            payload_size_bytes: Some(payload_size),
            session_id: None,
            session_duration_ms: None,
            duration_ms: duration.as_millis() as u64,
            interval_ms: interval.as_millis() as u64,
            timestamp_utc: timestamp_utc(),
            metrics,
        };

        println!(
            "{}",
            serde_json::to_string(&payload).map_err(|_| Error::Internal)?
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_default_client_identities() -> AsyncSecureStore {
        let store = AsyncSecureStore::new();
        maybe_bootstrap_client_profile_defaults(&store, BenchProfile::LocalTcp, "alice", "bob")
            .unwrap();
        store
    }

    fn store_with_hosted_http_client_identities() -> AsyncSecureStore {
        let store = AsyncSecureStore::new();
        maybe_bootstrap_client_profile_defaults(&store, BenchProfile::HostedHttp, "a", "b")
            .unwrap();
        store
    }

    #[test]
    fn parse_payload_size_ok() {
        assert_eq!(parse_payload_size("16B").unwrap(), 16);
        assert_eq!(parse_payload_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_payload_size("2MiB").unwrap(), 2 * 1024 * 1024);
    }

    #[test]
    fn parse_payload_size_invalid() {
        assert!(parse_payload_size("0B").is_err());
        assert!(parse_payload_size("15B").is_err());
        assert!(parse_payload_size("1XB").is_err());
    }

    #[test]
    fn parse_duration_ok() {
        assert_eq!(
            parse_duration_nonzero("500ms", "duration").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration_nonzero("30s", "duration").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration_nonzero("2m", "duration").unwrap(),
            Duration::from_secs(120)
        );
        assert_eq!(
            parse_duration_allow_zero("0s", "warmup").unwrap(),
            Duration::from_secs(0)
        );
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration_nonzero("0s", "duration").is_err());
        assert!(parse_duration_nonzero("1fortnight", "duration").is_err());
        assert!(parse_duration_nonzero("abc", "duration").is_err());
    }

    #[test]
    fn parse_transport_schemes() {
        assert!(parse_transport("tcp://127.0.0.1:7777").is_ok());
        assert!(parse_transport("http://127.0.0.1:3000/endpoint").is_ok());
        assert!(parse_transport("https://example.com/transport").is_ok());
        assert!(parse_transport("udp://127.0.0.1:9999").is_err());
    }

    #[test]
    fn resolve_transport_from_receiver_vid() {
        let store = store_with_default_client_identities();
        let receiver = store.try_resolve_alias("bob").unwrap();

        let transport = resolve_client_transport(&store, &receiver, None).unwrap();

        assert_eq!(transport.scheme(), "tcp");
        assert_eq!(transport.host_str(), Some("127.0.0.1"));
        assert_eq!(transport.port(), Some(13372));
    }

    #[test]
    fn reject_mismatched_transport_override() {
        let store = store_with_default_client_identities();
        let receiver = store.try_resolve_alias("bob").unwrap();

        let err = resolve_client_transport(&store, &receiver, Some("tcp://127.0.0.1:17777"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("does not match receiver endpoint"));
    }

    #[test]
    fn bootstrap_local_tcp_server_defaults_loads_private_bob() {
        let store = AsyncSecureStore::new();
        maybe_bootstrap_server_profile_defaults(&store, BenchProfile::LocalTcp, "bob").unwrap();

        let bob = store.try_resolve_alias("bob").unwrap();
        let alice = store.try_resolve_alias("alice").unwrap();

        assert!(store.has_private_vid(&bob).unwrap());
        assert!(store.has_verified_vid(&alice).unwrap());
        assert!(!matches!(
            store.get_relation_status_for_vid_pair(&bob, &alice),
            Ok(RelationshipStatus::Unrelated)
        ));
    }

    #[test]
    fn bootstrap_hosted_http_defaults_loads_a_and_b() {
        let store = store_with_hosted_http_client_identities();
        let a = store.try_resolve_alias("a").unwrap();
        let b = store.try_resolve_alias("b").unwrap();

        assert!(store.has_private_vid(&a).unwrap());
        assert!(store.has_verified_vid(&b).unwrap());
        assert!(!matches!(
            store.get_relation_status_for_vid_pair(&a, &b),
            Ok(RelationshipStatus::Unrelated)
        ));
    }

    #[test]
    fn profile_default_aliases_match_expected() {
        assert_eq!(BenchProfile::LocalTcp.default_client_sender(), "alice");
        assert_eq!(BenchProfile::LocalTcp.default_client_receiver(), "bob");
        assert_eq!(BenchProfile::HostedHttp.default_client_sender(), "a");
        assert_eq!(BenchProfile::HostedHttp.default_client_receiver(), "b");
    }

    #[test]
    fn server_subcommand_uses_default_vid_without_args() {
        use clap::Parser;

        #[derive(Parser)]
        struct BenchCliForTest {
            #[command(subcommand)]
            sub: BenchSubcommand,
        }

        let parsed = BenchCliForTest::parse_from(["bench-test", "server"]);
        match parsed.sub {
            BenchSubcommand::Server {
                profile,
                vid,
                interval,
                ..
            } => {
                assert_eq!(profile, BenchProfile::LocalTcp);
                assert!(vid.is_none());
                assert_eq!(interval, "1s");
            }
            _ => panic!("expected server subcommand"),
        }
    }

    #[test]
    fn percentile_and_stddev() {
        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(percentile(&values, 50.0), 30.0);
        assert!(stddev(&values) > 0.0);
    }

    #[test]
    fn frame_roundtrip() {
        let payload = build_frame(64, FrameKind::LatencyRequest, 42);
        let frame = parse_frame(&payload).unwrap();
        assert_eq!(frame.kind, FrameKind::LatencyRequest);
        assert_eq!(frame.seq, 42);
    }

    #[test]
    fn server_session_split_uses_idle_gap_threshold() {
        let interval = Duration::from_secs(1);
        assert!(!should_split_server_session(
            Duration::from_millis(1999),
            interval
        ));
        assert!(should_split_server_session(
            Duration::from_millis(2000),
            interval
        ));
    }

    #[test]
    fn server_window_emission_requires_full_interval() {
        let interval = Duration::from_secs(1);
        let mut non_empty = ThroughputStats::default();
        non_empty.record_recv(1024, 10.0);

        assert!(!should_emit_server_window(
            &non_empty,
            Duration::from_millis(100),
            interval
        ));
        assert!(should_emit_server_window(
            &non_empty,
            Duration::from_secs(1),
            interval
        ));
        assert!(!should_emit_server_window(
            &ThroughputStats::default(),
            Duration::from_secs(1),
            interval
        ));
    }

    #[test]
    fn server_json_session_fields_are_serialized() {
        let payload = BenchJson {
            mode: "server".to_string(),
            role: "server".to_string(),
            sender: None,
            receiver: Some("did:web:example:bob".to_string()),
            transport: Some("tcp://127.0.0.1:13372".to_string()),
            payload_size_bytes: None,
            session_id: Some(7),
            session_duration_ms: Some(3210),
            duration_ms: 3210,
            interval_ms: 1000,
            timestamp_utc: "0".to_string(),
            metrics: ThroughputMetricsJson {
                transfer_bytes: 1,
                messages: 1,
                msg_per_sec: 1.0,
                bandwidth_bps: 8.0,
                seal_us: summarize(&[]),
                open_us: summarize(&[]),
            },
        };

        let value = serde_json::to_value(payload).unwrap();
        assert_eq!(value["session_id"], 7);
        assert_eq!(value["session_duration_ms"], 3210);
    }
}
