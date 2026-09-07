//! HTTP surface: axum router, handlers, `Config`, `TestServer`.
//!
//! Reads are public (an archive's whole point is re-serving);
//! mutations and the audit log require a Bearer token when
//! `UNIDPP_ARCHIVE_ADMIN_TOKEN` is set (open in dev mode, mirroring
//! the registry/trust services). Every read is as-of stamped
//! (`x-as-of` header + `as_of` JSON field); point-in-time responses
//! (`?at=...`) are `immutable` and cacheable forever, and snapshot
//! re-serves carry a strong `ETag` derived from the body digest.
//!
//! Endpoints:
//!
//! | Endpoint | Meaning |
//! |---|---|
//! | `GET /` | discovery document (OAIS mapping, notarization recipe) |
//! | `GET /healthz` | liveness |
//! | `GET /keyring` | the notary anchor a verifier pins |
//! | `POST /snapshots` | ingest: notarize an as-of snapshot (SIP → AIP) |
//! | `GET /snapshots/{id}` | access: re-serve the AIP byte-identically |
//! | `GET /snapshots?passport_id=&at=` | data management: as-of listing |
//! | `GET /admin/log?limit=&offset=` | append-only audit journal |
//!
//! ## Create flow (OAIS ingest)
//!
//! `POST /snapshots` with `{passport_id, state_hash, log_head,
//! submitter?, state_size?}`: reserve a sequence + notarization
//! instant, optionally anchor the statement commitment into the
//! transparency log (fallback: unanchored with reason), seal the
//! record (Ed25519 signature over the canonical statement bytes),
//! journal it, materialize the AIP file, and return the document
//! with `201` + `Location` + a strong `ETag`. The whole flow is
//! serialized behind a mutation lock so sequence numbers and journal
//! order cannot interleave.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use crate::keyring::Keyring;
use crate::log_anchor::{self, LogAnchorConfig};
use crate::model::{
    anchor_summary_from_receipt, Anchoring, SnapshotRecord, ADAPTER_NOTE, OAIS_PROFILE, SCHEMA,
    SERVICE_ID,
};
use crate::store::{SnapshotStore, StoreError};
use crate::time::Timestamp;
use unidpp_model::Hash;

/// Default bind (8095 — after registry 8090, issuer 8091,
/// trust/log 8092).
pub const DEFAULT_BIND: &str = "127.0.0.1:8095";

/// Cache strategy for a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// Current-state response (default): short cache with
    /// revalidation.
    Current,
    /// Point-in-time or immutable-document response: the body is
    /// fixed for a given input — `immutable, max-age=86400`.
    PointInTime,
    /// Mutation response: never store.
    NoStore,
}

impl CachePolicy {
    /// The `cache-control` header value for this policy.
    pub fn header_value(self) -> &'static str {
        match self {
            CachePolicy::Current => "public, max-age=30, must-revalidate",
            CachePolicy::PointInTime => "public, max-age=86400, immutable",
            CachePolicy::NoStore => "no-store",
        }
    }
}

/// Deployment configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Listen address (`UNIDPP_ARCHIVE_BIND`).
    pub bind: SocketAddr,
    /// Bearer token guarding mutations and `/admin/*`; `None` = open
    /// (dev mode).
    pub admin_token: Option<String>,
    /// Optional JSONL journal file (append-only, replayed on start).
    pub state_file: Option<PathBuf>,
    /// Optional snapshot directory (the AIP files; verified and
    /// re-materialized on replay).
    pub snapshot_dir: Option<PathBuf>,
    /// The deterministic dev seed when env-key mode is unavailable.
    pub dev_seed: Option<String>,
    /// Transparency-log anchoring configuration (`UNIDPP_LOG_URL`).
    pub log: LogAnchorConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: DEFAULT_BIND.parse().unwrap(),
            admin_token: None,
            state_file: None,
            snapshot_dir: None,
            dev_seed: None,
            log: LogAnchorConfig::disabled(),
        }
    }
}

impl Config {
    /// Resolve the configuration from environment variables.
    pub fn from_env() -> Config {
        let mut c = Config::default();
        if let Ok(bind) = std::env::var("UNIDPP_ARCHIVE_BIND") {
            match bind.parse() {
                Ok(addr) => c.bind = addr,
                Err(_) => eprintln!("unidpp-archive: ignoring bad UNIDPP_ARCHIVE_BIND `{bind}`"),
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_ARCHIVE_ADMIN_TOKEN") {
            if !token.is_empty() {
                c.admin_token = Some(token);
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_ARCHIVE_STATE_FILE") {
            if !path.is_empty() {
                c.state_file = Some(PathBuf::from(path));
            }
        }
        if let Ok(path) = std::env::var("UNIDPP_ARCHIVE_SNAPSHOT_DIR") {
            if !path.is_empty() {
                c.snapshot_dir = Some(PathBuf::from(path));
            }
        }
        if let Ok(seed) = std::env::var("UNIDPP_ARCHIVE_DEV_SEED") {
            if !seed.is_empty() {
                c.dev_seed = Some(seed);
            }
        }
        c.log = LogAnchorConfig::from_env();
        c
    }
}

/// Shared application state.
pub struct AppState {
    /// Deployment configuration.
    pub config: Config,
    /// The snapshot store behind a mutex (journal + index + files).
    pub store: Mutex<SnapshotStore>,
    /// The service notary keyring.
    pub keyring: Keyring,
    /// Serializes the create flow (reserve → anchor → seal → append)
    /// so sequences and journal order cannot interleave across
    /// concurrent requests. Tokio mutex: the anchor hop awaits.
    mutations: tokio::sync::Mutex<()>,
}

impl AppState {
    /// Open the store (journal replay + AIP verification) and hold
    /// the resolved keyring.
    pub fn new(config: Config, keyring: Keyring) -> Result<AppState, StoreError> {
        let store =
            SnapshotStore::open(config.state_file.as_deref(), config.snapshot_dir.as_deref())?;
        Ok(AppState {
            config,
            store: Mutex::new(store),
            keyring,
            mutations: tokio::sync::Mutex::new(()),
        })
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn build_response(
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: String,
    cache: CachePolicy,
) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .header("cache-control", cache.header_value())
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

fn json_response(
    status: StatusCode,
    doc: &Value,
    as_of: Timestamp,
    cache: CachePolicy,
) -> Response {
    let body = serde_json::to_string_pretty(doc).unwrap();
    build_response(
        status,
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-as-of".into(), as_of.to_string()),
        ],
        body,
        cache,
    )
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    json_response(
        status,
        &json!({ "error": msg }),
        Timestamp::now(),
        CachePolicy::NoStore,
    )
}

fn bad_request(msg: &str) -> Response {
    error_response(StatusCode::BAD_REQUEST, msg)
}

fn not_found(msg: &str) -> Response {
    error_response(StatusCode::NOT_FOUND, msg)
}

fn store_error(e: StoreError) -> Response {
    match e {
        StoreError::Journal(m) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("storage integrity failure: {m}"),
        ),
        StoreError::Conflict(m) => error_response(StatusCode::CONFLICT, &m),
    }
}

fn require_admin(app: &AppState, headers: &HeaderMap) -> Option<Response> {
    let token = app.config.admin_token.as_ref()?;
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got == Some(token.as_str()) {
        None
    } else {
        Some(error_response(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

// ---------------------------------------------------------------------------
// Body/query parsing (registry parity)
// ---------------------------------------------------------------------------

fn parse_body(body: &str) -> Result<Value, String> {
    serde_json::from_str(body).map_err(|e| format!("invalid JSON body: {e}"))
}

fn req_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("`{key}` is required"))
}

fn opt_str(v: &Value, key: &str) -> Result<Option<String>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                return Err(format!("`{key}` must not be blank"));
            }
            if t.len() > 512 {
                return Err(format!("`{key}` must be at most 512 characters"));
            }
            Ok(Some(t.to_string()))
        }
        Some(_) => Err(format!("`{key}` must be a string")),
    }
}

fn opt_u64(v: &Value, key: &str) -> Result<Option<u64>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("`{key}` must be an unsigned integer")),
        Some(_) => Err(format!("`{key}` must be an unsigned integer")),
    }
}

fn req_hash(v: &Value, key: &str) -> Result<Hash, String> {
    req_str(v, key).and_then(|s| {
        Hash::from_hex(&s)
            .ok_or_else(|| format!("`{key}` must be a 64-character hex SHA-256 value"))
    })
}

fn validate_passport_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 512 {
        return Err("`passport_id` must be 1-512 characters".into());
    }
    if id.chars().any(|c| c.is_control()) {
        return Err("`passport_id` must not contain control characters".into());
    }
    Ok(())
}

fn parse_at(params: &HashMap<String, String>) -> Result<Option<Timestamp>, String> {
    let raw = params
        .get("at")
        .or_else(|| params.get("asof"))
        .map(String::as_str);
    match raw {
        None | Some("") => Ok(None),
        Some(s) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| format!("invalid `at` parameter: {e}")),
    }
}

fn opt_query(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params
        .get(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn cache_for(at: Option<Timestamp>) -> CachePolicy {
    if at.is_some() {
        CachePolicy::PointInTime
    } else {
        CachePolicy::Current
    }
}

/// A parsed ingest request (the SIP).
struct CreateRequest {
    passport_id: String,
    state_hash: Hash,
    log_head: Hash,
    submitter: Option<String>,
    state_size: Option<u64>,
}

fn parse_create_request(v: &Value) -> Result<CreateRequest, String> {
    let passport_id = req_str(v, "passport_id")?;
    validate_passport_id(&passport_id)?;
    Ok(CreateRequest {
        passport_id,
        state_hash: req_hash(v, "state_hash")?,
        log_head: req_hash(v, "log_head")?,
        submitter: opt_str(v, "submitter")?,
        state_size: opt_u64(v, "state_size")?,
    })
}

// ---------------------------------------------------------------------------
// Handlers — discovery / health / keyring
// ---------------------------------------------------------------------------

async fn discovery(State(app): State<Arc<AppState>>) -> Response {
    let body = json!({
        "service": SERVICE_ID,
        "description": "UniDPP Tier-C notarized archive: as-of snapshot packs with OAIS-style metadata, Ed25519 notarization, optional transparency-log anchoring, byte-identical re-serving.",
        "schema": SCHEMA,
        "anchoring_enabled": app.config.log.is_enabled(),
        "oais": {
            "profile": OAIS_PROFILE,
            "mapping": {
                "producer": "the issuer submitting {passport_id, state_hash, log_head} (POST /snapshots body = the SIP)",
                "ingest": "POST /snapshots: validate, timestamp, notarize (sign), optionally anchor into the transparency log",
                "archival_storage": "the JSONL journal (source of truth) + one AIP file per snapshot under the snapshot directory",
                "data_management": "GET /snapshots?passport_id=&at= — the as-of catalogue",
                "access": "GET /snapshots/{id} — re-serves the AIP byte-identically (access never changes the AIP)",
                "administration": "GET /keyring, GET /admin/log, Bearer-guarded ingest",
                "document_sections": {
                    "oais.submission": "the SIP: submitter, submitted_at, and the submitted {passport_id, state_hash, log_head, state_size}",
                    "oais.information_package": "the AIP content: passport state, log head, the as_of instant, the commitment and statement digests",
                    "oais.provenance": "the PDI: notarization (key id, signature), anchoring outcome and the verbatim log receipt"
                }
            }
        },
        "endpoints": {
            "discovery": "GET /",
            "health": "GET /healthz",
            "keyring": "GET /keyring",
            "ingest": "POST /snapshots",
            "snapshot": "GET /snapshots/{id}",
            "listing": "GET /snapshots?passport_id=&at=",
            "admin_log": "GET /admin/log?limit=&offset="
        },
        "notarization": {
            "suite": "ed25519",
            "domain": "tree-head",
            "adapter_note": ADAPTER_NOTE,
            "keyring_endpoint": "/keyring",
            "statement_recipe": [
                "core = CanonicalWriter: str(\"unidpp-archive\"), str(snapshot_id), u64(seq), str(oais.information_package.passport_id), hash(state_hash), hash(log_head), i64(as_of.secs)",
                "if oais.provenance.anchoring.status == \"anchored\": append u32(1), str(anchoring.log_id), u64(anchoring.receipt_id), u64(anchoring.tree_size), hash(anchoring.root); else append u32(0)",
                "verify: SignatureSlot{suite: ed25519, key_id: oais.provenance.signing.key_id, signature: hex(oais.provenance.signature)}.verify(SigningDomain::TreeHead, statement, public from /keyring)",
                "commitment check: sha256(core) == oais.information_package.commitment (and == oais.provenance.receipt.commitment when anchored)"
            ]
        },
        "anchoring": {
            "when": "UNIDPP_LOG_URL points at a reachable unidpp-log instance",
            "how": "POST {UNIDPP_LOG_URL}/commitments with {subject: urn:unidpp:archive:snapshot:<id>, commitment: sha256(core statement bytes)}",
            "journalled": "receipt id, log id, tree size, root, logged_at, and the verbatim receipt ride the snapshot's provenance and the audit journal",
            "fallback": "an unreachable or refusing log degrades to status=unanchored with the reason recorded; the snapshot remains notarized"
        },
        "storage": {
            "journal": "append-only JSONL (UNIDPP_ARCHIVE_STATE_FILE); replay on start with sequence, digest and torn-tail checks",
            "snapshot_store": "one JSON file per snapshot (UNIDPP_ARCHIVE_SNAPSHOT_DIR); verified against the journal on start, re-materialized when missing, mismatch is a hard error",
            "re_serve": "GET /snapshots/{id} re-renders from the journaled record — byte-identical by construction, pinned by the strong ETag"
        },
        "as_of": {
            "query_parameter": "at (alias: asof)",
            "response_header": "x-as-of",
            "listing_rule": "a snapshot is listed at instant T when notarized_at <= T",
            "point_in_time_cache": "responses to ?at=... carry cache-control: public, max-age=86400, immutable"
        },
        "auth": "POST /snapshots and /admin/log require a Bearer token when UNIDPP_ARCHIVE_ADMIN_TOKEN is set"
    });
    json_response(
        StatusCode::OK,
        &body,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

async fn healthz(State(app): State<Arc<AppState>>) -> Response {
    let size = {
        let store = app.store.lock().expect("store poisoned");
        store.size()
    };
    let body = json!({
        "status": "ok",
        "service": SERVICE_ID,
        "snapshots": size,
        "anchoring_enabled": app.config.log.is_enabled(),
        "as_of": Timestamp::now().to_string(),
    });
    json_response(
        StatusCode::OK,
        &body,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

async fn keyring(State(app): State<Arc<AppState>>) -> Response {
    let mut v = app.keyring.to_json();
    if let Some(m) = v.as_object_mut() {
        m.insert("as_of".into(), json!(Timestamp::now().to_string()));
    }
    json_response(
        StatusCode::OK,
        &v,
        Timestamp::now(),
        CachePolicy::PointInTime,
    )
}

// ---------------------------------------------------------------------------
// Handlers — ingest (POST /snapshots)
// ---------------------------------------------------------------------------

async fn create_snapshot(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let v = match parse_body(&body) {
        Ok(v) => v,
        Err(e) => return bad_request(&e),
    };
    let req = match parse_create_request(&v) {
        Ok(r) => r,
        Err(e) => return bad_request(&e),
    };

    // Serialize the whole ingest (reserve → anchor → seal → append).
    let _guard = app.mutations.lock().await;

    let (seq, notarized_at) = {
        let store = app.store.lock().expect("store poisoned");
        store.reserve()
    };
    let mut record = SnapshotRecord::new(
        seq,
        notarized_at,
        req.passport_id.clone(),
        req.state_hash,
        req.log_head,
        req.submitter,
        req.state_size,
    );

    // The optional anchoring hop (awaits — hence the tokio lock).
    let commitment = record.commitment();
    let subject = format!("urn:unidpp:archive:snapshot:{}", record.snapshot_id);
    let anchoring = match log_anchor::anchor(&app.config.log, &subject, commitment).await {
        Ok(receipt) => match anchor_summary_from_receipt(&receipt) {
            Ok(summary) => Anchoring::anchored(summary, receipt, commitment),
            Err(e) => Anchoring::unanchored(format!("log receipt rejected: {e}")),
        },
        Err(e) => Anchoring::unanchored(e),
    };
    record.set_anchoring(anchoring);

    if let Err(e) = record.seal(app.keyring.notary()) {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("notarization failed: {e}"),
        );
    }
    let body = record.render_body();
    let etag = format!("\"sha-{}\"", &record.body_digest.hex()[..32]);
    let snapshot_id = record.snapshot_id.clone();
    {
        let mut store = app.store.lock().expect("store poisoned");
        if let Err(e) = store.append_snapshot(&record) {
            return store_error(e);
        }
    }
    let mut headers = vec![
        ("content-type".into(), "application/json".into()),
        ("location".into(), format!("/snapshots/{snapshot_id}")),
        ("x-snapshot-id".into(), snapshot_id),
        ("x-as-of".into(), notarized_at.to_string()),
        ("etag".into(), etag),
    ];
    if record.anchoring.status == crate::model::AnchoringStatus::Anchored {
        headers.push((
            "x-anchored-receipt".into(),
            record
                .anchoring
                .receipt_seq
                .map(|s| s.to_string())
                .unwrap_or_default(),
        ));
    }
    build_response(StatusCode::CREATED, headers, body, CachePolicy::PointInTime)
}

// ---------------------------------------------------------------------------
// Handlers — access (GET /snapshots/{id}) and listing
// ---------------------------------------------------------------------------

async fn get_snapshot(State(app): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let id = id.trim().to_string();
    let found = {
        let store = app.store.lock().expect("store poisoned");
        store
            .get(&id)
            .map(|r| (r.render_body(), r.body_digest.hex(), r.notarized_at))
    };
    match found {
        Some((body, digest, as_of)) => build_response(
            StatusCode::OK,
            vec![
                ("content-type".into(), "application/json".into()),
                ("x-as-of".into(), as_of.to_string()),
                ("etag".into(), format!("\"sha-{}\"", &digest[..32])),
            ],
            body,
            // The AIP is immutable: re-serves are cacheable forever.
            CachePolicy::PointInTime,
        ),
        None => not_found(&format!("no snapshot `{id}`")),
    }
}

async fn list_snapshots(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let at = match parse_at(&params) {
        Ok(v) => v,
        Err(e) => return bad_request(&e),
    };
    let as_of = at.unwrap_or_else(Timestamp::now);
    let passport_id = opt_query(&params, "passport_id");
    let rows = {
        let store = app.store.lock().expect("store poisoned");
        store
            .list(passport_id.as_deref(), at)
            .into_iter()
            .map(|r| {
                json!({
                    "snapshot_id": r.snapshot_id,
                    "seq": r.seq,
                    "passport_id": r.passport_id,
                    "state_hash": r.state_hash.hex(),
                    "log_head": r.log_head.hex(),
                    "notarized_at": r.notarized_at.to_string(),
                    "anchored": r.anchoring.status == crate::model::AnchoringStatus::Anchored,
                    "log_id": r.anchoring.log_id,
                    "receipt_id": r.anchoring.receipt_seq.map(|s| s.to_string()),
                    "tree_size": r.anchoring.tree_size,
                    "root": r.anchoring.root.map(|h| h.hex()),
                    "body_sha256": r.body_digest.hex(),
                    "href": format!("/snapshots/{}", r.snapshot_id),
                })
            })
            .collect::<Vec<_>>()
    };
    let body = json!({
        "as_of": as_of.to_string(),
        "query": {
            "at": at.map(|t| t.to_string()),
            "passport_id": passport_id,
        },
        "count": rows.len(),
        "snapshots": rows,
    });
    json_response(StatusCode::OK, &body, as_of, cache_for(at))
}

// ---------------------------------------------------------------------------
// Handlers — admin
// ---------------------------------------------------------------------------

async fn admin_log(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(deny) = require_admin(&app, &headers) {
        return deny;
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(10_000);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let view = {
        let store = app.store.lock().expect("store poisoned");
        store.audit_json(limit, offset)
    };
    json_response(
        StatusCode::OK,
        &view,
        Timestamp::now(),
        CachePolicy::Current,
    )
}

// ---------------------------------------------------------------------------
// Router + run
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(discovery))
        .route("/healthz", get(healthz))
        .route("/keyring", get(keyring))
        .route("/snapshots", get(list_snapshots).post(create_snapshot))
        .route("/snapshots/{id}", get(get_snapshot))
        .route("/admin/log", get(admin_log))
        .with_state(app)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let (keyring, warnings) = Keyring::from_env(config.dev_seed.as_deref());
    for w in &warnings {
        eprintln!("unidpp-archive: {w}");
    }
    if keyring.mode() == crate::keyring::KeyringMode::SeededDev {
        eprintln!(
            "unidpp-archive: WARNING running with seeded-dev keyring \
             (set UNIDPP_ARCHIVE_SIGN_SEED for production)"
        );
    }
    if !config.log.is_enabled() {
        eprintln!(
            "unidpp-archive: log anchoring disabled (set UNIDPP_LOG_URL to anchor snapshots)"
        );
    }
    let app = Arc::new(AppState::new(config.clone(), keyring)?);
    let size = app.store.lock().expect("store poisoned").size();
    let listener = TcpListener::bind(config.bind).await?;
    eprintln!(
        "unidpp-archive listening on http://{} ({} snapshots replayed)",
        config.bind, size
    );
    axum::serve(listener, router(app)).await?;
    Ok(())
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    pub addr: SocketAddr,
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

/// Manual `Debug` (contains a oneshot sender and a join handle that
/// have nothing useful to print; the addr is what tests care about).
impl std::fmt::Debug for TestServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestServer")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl TestServer {
    pub async fn spawn(config: Config) -> Result<TestServer, StoreError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| StoreError::Journal(format!("cannot bind test listener: {e}")))?;
        let addr = listener
            .local_addr()
            .map_err(|e| StoreError::Journal(format!("no local addr: {e}")))?;
        let (keyring, _warnings) = Keyring::from_env(config.dev_seed.as_deref());
        let app = Arc::new(AppState::new(config, keyring)?);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-archive: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

// Unit-level sanity on the wire helpers that do not need a server.
#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::sha256;

    #[test]
    fn create_request_validation() {
        let good = json!({
            "passport_id": "urn:unidpp:passport:e8",
            "state_hash": sha256(&[b"s"]).hex(),
            "log_head": sha256(&[b"h"]).hex(),
            "submitter": "urn:unidpp:actor:issuer-1",
            "state_size": 2048,
        });
        let r = parse_create_request(&good).unwrap();
        assert_eq!(r.passport_id, "urn:unidpp:passport:e8");
        assert_eq!(r.state_hash, sha256(&[b"s"]));
        assert_eq!(r.log_head, sha256(&[b"h"]));
        assert_eq!(r.submitter.as_deref(), Some("urn:unidpp:actor:issuer-1"));
        assert_eq!(r.state_size, Some(2048));
        // Optionals may be omitted entirely.
        let minimal = json!({
            "passport_id": "p",
            "state_hash": sha256(&[b"s"]).hex(),
            "log_head": sha256(&[b"h"]).hex(),
        });
        let r = parse_create_request(&minimal).unwrap();
        assert!(r.submitter.is_none() && r.state_size.is_none());
        // Rejections.
        assert!(parse_create_request(&json!({"state_hash": "00", "log_head": "00"})).is_err());
        assert!(parse_create_request(&json!({
            "passport_id": "p", "state_hash": "nothex", "log_head": "00",
        }))
        .is_err());
        assert!(parse_create_request(&json!({
            "passport_id": "p",
            "state_hash": sha256(&[b"s"]).hex(),
            "log_head": sha256(&[b"h"]).hex(),
            "state_size": -1,
        }))
        .is_err());
        let long = "x".repeat(513);
        assert!(parse_create_request(&json!({
            "passport_id": long,
            "state_hash": sha256(&[b"s"]).hex(),
            "log_head": sha256(&[b"h"]).hex(),
        }))
        .is_err());
        let blank_submitter = json!({
            "passport_id": "p",
            "state_hash": sha256(&[b"s"]).hex(),
            "log_head": sha256(&[b"h"]).hex(),
            "submitter": "  ",
        });
        assert!(parse_create_request(&blank_submitter).is_err());
    }

    #[test]
    fn at_parameter_parsing() {
        let mut params = HashMap::new();
        assert_eq!(parse_at(&params).unwrap(), None);
        params.insert("at".to_string(), String::new());
        assert_eq!(parse_at(&params).unwrap(), None);
        params.insert("at".to_string(), "2026-09-07T10:00:00Z".into());
        let t = parse_at(&params).unwrap().unwrap();
        assert_eq!(t, Timestamp::parse("2026-09-07T10:00:00Z").unwrap());
        // The `asof` alias.
        let mut alias = HashMap::new();
        alias.insert("asof".to_string(), "2026-09-07".into());
        assert!(parse_at(&alias).unwrap().is_some());
        params.insert("at".to_string(), "garbage".into());
        assert!(parse_at(&params).is_err());
    }

    #[test]
    fn cache_policy_switches_on_at() {
        assert_eq!(cache_for(None), CachePolicy::Current);
        assert_eq!(
            cache_for(Some(Timestamp::UNIX_EPOCH)),
            CachePolicy::PointInTime
        );
    }
}
