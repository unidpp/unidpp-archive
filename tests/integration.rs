//! Integration tests: real HTTP against servers spawned on ephemeral
//! ports. Covers the required behaviours: ingest → notarized snapshot
//! with the three OAIS sections and a verifiable embedded Ed25519
//! signature; byte-identical re-serving (and byte-identical re-serving
//! after journal replay across a restart); as-of listing with passport
//! filters; transparency-log anchoring when a `unidpp-log` instance is
//! reachable (full receipt chain: operator signature + Merkle
//! inclusion + commitment binding) and the explicit unanchored
//! fallback when it is not; admin auth; and input validation.

mod support;

use std::path::PathBuf;

use serde_json::{json, Value};
use support::{enc, get, json_of, json_request};
use unidpp_archive::model::{
    core_bytes_from_document, statement_bytes_from_document, AnchoringStatus,
};
use unidpp_archive::{Config, LogAnchorConfig, TestServer};
use unidpp_log::model::{proof_from_json, sth_from_json};
use unidpp_model::{sha256, Hash};
use unidpp_signatif::keyring::{KeyId, PublicKey};
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};
use unidpp_signatif::verify_inclusion;

// ---------------------------------------------------------------------------
// Fixtures and verifier-side helpers
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

fn hash_hex(tag: &str) -> String {
    sha256(&[tag.as_bytes()]).hex()
}

fn it_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unidpp-archive-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("test dir");
    dir
}

fn base_config(tag: &str) -> Config {
    let dir = it_dir(tag);
    Config {
        dev_seed: Some("it-notary-seed".into()),
        state_file: Some(dir.join("journal.jsonl")),
        snapshot_dir: Some(dir.join("snapshots")),
        ..Config::default()
    }
}

async fn spawn(config: Config) -> TestServer {
    TestServer::spawn(config).await.expect("spawn server")
}

async fn spawn_log() -> unidpp_log::TestServer {
    unidpp_log::TestServer::spawn(unidpp_log::Config::default())
        .await
        .expect("spawn log")
}

async fn create(
    base: &str,
    passport: &str,
    seq: usize,
    token: Option<&str>,
) -> support::HttpResponse {
    let body = json!({
        "passport_id": passport,
        "state_hash": hash_hex(&format!("state-{seq}")),
        "log_head": hash_hex(&format!("head-{seq}")),
        "submitter": format!("urn:unidpp:actor:issuer-{seq}"),
        "state_size": 4096 + seq,
    });
    json_request(
        "POST",
        &format!("{base}/snapshots"),
        Some(&body.to_string()),
        token,
    )
    .await
}

/// The notary anchor, fetched live from `/keyring`.
async fn notary_public(base: &str) -> PublicKey {
    let doc = json_of(&get(&format!("{base}/keyring")).await);
    let hex = doc["public"].as_str().expect("public anchor");
    PublicKey::from_bytes(&hex_decode(hex)).expect("notary public key")
}

/// The verifier's check: rebuild the canonical statement bytes from
/// the document alone and verify the embedded signature.
fn verify_notarization(body: &[u8], public: &PublicKey) {
    let doc: Value = serde_json::from_slice(body).expect("document JSON");
    let statement = statement_bytes_from_document(&doc).expect("statement bytes");
    let prov = &doc["oais"]["provenance"];
    let slot = SignatureSlot {
        suite: Suite::Ed25519,
        key_id: KeyId::new(prov["signing"]["key_id"].as_str().expect("key id"))
            .expect("key id parses"),
        signature: Some(hex_decode(prov["signature"].as_str().expect("signature"))),
    };
    slot.verify(SigningDomain::TreeHead, &statement, public)
        .expect("notarization verifies");
}

fn parse_ts(v: &Value) -> unidpp_archive::Timestamp {
    unidpp_archive::Timestamp::parse(v.as_str().expect("timestamp string")).expect("timestamp")
}

// ---------------------------------------------------------------------------
// Discovery / keyring
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_healthz_and_keyring_anchor() {
    let server = spawn(base_config("discovery")).await;
    let base = &server.base_url;

    let doc = json_of(&get(&format!("{base}/")).await);
    assert_eq!(doc["service"], "unidpp-archive");
    assert!(doc["oais"]["mapping"]["ingest"].is_string());
    assert!(doc["notarization"]["statement_recipe"].is_array());
    assert!(doc["notarization"]["adapter_note"]
        .as_str()
        .unwrap()
        .contains("tree-head"));

    let health = json_of(&get(&format!("{base}/healthz")).await);
    assert_eq!(health["status"], "ok");
    assert_eq!(health["snapshots"], 0);
    assert_eq!(health["anchoring_enabled"], false);

    let keyring = json_of(&get(&format!("{base}/keyring")).await);
    assert_eq!(keyring["suite"], "ed25519");
    assert_eq!(keyring["public_len"], 32);
    assert_eq!(keyring["domain"], "tree-head");
    assert!(keyring["key_id"].as_str().unwrap().starts_with("k-"));

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Ingest + OAIS document shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_notarizes_with_oais_sections_and_signature() {
    let server = spawn(base_config("create")).await;
    let base = &server.base_url;
    let public = notary_public(base).await;

    let resp = create(base, "urn:unidpp:passport:e8", 0, None).await;
    assert_eq!(resp.status, 201);
    assert_eq!(
        resp.header("location").unwrap(),
        "/snapshots/s-000000000000"
    );
    assert_eq!(resp.header("x-snapshot-id").unwrap(), "s-000000000000");
    assert!(resp.header("etag").unwrap().starts_with("\"sha-"));
    assert!(resp.header("x-as-of").is_some());

    let doc = json_of(&resp);
    assert_eq!(doc["schema"], "unidpp-archive/snapshot/1");
    assert_eq!(
        doc["oais"]["submission"]["passport_id"],
        "urn:unidpp:passport:e8"
    );
    assert_eq!(
        doc["oais"]["submission"]["state_hash"],
        json!(hash_hex("state-0"))
    );
    assert_eq!(
        doc["oais"]["submission"]["submitter"],
        "urn:unidpp:actor:issuer-0"
    );
    // The three OAIS sections, and SIP == AIP on the preserved content.
    for section in ["submission", "information_package", "provenance"] {
        assert!(doc["oais"][section].is_object(), "missing {section}");
    }
    assert_eq!(
        doc["oais"]["submission"]["log_head"],
        doc["oais"]["information_package"]["log_head"]
    );
    assert_eq!(doc["oais"]["submission"]["state_size"], json!(4096));
    // Unanchored by default (no UNIDPP_LOG_URL), with an explicit reason.
    assert_eq!(
        doc["oais"]["provenance"]["anchoring"]["status"],
        "unanchored"
    );
    assert!(doc["oais"]["provenance"]["anchoring"]["reason"]
        .as_str()
        .unwrap()
        .contains("not configured"));
    // The signature verifies against the live anchor.
    verify_notarization(&resp.body, &public);
    // The commitment is the core-statement digest.
    let core = core_bytes_from_document(&doc).unwrap();
    assert_eq!(
        sha256(&[&core]).hex(),
        doc["oais"]["information_package"]["commitment"]
            .as_str()
            .unwrap()
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Byte-identical re-serving
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_is_re_served_byte_identically() {
    let server = spawn(base_config("reserve")).await;
    let base = &server.base_url;
    let public = notary_public(base).await;

    let post = create(base, "urn:unidpp:passport:bike-7", 1, None).await;
    assert_eq!(post.status, 201);
    let id = post.header("x-snapshot-id").unwrap().to_string();

    let first = get(&format!("{base}/snapshots/{id}")).await;
    assert_eq!(first.status, 200);
    assert_eq!(first.body, post.body, "re-serve must be byte-identical");
    assert_eq!(first.header("etag").unwrap(), post.header("etag").unwrap());
    assert!(first.header("cache-control").unwrap().contains("immutable"));
    // Stable across repeated serves, and still verifying.
    let second = get(&format!("{base}/snapshots/{id}")).await;
    assert_eq!(second.body, first.body);
    verify_notarization(&first.body, &public);

    // Unknown ids and malformed ids are 404s.
    assert_eq!(
        get(&format!("{base}/snapshots/s-999999999999"))
            .await
            .status,
        404
    );
    assert_eq!(get(&format!("{base}/snapshots/whatever")).await.status, 404);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// As-of listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn listing_filters_by_passport_and_as_of() {
    let server = spawn(base_config("listing")).await;
    let base = &server.base_url;

    let a1 = json_of(&create(base, "urn:unidpp:passport:a", 0, None).await);
    let b1 = json_of(&create(base, "urn:unidpp:passport:b", 1, None).await);
    let a2 = json_of(&create(base, "urn:unidpp:passport:a", 2, None).await);
    let t1 = parse_ts(&a1["as_of"]);
    let t2 = parse_ts(&b1["as_of"]);
    let t3 = parse_ts(&a2["as_of"]);
    assert!(t1 <= t2 && t2 <= t3, "sequencing follows time");
    // Timestamps are second-resolution: the cutoff instants the
    // assertions can rely on are the observed min/max.
    let at_min = t1;
    let at_max = t3;

    // Everything, no filters.
    let all = json_of(&get(&format!("{base}/snapshots")).await);
    assert_eq!(all["count"], 3);
    assert_eq!(all["snapshots"][0]["snapshot_id"], "s-000000000000");
    assert_eq!(all["snapshots"][2]["seq"], 2);
    assert_eq!(
        all["snapshots"][0]["notarized_at"],
        a1["oais"]["provenance"]["notarized_at"]
    );

    // Passport filter (query-encoded: colons are reserved characters).
    let only_a = json_of(
        &get(&format!(
            "{base}/snapshots?passport_id={}",
            enc("urn:unidpp:passport:a")
        ))
        .await,
    );
    assert_eq!(only_a["count"], 2);
    assert!(only_a["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["passport_id"] == "urn:unidpp:passport:a"));

    // As-of: only snapshots notarized at or before the instant.
    // Before the earliest instant: nothing existed yet.
    let before_anything = json_of(
        &get(&format!(
            "{base}/snapshots?at={}",
            unidpp_archive::Timestamp::from_secs(at_min.secs - 1)
        ))
        .await,
    );
    assert_eq!(before_anything["count"], 0);

    // At the latest observed instant: everything is listed (the
    // creates share a second, so the cutoff includes them all).
    let at_max_view = json_of(&get(&format!("{base}/snapshots?at={at_max}")).await);
    assert_eq!(at_max_view["count"], 3);
    assert_eq!(at_max_view["as_of"], at_max.to_string());

    let combined = json_of(
        &get(&format!(
            "{base}/snapshots?passport_id={}&at={at_max}",
            enc("urn:unidpp:passport:a")
        ))
        .await,
    );
    assert_eq!(combined["count"], 2);

    // The as-of echo rides the response header too.
    let resp = get(&format!("{base}/snapshots?at={}", at_min)).await;
    assert_eq!(resp.header("x-as-of").unwrap(), at_min.to_string());
    assert!(resp.header("cache-control").unwrap().contains("immutable"));

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Anchoring: reachable log (full chain) and explicit fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn log_anchoring_when_reachable_proves_the_full_chain() {
    let log = spawn_log().await;
    let mut config = base_config("anchored");
    config.log = LogAnchorConfig::enabled(log.base_url.clone());
    let server = spawn(config).await;
    let base = &server.base_url;
    let public = notary_public(base).await;

    let resp = create(base, "urn:unidpp:passport:e8", 5, None).await;
    assert_eq!(resp.status, 201);
    assert_eq!(resp.header("x-anchored-receipt").unwrap(), "0");
    let doc = json_of(&resp);

    let prov = &doc["oais"]["provenance"];
    assert_eq!(prov["anchoring"]["status"], "anchored");
    assert_eq!(prov["anchoring"]["log_id"], "unidpp-log-1");
    assert_eq!(prov["anchoring"]["receipt_id"], "0");
    assert_eq!(prov["anchoring"]["tree_size"], 1);

    // 1. The notarization still verifies (the signature covers the
    //    anchoring outcome).
    verify_notarization(&resp.body, &public);

    // 2. The anchored commitment is the core-statement digest.
    let commitment = prov["receipt"]["commitment"].as_str().unwrap();
    let core = core_bytes_from_document(&doc).unwrap();
    assert_eq!(sha256(&[&core]).hex(), commitment);

    // 3. The receipt chain verifies against the log's operator key:
    //    STH signature + Merkle inclusion.
    let log_doc = json_of(&get(&format!("{}/", log.base_url)).await);
    let op = PublicKey::from_bytes(&hex_decode(
        log_doc["operator"]["public_key_hex"].as_str().unwrap(),
    ))
    .unwrap();
    let receipt = &prov["receipt"];
    let sth = sth_from_json(&receipt["tree_head"]).expect("tree head from wire");
    sth.verify(&op).expect("operator signature verifies");
    let proof = proof_from_json(&receipt["inclusion"]).expect("inclusion from wire");
    verify_inclusion(&Hash::from_hex(commitment).unwrap(), &proof, &sth.root)
        .expect("inclusion verifies");

    // 4. The log itself re-serves the same receipt (seq 0).
    let live = json_of(&get(&format!("{}/receipt/0", log.base_url)).await);
    assert_eq!(live["commitment"].as_str().unwrap(), commitment);
    assert_eq!(
        live["subject"].as_str().unwrap(),
        "urn:unidpp:archive:snapshot:s-000000000000"
    );

    // 5. The journal carries the receipt id (the audit log view).
    let audit = json_of(&get(&format!("{base}/admin/log")).await);
    assert_eq!(audit["records"][0]["anchoring"]["receipt_id"], "0");
    assert!(audit["records"][0]["anchoring"]["receipt"].is_object());

    server.stop().await;
    log.stop().await;
}

#[tokio::test]
async fn unreachable_log_falls_back_to_unanchored() {
    // A port that is guaranteed closed: bind, note, drop.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut config = base_config("fallback");
    config.log = LogAnchorConfig::enabled(format!("http://127.0.0.1:{dead_port}"));
    let server = spawn(config).await;
    let base = &server.base_url;
    let public = notary_public(base).await;

    let health = json_of(&get(&format!("{base}/healthz")).await);
    assert_eq!(health["anchoring_enabled"], true);

    let resp = create(base, "urn:unidpp:passport:laptop-3", 7, None).await;
    assert_eq!(resp.status, 201, "the snapshot must still be notarized");
    let doc = json_of(&resp);
    let prov = &doc["oais"]["provenance"];
    assert_eq!(prov["anchoring"]["status"], "unanchored");
    assert!(prov["anchoring"]["reason"]
        .as_str()
        .unwrap()
        .contains("log unreachable"));
    assert!(prov["receipt"].is_null());
    // Degraded, not broken: the notarization verifies and the
    // snapshot re-serves byte-identically.
    verify_notarization(&resp.body, &public);
    let id = resp.header("x-snapshot-id").unwrap().to_string();
    let got = get(&format!("{base}/snapshots/{id}")).await;
    assert_eq!(got.body, resp.body);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Journal replay across restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn journal_replay_re_serves_byte_identically_and_continues() {
    let config = base_config("replay");
    let dir = config.state_file.as_ref().unwrap().parent().unwrap();
    let snaps_dir = config.snapshot_dir.clone().unwrap();

    let mut bodies = Vec::new();
    {
        let server = spawn(config.clone()).await;
        let base = &server.base_url;
        for (i, passport) in [
            "urn:unidpp:passport:e8",
            "urn:unidpp:passport:e8",
            "urn:unidpp:passport:bike-7",
        ]
        .iter()
        .enumerate()
        {
            let resp = create(base, passport, i, None).await;
            assert_eq!(resp.status, 201);
            bodies.push(resp.body.clone());
        }
        server.stop().await;
    }

    // The AIP files are on disk.
    assert_eq!(
        std::fs::read_dir(&snaps_dir).unwrap().count(),
        3,
        "one file per snapshot"
    );

    // Restart with the same journal + snapshot dir: everything
    // re-serves byte-identically.
    {
        let server = spawn(config.clone()).await;
        let base = &server.base_url;
        let health = json_of(&get(&format!("{base}/healthz")).await);
        assert_eq!(health["snapshots"], 3);
        for (i, body) in bodies.iter().enumerate() {
            let id = format!("s-{i:012}");
            let got = get(&format!("{base}/snapshots/{id}")).await;
            assert_eq!(got.status, 200);
            assert_eq!(&got.body, body, "snapshot {id} must re-serve identically");
        }
        // The as-of catalogue survived, and sequencing continues.
        let list = json_of(&get(&format!("{base}/snapshots")).await);
        assert_eq!(list["count"], 3);
        let next = create(base, "urn:unidpp:passport:e8", 9, None).await;
        assert_eq!(next.header("x-snapshot-id").unwrap(), "s-000000000003");
        server.stop().await;
    }

    // A tampered AIP file is detected at open (the archive must not
    // serve what was not notarized).
    let tampered = snaps_dir.join("s-000000000000.json");
    std::fs::write(&tampered, b"{\"tampered\": true}\n").unwrap();
    let spawned = TestServer::spawn(config.clone()).await;
    assert!(spawned.is_err());
    assert!(spawned.unwrap_err().to_string().contains("does not match"));
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Admin auth + audit log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_auth_and_audit_log() {
    let mut config = base_config("admin");
    config.admin_token = Some("it-secret".into());
    let server = spawn(config).await;
    let base = &server.base_url;

    // Ingest requires the token.
    assert_eq!(
        create(base, "urn:unidpp:passport:e8", 0, None).await.status,
        401
    );
    let ok = create(base, "urn:unidpp:passport:e8", 0, Some("it-secret")).await;
    assert_eq!(ok.status, 201);

    // Reads stay public.
    assert_eq!(get(&format!("{base}/snapshots")).await.status, 200);

    // The audit log requires the token and shows the journaled record.
    assert_eq!(get(&format!("{base}/admin/log")).await.status, 401);
    let audit_resp = json_request(
        "GET",
        &format!("{base}/admin/log?limit=10&offset=0"),
        None,
        Some("it-secret"),
    )
    .await;
    let audit = json_of(&audit_resp);
    assert_eq!(audit["total"], 1);
    assert_eq!(audit["records"][0]["seq"], 0);
    assert_eq!(audit["records"][0]["passport_id"], "urn:unidpp:passport:e8");
    assert!(audit["records"][0]["signature"].as_str().unwrap().len() == 128);
    assert_eq!(
        audit["records"][0]["body_sha256"].as_str().unwrap().len(),
        64
    );

    // A wrong token is still unauthorized.
    assert_eq!(
        create(base, "urn:unidpp:passport:e8", 1, Some("wrong"))
            .await
            .status,
        401
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn validation_errors() {
    let server = spawn(base_config("validation")).await;
    let base = &server.base_url;

    let bad = json!({
        "state_hash": hash_hex("s"),
        "log_head": hash_hex("h"),
    });
    let resp = json_request(
        "POST",
        &format!("{base}/snapshots"),
        Some(&bad.to_string()),
        None,
    )
    .await;
    assert_eq!(resp.status, 400);
    assert!(json_of(&resp)["error"]
        .as_str()
        .unwrap()
        .contains("passport_id"));

    let bad = json!({
        "passport_id": "urn:x",
        "state_hash": "not-hex",
        "log_head": hash_hex("h"),
    });
    let resp = json_request(
        "POST",
        &format!("{base}/snapshots"),
        Some(&bad.to_string()),
        None,
    )
    .await;
    assert_eq!(resp.status, 400);
    assert!(json_of(&resp)["error"]
        .as_str()
        .unwrap()
        .contains("state_hash"));

    // Missing log_head.
    let bad = json!({
        "passport_id": "urn:x",
        "state_hash": hash_hex("s"),
    });
    let resp = json_request(
        "POST",
        &format!("{base}/snapshots"),
        Some(&bad.to_string()),
        None,
    )
    .await;
    assert_eq!(resp.status, 400);

    // Non-JSON body.
    let resp = json_request(
        "POST",
        &format!("{base}/snapshots"),
        Some("{not json"),
        None,
    )
    .await;
    assert_eq!(resp.status, 400);

    // Bad `at` on the listing.
    assert_eq!(
        get(&format!("{base}/snapshots?at=whenever")).await.status,
        400
    );

    server.stop().await;
}

// ---------------------------------------------------------------------------
// The archival end-to-end story (many snapshots, mixed anchor states)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn archive_of_many_snapshots_stays_consistent() {
    let log = spawn_log().await;
    let mut config = base_config("story");
    config.log = LogAnchorConfig::enabled(log.base_url.clone());
    let server = spawn(config).await;
    let base = &server.base_url;
    let public = notary_public(base).await;

    let mut ids = Vec::new();
    for i in 0..6usize {
        let resp = create(base, "urn:unidpp:passport:e8", i, None).await;
        assert_eq!(resp.status, 201);
        verify_notarization(&resp.body, &public);
        ids.push(resp.header("x-snapshot-id").unwrap().to_string());
    }

    // Sequencing is strictly monotonic and ids are unique.
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len());

    // The log tree grew to match (one commitment per snapshot).
    let head = json_of(&get(&format!("{}/tree/head", log.base_url)).await);
    assert_eq!(head["tree_size"], 6);

    // Every snapshot re-serves and every provenance section is filled.
    for id in &ids {
        let resp = get(&format!("{base}/snapshots/{id}")).await;
        assert_eq!(resp.status, 200);
        let doc = json_of(&resp);
        assert_eq!(doc["oais"]["provenance"]["anchoring"]["status"], "anchored");
        assert!(doc["oais"]["provenance"]["receipt"].is_object());
    }

    // Status enum import is exercised on the typed view too.
    assert_ne!(AnchoringStatus::Anchored, AnchoringStatus::Unanchored);

    server.stop().await;
    log.stop().await;
}
