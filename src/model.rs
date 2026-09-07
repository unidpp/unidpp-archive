//! The archive's domain shapes: the snapshot record (the journal's
//! storage unit), the canonical statement bytes (what the notary
//! signs and what the transparency log anchors), the OAIS-style
//! document (the archival information package a client receives
//! byte-identically), and the verifier-side rebuild helpers.
//!
//! Model-driven by design: the served document is *derived state* —
//! a pure function of the record — so journal replay reproduces
//! byte-identical bodies (the property the restart tests pin). The
//! document embeds its own notarization signature over the canonical
//! statement bytes, so the AIP is self-verifying offline.
//!
//! ## Canonical bytes
//!
//! The **core statement** (what the commitment anchors) is the
//! [`unidpp_model::CanonicalWriter`] serialization of: service id,
//! snapshot id, sequence, passport id, state hash, log head, and the
//! as-of (notarization) instant. The **full statement** (what the
//! signature covers) appends the anchoring outcome: an anchored flag
//! and, when anchored, the log id, receipt sequence, tree size and
//! root. Both are rebuildable from the served document alone — see
//! [`core_bytes_from_document`] and [`statement_bytes_from_document`].

use serde_json::{json, Value};
use unidpp_model::{sha256, CanonicalWriter, Hash};
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};

use crate::hex::{hex_decode, hex_encode};
use crate::time::Timestamp;

/// Service identity (appears in every canonical statement).
pub const SERVICE_ID: &str = "unidpp-archive";

/// The served document's schema tag.
pub const SCHEMA: &str = "unidpp-archive/snapshot/1";

/// The OAIS profile label carried in every document.
pub const OAIS_PROFILE: &str = "ISO 14721 (OAIS) simplified for digital product passports";

/// The signing-domain adapter note (the same note as `unidpp-trust`).
pub const ADAPTER_NOTE: &str = "SIGNATIF has no archival-notarization domain; tree-head (the operator's signed statement of state, used for transparency-log signed tree heads) is the closest documented adaptation — the same adapter note as unidpp-trust. signatif's HistoricalStamp domain ('a notarized historical verification stamp') is the semantically exact slot; adoption is deferred to the 19-signatif-spec-sync divergence register. The signature covers the canonical statement bytes and is embedded in the document so the AIP is self-verifying.";

/// The domain every notarization signature uses.
pub const NOTARIZATION_DOMAIN: SigningDomain = SigningDomain::TreeHead;

// ---------------------------------------------------------------------------
// Anchoring outcome
// ---------------------------------------------------------------------------

/// Whether a snapshot's commitment reached a transparency log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchoringStatus {
    /// The commitment was sequenced by a log; the receipt is embedded.
    Anchored,
    /// The log was unreachable or refused; the snapshot is still
    /// notarized and stored, with the reason recorded.
    Unanchored,
}

impl AnchoringStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AnchoringStatus::Anchored => "anchored",
            AnchoringStatus::Unanchored => "unanchored",
        }
    }
}

/// The anchoring fields extracted from a log receipt (the summary the
/// canonical statement commits to; the full receipt is preserved
/// verbatim beside it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSummary {
    pub log_id: String,
    /// The log's sequence number for the anchored commitment (the
    /// "receipt id" that is journaled).
    pub receipt_seq: u64,
    pub tree_size: u64,
    pub root: Hash,
    pub logged_at: Timestamp,
}

/// Parse the anchoring summary out of a `unidpp-log` inclusion
/// receipt (the JSON body of `POST /commitments`). Strict: a receipt
/// missing any anchored field is rejected, because the canonical
/// statement commits to all of them.
pub fn anchor_summary_from_receipt(v: &Value) -> Result<AnchorSummary, String> {
    let obj = v.as_object().ok_or("receipt must be an object")?;
    let log_id = obj
        .get("log_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("receipt missing `log_id`")?
        .to_string();
    let receipt_seq = match obj.get("seq").and_then(Value::as_u64) {
        Some(n) => n,
        None => obj
            .get("receipt_id")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("receipt missing `seq`/`receipt_id`")?,
    };
    let head = obj
        .get("tree_head")
        .ok_or("receipt missing `tree_head`")?
        .as_object()
        .ok_or("`tree_head` must be an object")?;
    let tree_size = head
        .get("tree_size")
        .and_then(Value::as_u64)
        .ok_or("receipt missing `tree_head.tree_size`")?;
    let root = head
        .get("root")
        .and_then(Value::as_str)
        .and_then(Hash::from_hex)
        .ok_or("receipt missing/invalid `tree_head.root`")?;
    let logged_at = obj
        .get("logged_at")
        .and_then(Value::as_str)
        .and_then(|s| Timestamp::parse(s).ok())
        .ok_or("receipt missing/invalid `logged_at`")?;
    Ok(AnchorSummary {
        log_id,
        receipt_seq,
        tree_size,
        root,
        logged_at,
    })
}

/// The anchoring outcome recorded with a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchoring {
    pub status: AnchoringStatus,
    /// Why anchoring did not happen (unanchored only).
    pub reason: Option<String>,
    pub log_id: Option<String>,
    pub receipt_seq: Option<u64>,
    pub tree_size: Option<u64>,
    pub root: Option<Hash>,
    pub logged_at: Option<Timestamp>,
    /// The commitment that was (or would be) anchored: the SHA-256 of
    /// the core statement bytes. Always set on a sealed record.
    pub commitment: Option<Hash>,
    /// The verbatim inclusion receipt from the log (anchored only) —
    /// preserved so the AIP is self-contained for offline
    /// verification of the anchor chain.
    pub receipt: Option<Value>,
}

impl Anchoring {
    /// A successful anchor: summary fields, the verbatim receipt, and
    /// the commitment that was anchored.
    pub fn anchored(summary: AnchorSummary, receipt: Value, commitment: Hash) -> Anchoring {
        Anchoring {
            status: AnchoringStatus::Anchored,
            reason: None,
            log_id: Some(summary.log_id),
            receipt_seq: Some(summary.receipt_seq),
            tree_size: Some(summary.tree_size),
            root: Some(summary.root),
            logged_at: Some(summary.logged_at),
            commitment: Some(commitment),
            receipt: Some(receipt),
        }
    }

    /// A skipped anchor with the reason (log not configured,
    /// unreachable, or a refused receipt).
    pub fn unanchored(reason: String) -> Anchoring {
        Anchoring {
            status: AnchoringStatus::Unanchored,
            reason: Some(reason),
            log_id: None,
            receipt_seq: None,
            tree_size: None,
            root: None,
            logged_at: None,
            commitment: None,
            receipt: None,
        }
    }

    /// The journal rendering: all summary fields **plus the verbatim
    /// receipt** (so replay reproduces byte-identical documents).
    fn to_journal_json(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "reason": self.reason,
            "log_id": self.log_id,
            "receipt_id": self.receipt_seq.map(|s| s.to_string()),
            "tree_size": self.tree_size,
            "root": self.root.map(|h| h.hex()),
            "logged_at": self.logged_at.map(|t| t.to_string()),
            "commitment": self.commitment.map(|h| h.hex()),
            "receipt": self.receipt,
        })
    }

    /// The document rendering: the summary fields without the receipt
    /// (the receipt rides one level up, under
    /// `oais.provenance.receipt`).
    fn to_document_json(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "reason": self.reason,
            "log_id": self.log_id,
            "receipt_id": self.receipt_seq.map(|s| s.to_string()),
            "tree_size": self.tree_size,
            "root": self.root.map(|h| h.hex()),
            "logged_at": self.logged_at.map(|t| t.to_string()),
        })
    }

    fn from_json(v: &Value) -> Result<Anchoring, String> {
        let obj = v.as_object().ok_or("`anchoring` must be an object")?;
        let status = match obj.get("status").and_then(Value::as_str) {
            Some("anchored") => AnchoringStatus::Anchored,
            Some("unanchored") => AnchoringStatus::Unanchored,
            _ => return Err("`anchoring.status` must be `anchored`/`unanchored`".into()),
        };
        let opt_str = |k: &str| -> Result<Option<String>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(format!("`anchoring.{k}` must be a string or null")),
            }
        };
        let opt_u64 = |k: &str| -> Result<Option<u64>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Number(n)) => n
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| format!("`anchoring.{k}` must be an unsigned integer")),
                Some(_) => Err(format!(
                    "`anchoring.{k}` must be an unsigned integer or null"
                )),
            }
        };
        let opt_hash = |k: &str| -> Result<Option<Hash>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Hash::from_hex(s)
                    .map(Some)
                    .ok_or_else(|| format!("`anchoring.{k}` must be 64-char hex")),
                Some(_) => Err(format!("`anchoring.{k}` must be a hex string or null")),
            }
        };
        let opt_time = |k: &str| -> Result<Option<Timestamp>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Timestamp::parse(s)
                    .map(Some)
                    .map_err(|e| format!("`anchoring.{k}`: {e}")),
                Some(_) => Err(format!(
                    "`anchoring.{k}` must be an RFC 3339 string or null"
                )),
            }
        };
        let receipt = match obj.get("receipt") {
            None | Some(Value::Null) => None,
            Some(v @ Value::Object(_)) => Some(v.clone()),
            Some(_) => return Err("`anchoring.receipt` must be an object or null".into()),
        };
        let receipt_seq = match obj.get("receipt_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(
                s.parse::<u64>()
                    .map_err(|_| "`anchoring.receipt_id` must be a numeric string")?,
            ),
            Some(_) => return Err("`anchoring.receipt_id` must be a numeric string or null".into()),
        };
        let anchoring = Anchoring {
            status,
            reason: opt_str("reason")?,
            log_id: opt_str("log_id")?,
            receipt_seq,
            tree_size: opt_u64("tree_size")?,
            root: opt_hash("root")?,
            logged_at: opt_time("logged_at")?,
            commitment: opt_hash("commitment")?,
            receipt,
        };
        // Integrity: an anchored outcome commits to all anchor fields
        // in the canonical statement — a partial one cannot replay.
        if anchoring.status == AnchoringStatus::Anchored {
            let complete = anchoring.log_id.is_some()
                && anchoring.receipt_seq.is_some()
                && anchoring.tree_size.is_some()
                && anchoring.root.is_some()
                && anchoring.logged_at.is_some()
                && anchoring.commitment.is_some()
                && anchoring.receipt.is_some();
            if !complete {
                return Err(
                    "an `anchored` record must carry log_id, receipt_id, tree_size, root, logged_at, commitment and the receipt"
                        .into(),
                );
            }
        }
        Ok(anchoring)
    }
}

// ---------------------------------------------------------------------------
// Snapshot record
// ---------------------------------------------------------------------------

/// One notarized snapshot — the JSONL journal's storage unit, the
/// replay input, and the sole source of the served document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRecord {
    /// Strictly monotonic sequence (the journal's spine).
    pub seq: u64,
    /// Content-free public id (`s-` + zero-padded seq).
    pub snapshot_id: String,
    /// The as-of instant: when the service notarized this state.
    pub notarized_at: Timestamp,
    /// The passport the snapshot preserves (producer's identity).
    pub passport_id: String,
    /// The passport state hash at the snapshot moment.
    pub state_hash: Hash,
    /// The passport event-log head at the snapshot moment.
    pub log_head: Hash,
    /// Who submitted the snapshot (OAIS submission), if declared.
    pub submitter: Option<String>,
    /// Size of the state the hash commits to, if declared.
    pub state_size: Option<u64>,
    /// The anchoring outcome.
    pub anchoring: Anchoring,
    /// The notarization signature (Ed25519 over the statement bytes).
    pub signature: Vec<u8>,
    /// Key id of the notary key that produced the signature.
    pub key_id: String,
    /// SHA-256 of the rendered document bytes (journal-side fixity:
    /// detects renderer drift and snapshot-file tampering).
    pub body_digest: Hash,
}

/// The canonical core statement: service, id, sequence, passport,
/// state, log head, as-of. This is what the anchored commitment
/// digests.
fn canonical_core(
    snapshot_id: &str,
    seq: u64,
    passport_id: &str,
    state_hash: &Hash,
    log_head: &Hash,
    notarized_at: Timestamp,
) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    w.write_str(SERVICE_ID);
    w.write_str(snapshot_id);
    w.write_u64(seq);
    w.write_str(passport_id);
    w.write_hash(state_hash);
    w.write_hash(log_head);
    w.write_i64(notarized_at.secs);
    w.into_bytes()
}

/// Append the anchoring outcome to the core bytes: the full statement
/// the notary signs.
fn canonical_statement(core: &[u8], anchoring: &Anchoring) -> Vec<u8> {
    let mut w = CanonicalWriter::new();
    w.write_bytes_raw(core);
    match anchoring.status {
        AnchoringStatus::Unanchored => w.write_u32(0),
        AnchoringStatus::Anchored => {
            w.write_u32(1);
            w.write_str(anchoring.log_id.as_deref().unwrap_or_default());
            w.write_u64(anchoring.receipt_seq.unwrap_or(0));
            w.write_u64(anchoring.tree_size.unwrap_or(0));
            w.write_hash(anchoring.root.as_ref().unwrap_or(&Hash([0u8; 32])));
        }
    }
    w.into_bytes()
}

impl SnapshotRecord {
    /// A fresh, unsigned record (anchoring defaults to unanchored
    /// with no reason; the API layer sets the real outcome before
    /// sealing).
    pub fn new(
        seq: u64,
        notarized_at: Timestamp,
        passport_id: String,
        state_hash: Hash,
        log_head: Hash,
        submitter: Option<String>,
        state_size: Option<u64>,
    ) -> SnapshotRecord {
        SnapshotRecord {
            seq,
            snapshot_id: snapshot_id_of(seq),
            notarized_at,
            passport_id,
            state_hash,
            log_head,
            submitter,
            state_size,
            anchoring: Anchoring::unanchored("not attempted yet".to_string()),
            signature: Vec::new(),
            key_id: String::new(),
            body_digest: Hash([0u8; 32]),
        }
    }

    /// Replace the anchoring outcome (must happen before
    /// [`SnapshotRecord::seal`], because the signature covers it).
    pub fn set_anchoring(&mut self, anchoring: Anchoring) {
        self.anchoring = anchoring;
    }

    /// The canonical core statement bytes.
    pub fn core_statement_bytes(&self) -> Vec<u8> {
        canonical_core(
            &self.snapshot_id,
            self.seq,
            &self.passport_id,
            &self.state_hash,
            &self.log_head,
            self.notarized_at,
        )
    }

    /// The canonical full statement bytes (core + anchoring).
    pub fn statement_bytes(&self) -> Vec<u8> {
        canonical_statement(&self.core_statement_bytes(), &self.anchoring)
    }

    /// The commitment the transparency log anchors: the SHA-256 of
    /// the core statement bytes.
    pub fn commitment(&self) -> Hash {
        sha256(&[&self.core_statement_bytes()])
    }

    /// Notarize and seal: sign the statement bytes with the notary
    /// key, record the key id, and fix the rendered-body digest.
    /// Re-sealing recomputes everything.
    pub fn seal(&mut self, notary: &KeyPair) -> Result<(), String> {
        let slot = SignatureSlot::sign(notary, NOTARIZATION_DOMAIN, &self.statement_bytes())
            .map_err(|e| format!("notarization sign: {e}"))?;
        self.signature = slot.signature.unwrap_or_default();
        self.key_id = notary.key_id().to_string();
        self.anchoring.commitment = Some(self.commitment());
        self.body_digest = sha256(&[self.render_body().as_bytes()]);
        Ok(())
    }

    /// The served document (the AIP wire view).
    pub fn to_document(&self) -> Value {
        let a = &self.anchoring;
        let statement_digest = sha256(&[self.statement_bytes().as_slice()]);
        json!({
            "schema": SCHEMA,
            "service": SERVICE_ID,
            "snapshot_id": self.snapshot_id,
            "seq": self.seq,
            "as_of": self.notarized_at.to_string(),
            "oais": {
                "profile": OAIS_PROFILE,
                "submission": {
                    "submitter": self.submitter,
                    "submitted_at": self.notarized_at.to_string(),
                    "passport_id": self.passport_id,
                    "state_hash": self.state_hash.hex(),
                    "log_head": self.log_head.hex(),
                    "state_size": self.state_size,
                },
                "information_package": {
                    "passport_id": self.passport_id,
                    "state_hash": self.state_hash.hex(),
                    "log_head": self.log_head.hex(),
                    "as_of": self.notarized_at.to_string(),
                    "commitment": a.commitment.map(|h| h.hex()),
                    "statement_digest": statement_digest.hex(),
                },
                "provenance": {
                    "service": SERVICE_ID,
                    "notarized_at": self.notarized_at.to_string(),
                    "signing": {
                        "suite": Suite::Ed25519.as_str(),
                        "key_id": self.key_id,
                        "domain": "tree-head",
                        "adapter_note": ADAPTER_NOTE,
                    },
                    "anchoring": a.to_document_json(),
                    "receipt": a.receipt,
                    "signature": hex_encode(&self.signature),
                    "verification": "Rebuild the canonical statement bytes (discovery document, notarization.statement_recipe) and verify with unidpp_signatif SignatureSlot::verify(SigningDomain::TreeHead, bytes, public) against the /keyring anchor.",
                },
            },
        })
    }

    /// The exact served bytes (pretty-printed; serde_json's default
    /// sorted-key maps make this a pure function of the record).
    pub fn render_body(&self) -> String {
        serde_json::to_string_pretty(&self.to_document()).expect("document serializes")
    }

    /// The journal line (the storage unit — round-trippable).
    pub fn to_journal_json(&self) -> Value {
        json!({
            "seq": self.seq,
            "snapshot_id": self.snapshot_id,
            "notarized_at": self.notarized_at.to_string(),
            "passport_id": self.passport_id,
            "state_hash": self.state_hash.hex(),
            "log_head": self.log_head.hex(),
            "submitter": self.submitter,
            "state_size": self.state_size,
            "anchoring": self.anchoring.to_journal_json(),
            "signature": hex_encode(&self.signature),
            "key_id": self.key_id,
            "body_digest": self.body_digest.hex(),
        })
    }

    /// Rebuild a record from its journal line.
    pub fn from_journal_json(v: &Value) -> Result<SnapshotRecord, String> {
        let obj = v.as_object().ok_or("snapshot record must be an object")?;
        let req_str = |k: &str| -> Result<String, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("missing `{k}`"))
        };
        let req_u64 = |k: &str| -> Result<u64, String> {
            obj.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("missing/invalid `{k}`"))
        };
        let req_hash = |k: &str| -> Result<Hash, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .and_then(Hash::from_hex)
                .ok_or_else(|| format!("missing/invalid `{k}` (64-char hex)"))
        };
        let opt_str = |k: &str| -> Result<Option<String>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(format!("`{k}` must be a string or null")),
            }
        };
        let opt_u64 = |k: &str| -> Result<Option<u64>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::Number(n)) => n
                    .as_u64()
                    .map(Some)
                    .ok_or_else(|| format!("`{k}` must be an unsigned integer")),
                Some(_) => Err(format!("`{k}` must be an unsigned integer or null")),
            }
        };
        let anchoring = Anchoring::from_json(obj.get("anchoring").ok_or("missing `anchoring`")?)?;
        let signature =
            hex_decode(&req_str("signature")?).map_err(|e| format!("`signature`: {e}"))?;
        Ok(SnapshotRecord {
            seq: req_u64("seq")?,
            snapshot_id: req_str("snapshot_id")?,
            notarized_at: Timestamp::parse(&req_str("notarized_at")?)
                .map_err(|e| format!("`notarized_at`: {e}"))?,
            passport_id: req_str("passport_id")?,
            state_hash: req_hash("state_hash")?,
            log_head: req_hash("log_head")?,
            submitter: opt_str("submitter")?,
            state_size: opt_u64("state_size")?,
            anchoring,
            signature,
            key_id: req_str("key_id")?,
            body_digest: req_hash("body_digest")?,
        })
    }
}

/// The public snapshot id for a sequence number (`s-` + 12 digits —
/// zero-padded so lexical order matches sequencing order).
pub fn snapshot_id_of(seq: u64) -> String {
    format!("s-{seq:012}")
}

// ---------------------------------------------------------------------------
// Verifier-side rebuild (exactly what a CLI would do with a document)
// ---------------------------------------------------------------------------

fn doc_field<'a>(doc: &'a Value, path: &[&str]) -> Result<&'a Value, String> {
    let mut v = doc;
    for key in path {
        v = v
            .get(key)
            .ok_or_else(|| format!("document missing `{}`", path.join(".")))?;
    }
    Ok(v)
}

/// Rebuild the canonical **core** statement bytes from a served
/// document (the verifier side; mirrors [`SnapshotRecord::core_statement_bytes`]).
pub fn core_bytes_from_document(doc: &Value) -> Result<Vec<u8>, String> {
    if doc_field(doc, &["service"])?.as_str() != Some(SERVICE_ID) {
        return Err(format!("document `service` must be `{SERVICE_ID}`"));
    }
    let snapshot_id = doc_field(doc, &["snapshot_id"])?
        .as_str()
        .ok_or("`snapshot_id` must be a string")?;
    let seq = doc_field(doc, &["seq"])?
        .as_u64()
        .ok_or("`seq` must be an unsigned integer")?;
    let ip = |k: &str| -> Result<String, String> {
        doc_field(doc, &["oais", "information_package", k])?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("`oais.information_package.{k}` must be a string"))
    };
    let state_hash = Hash::from_hex(&ip("state_hash")?)
        .ok_or("`oais.information_package.state_hash` must be 64-char hex")?;
    let log_head = Hash::from_hex(&ip("log_head")?)
        .ok_or("`oais.information_package.log_head` must be 64-char hex")?;
    let as_of = Timestamp::parse(&ip("as_of")?).map_err(|e| format!("`as_of`: {e}"))?;
    Ok(canonical_core(
        snapshot_id,
        seq,
        &ip("passport_id")?,
        &state_hash,
        &log_head,
        as_of,
    ))
}

/// Rebuild the canonical **full** statement bytes (core + anchoring
/// outcome) from a served document — the bytes the embedded signature
/// covers.
pub fn statement_bytes_from_document(doc: &Value) -> Result<Vec<u8>, String> {
    let core = core_bytes_from_document(doc)?;
    let anchoring = doc_field(doc, &["oais", "provenance", "anchoring"])?;
    let status = anchoring
        .get("status")
        .and_then(Value::as_str)
        .ok_or("`oais.provenance.anchoring.status` missing")?;
    match status {
        "unanchored" => Ok(canonical_statement(&core, &Anchoring::unanchored_default())),
        "anchored" => {
            let log_id = anchoring
                .get("log_id")
                .and_then(Value::as_str)
                .ok_or("`anchoring.log_id` missing")?;
            let receipt_seq = anchoring
                .get("receipt_id")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or("`anchoring.receipt_id` must be a numeric string")?;
            let tree_size = anchoring
                .get("tree_size")
                .and_then(Value::as_u64)
                .ok_or("`anchoring.tree_size` missing")?;
            let root = anchoring
                .get("root")
                .and_then(Value::as_str)
                .and_then(Hash::from_hex)
                .ok_or("`anchoring.root` must be 64-char hex")?;
            let a = Anchoring {
                status: AnchoringStatus::Anchored,
                reason: None,
                log_id: Some(log_id.to_string()),
                receipt_seq: Some(receipt_seq),
                tree_size: Some(tree_size),
                root: Some(root),
                logged_at: None,
                commitment: None,
                receipt: None,
            };
            Ok(canonical_statement(&core, &a))
        }
        other => Err(format!(
            "`anchoring.status` must be `anchored`/`unanchored`, got `{other}`"
        )),
    }
}

impl Anchoring {
    /// The unanchored shape used by the verifier-side rebuild (fields
    /// beyond `status` are ignored by the canonical writer).
    fn unanchored_default() -> Anchoring {
        Anchoring {
            status: AnchoringStatus::Unanchored,
            reason: None,
            log_id: None,
            receipt_seq: None,
            tree_size: None,
            root: None,
            logged_at: None,
            commitment: None,
            receipt: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_signatif::keyring::KeyId;

    fn hash_of(tag: &str) -> Hash {
        sha256(&[tag.as_bytes()])
    }

    fn notary() -> KeyPair {
        KeyPair::seeded(Suite::Ed25519, b"unit-notary").unwrap()
    }

    fn sealed_record(seq: u64) -> SnapshotRecord {
        let mut r = SnapshotRecord::new(
            seq,
            Timestamp::from_secs(1_900_000_000 + seq as i64),
            format!("urn:unidpp:passport:e8-{seq}"),
            hash_of(&format!("state-{seq}")),
            hash_of(&format!("head-{seq}")),
            Some(format!("urn:unidpp:actor:issuer-{seq}")),
            Some(1234 + seq),
        );
        r.seal(&notary()).unwrap();
        r
    }

    fn anchored_record(seq: u64) -> SnapshotRecord {
        let mut r = sealed_record(seq);
        let receipt = json!({
            "receipt_id": "7",
            "log_id": "unit-log",
            "seq": 7,
            "subject": format!("urn:unidpp:archive:snapshot:{}", r.snapshot_id),
            "commitment": r.commitment().hex(),
            "logged_at": (Timestamp::from_secs(1_900_000_999)).to_string(),
            "tree_head": {
                "log_id": "unit-log",
                "tree_size": 8,
                "timestamp": (Timestamp::from_secs(1_900_000_999)).to_string(),
                "root": hash_of("root").hex(),
                "signature": {"suite": "ed25519", "key_id": "k-x", "value": "00"},
            },
        });
        let summary = anchor_summary_from_receipt(&receipt).unwrap();
        r.set_anchoring(Anchoring::anchored(summary, receipt, r.commitment()));
        r.seal(&notary()).unwrap();
        r
    }

    #[test]
    fn snapshot_ids_are_padded_and_ordered() {
        assert_eq!(snapshot_id_of(0), "s-000000000000");
        assert_eq!(snapshot_id_of(42), "s-000000000042");
        assert!(snapshot_id_of(9) < snapshot_id_of(10));
        assert_eq!(sealed_record(3).snapshot_id, "s-000000000003");
    }

    #[test]
    fn statement_bytes_are_deterministic_and_anchoring_sensitive() {
        let a = sealed_record(1);
        let b = sealed_record(1);
        assert_eq!(a.statement_bytes(), b.statement_bytes());
        assert_eq!(a.core_statement_bytes(), b.core_statement_bytes());
        // Different seq → different bytes.
        assert_ne!(a.statement_bytes(), sealed_record(2).statement_bytes());
        // Anchoring changes the statement but not the core.
        let anchored = anchored_record(1);
        assert_eq!(anchored.core_statement_bytes(), a.core_statement_bytes());
        assert_ne!(anchored.statement_bytes(), a.statement_bytes());
    }

    #[test]
    fn commitment_is_the_core_digest() {
        let r = sealed_record(5);
        assert_eq!(
            r.commitment(),
            Hash::from_hex(&sha256(&[&r.core_statement_bytes()]).hex()).unwrap()
        );
        assert_ne!(r.commitment(), sealed_record(6).commitment());
    }

    #[test]
    fn journal_json_round_trips_both_anchor_states() {
        for r in [sealed_record(0), anchored_record(1)] {
            let v = r.to_journal_json();
            let back = SnapshotRecord::from_journal_json(&v).unwrap();
            assert_eq!(back, r);
        }
        assert!(SnapshotRecord::from_journal_json(&json!({"seq": 1})).is_err());
        // A receipt that is not an object is refused.
        let mut v = anchored_record(2).to_journal_json();
        v["anchoring"]["status"] = json!("anchored");
        v["anchoring"]["receipt_id"] = json!("x");
        assert!(SnapshotRecord::from_journal_json(&v).is_err());
    }

    #[test]
    fn sealed_signature_verifies_and_tampering_fails() {
        let r = anchored_record(4);
        let key = notary();
        let slot = SignatureSlot {
            suite: Suite::Ed25519,
            key_id: KeyId::new(&r.key_id).unwrap(),
            signature: Some(r.signature.clone()),
        };
        slot.verify(NOTARIZATION_DOMAIN, &r.statement_bytes(), key.public())
            .expect("notarization verifies");
        // Tampered passport id → different canonical bytes → fail.
        let mut doc = r.to_document();
        doc["oais"]["information_package"]["passport_id"] = json!("urn:unidpp:passport:other");
        let rebuilt = statement_bytes_from_document(&doc).unwrap();
        assert!(slot
            .verify(NOTARIZATION_DOMAIN, &rebuilt, key.public())
            .is_err());
        // Wrong key fails.
        let other = KeyPair::seeded(Suite::Ed25519, b"other-notary").unwrap();
        assert!(slot
            .verify(NOTARIZATION_DOMAIN, &r.statement_bytes(), other.public())
            .is_err());
    }

    #[test]
    fn document_rebuild_matches_the_record_bytes() {
        for r in [sealed_record(7), anchored_record(8)] {
            let doc = r.to_document();
            assert_eq!(
                core_bytes_from_document(&doc).unwrap(),
                r.core_statement_bytes()
            );
            assert_eq!(
                statement_bytes_from_document(&doc).unwrap(),
                r.statement_bytes()
            );
        }
    }

    #[test]
    fn render_is_byte_stable_across_round_trips() {
        let r = anchored_record(9);
        let first = r.render_body();
        assert_eq!(first, r.render_body());
        let back = SnapshotRecord::from_journal_json(&r.to_journal_json()).unwrap();
        assert_eq!(back.render_body(), first);
        // The journaled body digest matches the rendered bytes.
        assert_eq!(sha256(&[first.as_bytes()]), r.body_digest);
    }

    #[test]
    fn document_carries_the_three_oais_sections() {
        let doc = anchored_record(11).to_document();
        let oais = &doc["oais"];
        assert_eq!(oais["profile"], OAIS_PROFILE);
        for section in ["submission", "information_package", "provenance"] {
            assert!(oais.get(section).is_some(), "missing {section}");
        }
        // The submission (SIP) and the information package (AIP)
        // agree on the preserved content.
        assert_eq!(
            oais["submission"]["passport_id"],
            oais["information_package"]["passport_id"]
        );
        assert_eq!(
            oais["submission"]["state_hash"],
            oais["information_package"]["state_hash"]
        );
        assert_eq!(
            oais["submission"]["log_head"],
            oais["information_package"]["log_head"]
        );
        // Provenance carries the signature, key id and anchoring.
        assert!(oais["provenance"]["signature"].as_str().unwrap().len() == 128);
        assert!(oais["provenance"]["signing"]["key_id"]
            .as_str()
            .unwrap()
            .starts_with("k-"));
        assert_eq!(oais["provenance"]["anchoring"]["status"], "anchored");
        assert!(oais["provenance"]["receipt"].is_object());
    }

    #[test]
    fn anchor_summary_parses_and_rejects_receipts() {
        let good = json!({
            "receipt_id": "3",
            "log_id": "unit-log",
            "seq": 3,
            "logged_at": "2026-09-07T10:00:00Z",
            "tree_head": {"tree_size": 4, "root": hash_of("r").hex()},
        });
        let s = anchor_summary_from_receipt(&good).unwrap();
        assert_eq!(s.log_id, "unit-log");
        assert_eq!(s.receipt_seq, 3);
        assert_eq!(s.tree_size, 4);
        assert_eq!(s.root, hash_of("r"));
        assert_eq!(
            s.logged_at,
            Timestamp::parse("2026-09-07T10:00:00Z").unwrap()
        );
        // seq falls back to receipt_id parsing.
        let alt = json!({
            "receipt_id": "12",
            "log_id": "unit-log",
            "logged_at": "2026-09-07T10:00:00Z",
            "tree_head": {"tree_size": 13, "root": hash_of("r").hex()},
        });
        assert_eq!(anchor_summary_from_receipt(&alt).unwrap().receipt_seq, 12);
        // Rejections.
        for bad in [
            json!({}),
            json!({"log_id": "l", "seq": 1, "logged_at": "nope", "tree_head": {}}),
            json!({"log_id": "l", "seq": 1, "logged_at": "2026-09-07T10:00:00Z", "tree_head": {"tree_size": 1, "root": "zz"}}),
        ] {
            assert!(anchor_summary_from_receipt(&bad).is_err());
        }
    }

    #[test]
    fn statement_rebuild_rejects_malformed_documents() {
        let doc = anchored_record(12).to_document();
        // Wrong service.
        let mut bad = doc.clone();
        bad["service"] = json!("someone-else");
        assert!(core_bytes_from_document(&bad).is_err());
        // Missing information package.
        let mut bad = doc.clone();
        bad["oais"]["information_package"] = Value::Null;
        assert!(core_bytes_from_document(&bad).is_err());
        // Bad anchoring status.
        let mut bad = doc.clone();
        bad["oais"]["provenance"]["anchoring"]["status"] = json!("maybe");
        assert!(statement_bytes_from_document(&bad).is_err());
        // Anchored without receipt id.
        let mut bad = doc;
        bad["oais"]["provenance"]["anchoring"]["receipt_id"] = Value::Null;
        assert!(statement_bytes_from_document(&bad).is_err());
    }

    #[test]
    fn adapter_note_is_the_trust_house_note() {
        assert!(ADAPTER_NOTE.contains("tree-head"));
        assert!(ADAPTER_NOTE.contains("unidpp-trust"));
        assert!(ADAPTER_NOTE.contains("HistoricalStamp"));
    }
}
