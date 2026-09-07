//! UniDPP Tier-C notarized archive service (crate `unidpp-archive`).
//!
//! Part of UniDPP (github.com/unidpp) — `10-remaining-tasks-definitive.md`
//! item 25 (`25-archival-tc.md`): the **Tier-C notarization** tier.
//! Tier-A is the offline carrier (QR/NFC bytes), Tier-B the online
//! resolution/verdict path; this service is what remains when even the
//! issuer is gone: a **notarized as-of snapshot** of a passport state,
//! re-servable byte-identically, with archival metadata and an optional
//! transparency-log anchor.
//!
//! The domain is **ISO 14721 (OAIS) simplified for digital product
//! passports**: every snapshot document carries three metadata
//! sections —
//!
//! - `oais.submission` — the Submission Information Package (SIP):
//!   who submitted what, when (passport id, state hash, event-log
//!   head, submitter, submitted-at);
//! - `oais.information_package` — the Archival Information Package
//!   (AIP): the preserved content itself — the passport state hash,
//!   log head and the **as-of** instant the snapshot is valid for —
//!   plus the fixity digests (statement digest, anchored commitment);
//! - `oais.provenance` — the Preservation Description Information
//!   (PDI): the notarization trail — service identity, signing key
//!   id, the Ed25519 signature, the anchoring outcome (log id,
//!   receipt id, tree size, root) and the verbatim inclusion receipt
//!   when anchoring succeeded.
//!
//! ## Notarization
//!
//! The snapshot statement (passport id, state hash, log head, as-of
//! instant, sequence, anchoring outcome) is serialized to canonical
//! bytes with [`unidpp_model::CanonicalWriter`] and signed by the
//! service keyring with
//! [`unidpp_signatif::sign::SignatureSlot::sign`] in
//! [`unidpp_signatif::sign::SigningDomain::TreeHead`] — the same
//! adapter note as `unidpp-trust`: SIGNATIF has no
//! archival-notarization domain, and tree-head (the operator's signed
//! statement of state) is the closest documented adaptation. (signatif
//! also defines a `HistoricalStamp` domain — "a notarized historical
//! verification stamp" — which is the semantically exact slot;
//! adopting it is deferred to the `19-signatif-spec-sync` divergence
//! register.) The signature is **embedded in the document**, so the
//! AIP is self-verifying: a verifier rebuilds the canonical bytes from
//! the document fields alone (see [`model::statement_bytes_from_document`]).
//!
//! ## Anchoring
//!
//! When `UNIDPP_LOG_URL` is configured and reachable, the snapshot's
//! commitment (the SHA-256 of the core statement bytes) is POSTed to
//! the transparency log's `POST /commitments` endpoint
//! ([`log_anchor`]); the returned inclusion receipt is journaled with
//! the snapshot (receipt id, log id, tree size, root, and the receipt
//! document verbatim). When the log is unreachable the snapshot is
//! still notarized and stored — `oais.provenance.anchoring.status`
//! says `unanchored` with the reason (the graded-trust doctrine:
//! degrade explicitly, never silently).
//!
//! ## Storage
//!
//! The registry's proven pattern, plus a file store: a JSONL
//! append-only journal is the source of truth, replayed on start with
//! integrity checks (sequence monotonicity, torn-tail tolerance,
//! renderer-drift detection), and each snapshot body is materialized
//! as a file (the AIP) under the snapshot directory — verified on
//! replay, re-materialized when missing, a mismatch is a hard error.
//!
//! Server conventions mirror `unidpp-registry` / `unidpp-resolver` /
//! `unidpp-trust` / `unidpp-log`: axum over tokio,
//! dependency-light, Bearer-guarded mutations, as-of stamped reads.

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]
#![warn(rustdoc::broken_intra_doc_links)]

pub mod api;
pub mod hex;
pub mod http;
pub mod keyring;
pub mod log_anchor;
pub mod model;
pub mod store;
pub mod time;

pub use api::{run, Config, TestServer};
pub use hex::{hex_decode, hex_encode};
pub use keyring::{Keyring, KeyringMode};
pub use log_anchor::LogAnchorConfig;
pub use model::{Anchoring, AnchoringStatus, SnapshotRecord};
pub use store::{SnapshotStore, StoreError};
pub use time::Timestamp;
