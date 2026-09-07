//! Store: in-memory index + append-only JSONL journal + the snapshot
//! file store (the AIP files), with replay on open.
//!
//! The registry's proven pattern (see `unidpp-log/src/store.rs`,
//! `unidpp-registry/src/store.rs`): the journal *is* the storage,
//! nothing is edited in place. Sequencing is strictly monotonic by
//! construction — `append_snapshot` assigns `seq = records.len()`
//! under the caller's lock; the journal replays with the same
//! discipline and refuses any journal whose sequence numbers are not
//! exactly 0, 1, 2, ….
//!
//! Durability vs. torn writes: a crash mid-write can tear only the
//! *final* journal line; a torn tail is tolerated (warned), any
//! corruption earlier in the file is a hard error — an archive must
//! not paper over a hole in the middle.
//!
//! The snapshot files are *derived* from the journal (rendering is a
//! pure function of the record), but they are the archival copies the
//! task's Tier-C storage story promises: on open, every file is
//! verified against the re-rendered body (byte-for-byte) and the
//! journaled `body_digest` (renderer-drift detection); a missing file
//! is re-materialized (self-healing), a mismatching one is a hard
//! integrity error — the AIP on disk must be exactly what was
//! notarized.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use unidpp_model::sha256;

use crate::model::SnapshotRecord;
use crate::time::Timestamp;

/// Store-level failures (journal or AIP integrity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The journal or a snapshot file violates archival integrity.
    Journal(String),
    /// The append conflicts with the journal's spine (wrong seq).
    Conflict(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Journal(m) => write!(f, "journal integrity failure: {m}"),
            StoreError::Conflict(m) => write!(f, "conflict: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// The archive's durable state.
pub struct SnapshotStore {
    records: Vec<SnapshotRecord>,
    journal: Option<File>,
    snapshot_dir: Option<PathBuf>,
}

impl std::fmt::Debug for SnapshotStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotStore")
            .field("size", &self.records.len())
            .field("journaled", &self.journal.is_some())
            .field("file_store", &self.snapshot_dir.is_some())
            .finish()
    }
}

impl SnapshotStore {
    /// Fresh store with an optional JSONL journal and an optional
    /// snapshot directory. Existing journal lines are replayed
    /// (a torn final line is tolerated; anything else is an integrity
    /// error), then every snapshot file is verified or re-materialized.
    pub fn open(
        journal: Option<&Path>,
        snapshot_dir: Option<&Path>,
    ) -> Result<SnapshotStore, StoreError> {
        let mut store = SnapshotStore {
            records: Vec::new(),
            journal: None,
            snapshot_dir: snapshot_dir.map(Path::to_path_buf),
        };
        if let Some(path) = journal {
            prepare_parent(path)?;
            if path.exists() {
                store.replay(path)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| StoreError::Journal(format!("cannot open journal: {e}")))?;
            store.journal = Some(file);
        }
        if let Some(dir) = snapshot_dir {
            std::fs::create_dir_all(dir)
                .map_err(|e| StoreError::Journal(format!("cannot create snapshot dir: {e}")))?;
            store.verify_snapshot_files()?;
        }
        Ok(store)
    }

    fn replay(&mut self, path: &Path) -> Result<(), StoreError> {
        let file = File::open(path)
            .map_err(|e| StoreError::Journal(format!("cannot read journal: {e}")))?;
        let mut lines = BufReader::new(file).lines();
        let mut line_no = 0usize;
        // Read one line ahead so a parse failure on the *last* line can
        // be treated as a torn tail rather than corruption.
        let mut pending = lines
            .next()
            .transpose()
            .map_err(|e| StoreError::Journal(format!("journal read error: {e}")))?;
        while let Some(line) = pending.take() {
            line_no += 1;
            let next = lines
                .next()
                .transpose()
                .map_err(|e| StoreError::Journal(format!("journal read error: {e}")))?;
            let is_last = next.is_none();
            let parsed = serde_json::from_str::<serde_json::Value>(&line)
                .map_err(|e| e.to_string())
                .and_then(|v| SnapshotRecord::from_journal_json(&v));
            match parsed {
                Ok(record) => {
                    if record.seq != self.records.len() as u64 {
                        return Err(StoreError::Journal(format!(
                            "line {line_no}: seq {} is out of sequence (expected {})",
                            record.seq,
                            self.records.len()
                        )));
                    }
                    // Renderer-drift detection: the journaled body
                    // digest must equal today's render of the record.
                    let body = record.render_body();
                    if sha256(&[body.as_bytes()]) != record.body_digest {
                        return Err(StoreError::Journal(format!(
                            "line {line_no}: rendered body digest does not match the journaled digest \
                             (renderer drift or a tampered record)"
                        )));
                    }
                    self.records.push(record);
                }
                Err(e) if is_last && !line.trim().is_empty() => {
                    // Torn tail from a crash mid-write: tolerated loudly.
                    eprintln!(
                        "unidpp-archive: journal ends with a torn line (kept {} snapshots): {e}",
                        self.records.len()
                    );
                }
                Err(e) => {
                    return Err(StoreError::Journal(format!("line {line_no}: {e}")));
                }
            }
            pending = next;
        }
        Ok(())
    }

    /// Verify every snapshot file against the re-rendered body;
    /// re-materialize missing ones; mismatching bytes are a hard
    /// error (the AIP on disk must be what was notarized).
    fn verify_snapshot_files(&mut self) -> Result<(), StoreError> {
        let Some(dir) = self.snapshot_dir.clone() else {
            return Ok(());
        };
        for record in &self.records {
            let path = snapshot_path(&dir, &record.snapshot_id);
            let body = record.render_body();
            match std::fs::read(&path) {
                Ok(bytes) => {
                    if bytes != body.as_bytes() {
                        return Err(StoreError::Journal(format!(
                            "snapshot file {} does not match the journaled record \
                             (tampered or stale)",
                            path.display()
                        )));
                    }
                }
                Err(_) => {
                    std::fs::write(&path, body.as_bytes()).map_err(|e| {
                        StoreError::Journal(format!(
                            "cannot re-materialize snapshot file {}: {e}",
                            path.display()
                        ))
                    })?;
                    eprintln!(
                        "unidpp-archive: re-materialized missing snapshot file {}",
                        path.display()
                    );
                }
            }
        }
        Ok(())
    }

    /// Reserve the next sequence number and the notarization instant
    /// (no journal write — the record is sealed and appended after
    /// the optional anchoring round-trip; the API layer serializes
    /// reservations behind a mutation lock).
    pub fn reserve(&self) -> (u64, Timestamp) {
        (self.records.len() as u64, Timestamp::now())
    }

    /// Append one sealed snapshot: journal the record, write the AIP
    /// file, apply to the index. The record's `seq` must be exactly
    /// the next sequence number.
    pub fn append_snapshot(&mut self, record: &SnapshotRecord) -> Result<(), StoreError> {
        if record.seq != self.records.len() as u64 {
            return Err(StoreError::Conflict(format!(
                "snapshot seq {} is not the next sequence number ({})",
                record.seq,
                self.records.len()
            )));
        }
        let body = record.render_body();
        if sha256(&[body.as_bytes()]) != record.body_digest {
            return Err(StoreError::Journal(
                "record body digest does not match its rendered bytes".into(),
            ));
        }
        if let Some(j) = self.journal.as_mut() {
            let line = serde_json::to_string(&record.to_journal_json())
                .map_err(|e| StoreError::Journal(format!("cannot serialize record: {e}")))?;
            writeln!(j, "{line}")
                .and_then(|_| j.flush())
                .map_err(|e| StoreError::Journal(format!("journal write failed: {e}")))?;
        }
        if let Some(dir) = &self.snapshot_dir {
            let path = snapshot_path(dir, &record.snapshot_id);
            std::fs::write(&path, body.as_bytes()).map_err(|e| {
                StoreError::Journal(format!(
                    "cannot write snapshot file {}: {e}",
                    path.display()
                ))
            })?;
        }
        self.records.push(record.clone());
        Ok(())
    }

    // -- reads -----------------------------------------------------------

    /// Number of snapshots (== the next sequence number).
    pub fn size(&self) -> u64 {
        self.records.len() as u64
    }

    /// The record for a snapshot id.
    pub fn get(&self, snapshot_id: &str) -> Option<&SnapshotRecord> {
        self.records.iter().find(|r| r.snapshot_id == snapshot_id)
    }

    /// As-of listing: every snapshot for `passport_id` (when given)
    /// that existed at `at` (when given — `notarized_at <= at`),
    /// in sequencing order.
    pub fn list(&self, passport_id: Option<&str>, at: Option<Timestamp>) -> Vec<&SnapshotRecord> {
        self.records
            .iter()
            .filter(|r| passport_id.map_or(true, |p| r.passport_id == p))
            .filter(|r| at.map_or(true, |t| r.notarized_at <= t))
            .collect()
    }

    /// The audit view of the journal (derived; ordered).
    pub fn audit_json(&self, limit: usize, offset: usize) -> serde_json::Value {
        let total = self.records.len();
        let slice: Vec<serde_json::Value> = self
            .records
            .iter()
            .skip(offset)
            .take(limit)
            .map(|r| {
                let mut v = r.to_journal_json();
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("body_sha256".into(), serde_json::json!(r.body_digest.hex()));
                }
                v
            })
            .collect();
        serde_json::json!({
            "count": slice.len(),
            "total": total,
            "limit": limit,
            "offset": offset,
            "records": slice,
        })
    }
}

fn snapshot_path(dir: &Path, snapshot_id: &str) -> PathBuf {
    dir.join(format!("{snapshot_id}.json"))
}

fn prepare_parent(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StoreError::Journal(format!("cannot create journal dir: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnchorSummary, Anchoring};
    use serde_json::json;
    use unidpp_model::Hash;
    use unidpp_signatif::keyring::KeyPair;
    use unidpp_signatif::sign::Suite;

    fn hash_of(tag: &str) -> Hash {
        sha256(&[tag.as_bytes()])
    }

    fn notary() -> KeyPair {
        KeyPair::seeded(Suite::Ed25519, b"store-notary").unwrap()
    }

    fn sealed(seq: u64, at: i64) -> SnapshotRecord {
        let mut r = SnapshotRecord::new(
            seq,
            Timestamp::from_secs(at),
            format!("urn:unidpp:passport:p-{seq}"),
            hash_of(&format!("s-{seq}")),
            hash_of(&format!("h-{seq}")),
            None,
            None,
        );
        r.seal(&notary()).unwrap();
        r
    }

    fn dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("unidpp-archive-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sequencing_is_strictly_monotonic() {
        let mut store = SnapshotStore::open(None, None).unwrap();
        assert_eq!(store.size(), 0);
        for seq in 0..5u64 {
            let (reserved, _) = store.reserve();
            assert_eq!(reserved, seq);
            let rec = sealed(seq, 100 + seq as i64);
            store.append_snapshot(&rec).unwrap();
        }
        assert_eq!(store.size(), 5);
        assert!(store.get("s-000000000004").is_some());
        assert!(store.get("s-000000000005").is_none());
        // A stale reservation is a conflict, never a silent overwrite.
        let err = store.append_snapshot(&sealed(2, 999)).unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[test]
    fn journal_round_trip_reproduces_identical_bodies() {
        let d = dir("roundtrip");
        let journal = d.join("journal.jsonl");
        let snaps = d.join("snapshots");
        let mut first_body = None;
        {
            let mut store = SnapshotStore::open(Some(&journal), Some(&snaps)).unwrap();
            for seq in 0..3u64 {
                let rec = sealed(seq, 1_900_000_000 + seq as i64);
                store.append_snapshot(&rec).unwrap();
                if seq == 1 {
                    first_body = Some(rec.render_body());
                }
            }
            assert_eq!(store.size(), 3);
        }
        let mut store = SnapshotStore::open(Some(&journal), Some(&snaps)).unwrap();
        assert_eq!(store.size(), 3);
        assert_eq!(
            store.get("s-000000000001").unwrap().render_body(),
            first_body.unwrap()
        );
        // The AIP files exist and match.
        for seq in 0..3u64 {
            let id = format!("s-{seq:012}");
            let bytes = std::fs::read(snaps.join(format!("{id}.json"))).unwrap();
            assert_eq!(bytes, store.get(&id).unwrap().render_body().as_bytes());
        }
        // Appends continue the sequence after a restart.
        let rec = sealed(3, 1_900_000_100);
        store.append_snapshot(&rec).unwrap();
        assert_eq!(store.size(), 4);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn journal_with_a_sequence_gap_is_refused() {
        let d = dir("gap");
        let journal = d.join("journal.jsonl");
        {
            let mut store = SnapshotStore::open(Some(&journal), None).unwrap();
            store.append_snapshot(&sealed(0, 1)).unwrap();
        }
        let line = std::fs::read_to_string(&journal).unwrap();
        let tampered = line.replace("\"seq\":0", "\"seq\":5");
        std::fs::write(&journal, tampered).unwrap();
        let err = SnapshotStore::open(Some(&journal), None).unwrap_err();
        assert!(matches!(err, StoreError::Journal(_)));
        assert!(err.to_string().contains("out of sequence"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn torn_tail_is_tolerated_but_mid_file_corruption_is_refused() {
        let d = dir("torn");
        let journal = d.join("journal.jsonl");
        {
            let mut store = SnapshotStore::open(Some(&journal), None).unwrap();
            for seq in 0..3u64 {
                store.append_snapshot(&sealed(seq, seq as i64)).unwrap();
            }
        }
        // Mid-file corruption (line 2 mangled): hard error.
        let good = std::fs::read_to_string(&journal).unwrap();
        let mut lines: Vec<&str> = good.lines().collect();
        lines[1] = "{\"seq\": 1, \"broken\"";
        std::fs::write(&journal, lines.join("\n") + "\n").unwrap();
        assert!(SnapshotStore::open(Some(&journal), None).is_err());

        // Torn final line (crash mid-write): tolerated, earlier
        // snapshots replay and the sequence continues.
        let mut lines: Vec<&str> = good.lines().collect();
        lines.push("{\"seq\": 3, \"passport_id\": \"x\"");
        std::fs::write(&journal, lines.join("\n")).unwrap();
        let mut store = SnapshotStore::open(Some(&journal), None).unwrap();
        assert_eq!(store.size(), 3);
        store.append_snapshot(&sealed(3, 9)).unwrap();
        assert_eq!(store.size(), 4);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_aip_file_is_detected_and_missing_files_heal() {
        let d = dir("aip");
        let journal = d.join("journal.jsonl");
        let snaps = d.join("snapshots");
        {
            let mut store = SnapshotStore::open(Some(&journal), Some(&snaps)).unwrap();
            store.append_snapshot(&sealed(0, 10)).unwrap();
            store.append_snapshot(&sealed(1, 11)).unwrap();
        }
        // Missing file: re-materialized on open.
        std::fs::remove_file(snaps.join("s-000000000001.json")).unwrap();
        let store = SnapshotStore::open(Some(&journal), Some(&snaps)).unwrap();
        assert_eq!(store.size(), 2);
        assert!(snaps.join("s-000000000001.json").exists());

        // Tampered file: hard integrity error.
        let path = snaps.join("s-000000000000.json");
        std::fs::write(&path, b"{\"tampered\": true}\n").unwrap();
        let err = SnapshotStore::open(Some(&journal), Some(&snaps)).unwrap_err();
        assert!(matches!(err, StoreError::Journal(_)));
        assert!(err.to_string().contains("does not match"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_journal_record_breaks_the_body_digest_check() {
        let d = dir("digest");
        let journal = d.join("journal.jsonl");
        {
            let mut store = SnapshotStore::open(Some(&journal), None).unwrap();
            store.append_snapshot(&sealed(0, 20)).unwrap();
        }
        // Rewrite the passport id without updating the digest.
        let line = std::fs::read_to_string(&journal).unwrap();
        let tampered = line.replace("urn:unidpp:passport:p-0", "urn:unidpp:passport:evil");
        std::fs::write(&journal, tampered).unwrap();
        let err = SnapshotStore::open(Some(&journal), None).unwrap_err();
        assert!(matches!(err, StoreError::Journal(_)));
        assert!(err.to_string().contains("digest"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn as_of_listing_filters_by_passport_and_time() {
        let mut store = SnapshotStore::open(None, None).unwrap();
        let mut a = sealed(0, 1_000);
        a.passport_id = "urn:p:a".into();
        let mut b = sealed(1, 2_000);
        b.passport_id = "urn:p:b".into();
        let mut a2 = sealed(2, 3_000);
        a2.passport_id = "urn:p:a".into();
        // Re-seal: the passport id is part of the signed statement.
        for r in [&mut a, &mut b, &mut a2] {
            r.seal(&notary()).unwrap();
            store.append_snapshot(r).unwrap();
        }
        assert_eq!(store.list(None, None).len(), 3);
        assert_eq!(store.list(Some("urn:p:a"), None).len(), 2);
        assert_eq!(store.list(Some("urn:p:b"), None).len(), 1);
        assert_eq!(store.list(Some("urn:p:zz"), None).len(), 0);
        // As-of: only snapshots notarized at or before the instant.
        assert_eq!(store.list(None, Some(Timestamp::from_secs(999))).len(), 0);
        assert_eq!(store.list(None, Some(Timestamp::from_secs(1_000))).len(), 1);
        assert_eq!(store.list(None, Some(Timestamp::from_secs(2_500))).len(), 2);
        assert_eq!(
            store
                .list(Some("urn:p:a"), Some(Timestamp::from_secs(2_500)))
                .len(),
            1
        );
    }

    #[test]
    fn audit_view_is_paginated() {
        let mut store = SnapshotStore::open(None, None).unwrap();
        for seq in 0..3u64 {
            store.append_snapshot(&sealed(seq, seq as i64)).unwrap();
        }
        let v = store.audit_json(2, 1);
        assert_eq!(v["total"], 3);
        assert_eq!(v["count"], 2);
        assert_eq!(v["records"][0]["seq"], 1);
        assert!(v["records"][0]["body_sha256"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn anchored_records_round_trip_through_the_journal() {
        let d = dir("anchored");
        let journal = d.join("journal.jsonl");
        let receipt = json!({
            "receipt_id": "5",
            "log_id": "t-log",
            "seq": 5,
            "logged_at": "2026-09-07T00:00:00Z",
            "tree_head": {"tree_size": 6, "root": hash_of("r").hex()},
        });
        let summary = AnchorSummary {
            log_id: "t-log".into(),
            receipt_seq: 5,
            tree_size: 6,
            root: hash_of("r"),
            logged_at: Timestamp::from_secs(0),
        };
        {
            let mut store = SnapshotStore::open(Some(&journal), None).unwrap();
            let mut rec = sealed(0, 42);
            rec.set_anchoring(Anchoring::anchored(
                summary.clone(),
                receipt.clone(),
                rec.commitment(),
            ));
            rec.seal(&notary()).unwrap();
            store.append_snapshot(&rec).unwrap();
        }
        let store = SnapshotStore::open(Some(&journal), None).unwrap();
        let rec = store.get("s-000000000000").unwrap();
        assert_eq!(
            rec.anchoring.status,
            crate::model::AnchoringStatus::Anchored
        );
        assert_eq!(rec.anchoring.receipt_seq, Some(5));
        assert_eq!(rec.anchoring.receipt, Some(receipt));
        let _ = std::fs::remove_dir_all(&d);
    }
}
