# unidpp-archive

The UniDPP **Tier-C notarized archive service**: as-of snapshot packs
for digital product passports, with ISO 14721 (OAIS)-style metadata,
Ed25519 notarization via `unidpp-signatif`, optional transparency-log
anchoring via `unidpp-log`, and byte-identical re-serving. Part of
[UniDPP](https://github.com/unidpp); `10-remaining-tasks-definitive.md`
item 25 (`25-archival-tc.md`, dispatch C3 — "Tier-C notarized snapshot
service, R2 target"). Apache-2.0.

## What this is

Tier-A is the offline carrier (QR/NFC bytes). Tier-B is the online
resolution/verdict path. **Tier-C is what remains when even the issuer
is gone**: a notarized, timestamped snapshot of a passport state
(passport id + state hash + event-log head), archived with metadata an
auditor can read decades later and a signature an offline verifier can
check today.

A snapshot is created by `POST /snapshots {passport_id, state_hash,
log_head}`. The service:

1. **stamps** it (a server-side as-of instant — the notarization is
   the archive's own clock, journaled and preserved across restarts);
2. **notarizes** it — signs the canonical statement bytes with the
   service's Ed25519 notary key in `unidpp-signatif`'s **tree-head**
   domain (see the adapter note below) and embeds the signature in the
   document, so the archival package is self-verifying;
3. **optionally anchors** the statement commitment into a
   transparency log (`POST {UNIDPP_LOG_URL}/commitments` on a
   `unidpp-log` instance); the inclusion receipt — receipt id, log id,
   tree size, root, and the receipt document verbatim — is journaled
   with the snapshot. If the log is unreachable or refuses, the
   snapshot degrades **explicitly** to `anchoring.status = unanchored`
   with the reason recorded (graded trust, never silent);
4. **stores** it durably: an append-only JSONL journal (the source of
   truth) plus one JSON file per snapshot (the archival copies),
   replayed and cross-verified on every start.

`GET /snapshots/{id}` re-serves the exact same bytes, forever.

## Endpoints

| Endpoint | Meaning |
|---|---|
| `GET /` | discovery document: OAIS mapping, notarization recipe, anchoring and storage story |
| `GET /healthz` | liveness (snapshot count, anchoring enabled) |
| `GET /keyring` | the notary anchor (suite, key id, hex public key, verification recipe) |
| `POST /snapshots` | ingest: `{passport_id, state_hash, log_head, submitter?, state_size?}` → the notarized document, `201`, `Location`, strong `ETag` |
| `GET /snapshots/{id}` | access: re-serve the archival package **byte-identically** (`immutable`, strong `ETag`) |
| `GET /snapshots?passport_id=&at=` | as-of catalogue: snapshots for a passport that existed at instant `at` (RFC 3339; `x-as-of` header + `as_of` field on every response) |
| `GET /admin/log?limit=&offset=` | the append-only audit journal |

`POST /snapshots` and `/admin/log` require a Bearer token when
`UNIDPP_ARCHIVE_ADMIN_TOKEN` is set; reads are public (an archive's
whole point is re-serving).

## The OAIS mapping (ISO 14721, simplified for passports)

Every snapshot document carries three metadata sections:

| Document path | OAIS concept | Contents |
|---|---|---|
| `oais.submission` | Submission Information Package (SIP) — what the Producer handed over | `submitter`, `submitted_at`, and the submitted `{passport_id, state_hash, log_head, state_size}` |
| `oais.information_package` | Archival Information Package (AIP) — the preserved content | passport id, state hash, log head, the **`as_of`** instant the snapshot is valid for, and the fixity values (`commitment`, `statement_digest`) |
| `oais.provenance` | Preservation Description Information (PDI) — how the AIP came to be | the notarization (`signing.suite/key_id/domain`, the `signature`), the anchoring outcome (`status`, `reason`, `log_id`, `receipt_id`, `tree_size`, `root`, `logged_at`), the verbatim log `receipt`, and the verification recipe |

The surrounding OAIS functional entities map onto the service surface:
Producer → the `POST /snapshots` body; Ingest → the create handler
(validate, stamp, notarize, anchor, journal); Archival Storage → the
journal + snapshot files; Data Management → the as-of listing; Access
→ byte-identical re-serving (access never changes the AIP);
Administration → `/keyring`, `/admin/log`, the Bearer guard. The full
mapping is in the discovery document (`GET /`).

## Verifying a snapshot

The document is self-verifying against the `/keyring` anchor:

```rust
// 1. Rebuild the canonical core statement bytes:
//    CanonicalWriter: str("unidpp-archive"), str(snapshot_id), u64(seq),
//    str(oais.information_package.passport_id), hash(state_hash),
//    hash(log_head), i64(as_of.secs)
// 2. Append the anchoring outcome: u32(0) when unanchored, else
//    u32(1), str(log_id), u64(receipt_id), u64(tree_size), hash(root)
//    (unidpp_archive::model::statement_bytes_from_document does this
//    from the document alone).
let statement = statement_bytes_from_document(&doc)?;
let slot = SignatureSlot { suite: Suite::Ed25519, /* key_id, signature from the document */ };
slot.verify(SigningDomain::TreeHead, &statement, &notary_public_key)?;

// 3. Fixity: sha256(core) == oais.information_package.commitment
//    (and == the embedded receipt's commitment when anchored).
// 4. (When anchored) the full receipt chain also verifies offline:
//    STH signature under the log operator key + Merkle inclusion —
//    see unidpp-signatif::verify_inclusion.
```

The integration tests are the executable form of these checks,
including the tamper rejections.

## Notarization adapter note

The signature uses `unidpp-signatif`'s **tree-head** domain with the
same adapter note as `unidpp-trust`: SIGNATIF has no
archival-notarization domain; tree-head (the operator's signed
statement of state, used for transparency-log signed tree heads) is
the closest documented adaptation. signatif also defines a
`HistoricalStamp` domain ("a notarized historical verification stamp")
which is the semantically exact slot; adopting it is deferred to the
`19-signatif-spec-sync` divergence register. Unlike `unidpp-trust`
(which co-signs mutable response bodies in headers), the archive's
signature covers the **canonical statement bytes** and is **embedded
in the document** — the AIP carries its own proof.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `UNIDPP_ARCHIVE_BIND` | listen address | `127.0.0.1:8095` |
| `UNIDPP_ARCHIVE_ADMIN_TOKEN` | Bearer token for ingest + audit | open (dev) |
| `UNIDPP_ARCHIVE_STATE_FILE` | JSONL journal path (replayed on start) | none (memory only) |
| `UNIDPP_ARCHIVE_SNAPSHOT_DIR` | snapshot file store (one JSON per AIP) | none |
| `UNIDPP_ARCHIVE_SIGN_SEED` | hex seed for the notary key (production) | — |
| `UNIDPP_ARCHIVE_DEV_SEED` | deterministic dev seed (development only) | `unidpp-archive/dev-1` |
| `UNIDPP_LOG_URL` | base URL of a `unidpp-log` instance for anchoring | unset = unanchored |
| `UNIDPP_ARCHIVE_LOG_TOKEN` | Bearer token for the log's append guard | none |
| `UNIDPP_ARCHIVE_LOG_TIMEOUT_MS` | anchoring timeout | 3000 |

Production: supply `UNIDPP_ARCHIVE_SIGN_SEED` (hex, at least 16 bytes,
from a CSPRNG ceremony — the service warns loudly in seeded-dev mode),
put the journal and snapshot dir on durable storage, and front the
service with TLS. The Cloudflare deployment map (`33-cf-deployment.md`)
targets R2 for the Tier-C snapshot store; the file layout here (one
immutable JSON object per snapshot) is the R2 object model already.

## Storage and replay

The registry's proven pattern plus a file store:

- the **JSONL journal** is the source of truth — every append is one
  line, flushed before the response; replay on start re-applies lines
  in order and refuses gaps, mid-file corruption, or records whose
  re-rendered body no longer matches the journaled digest (renderer
  drift / tamper detection). A torn final line (crash mid-write) is
  tolerated loudly;
- the **snapshot files** are the archival copies: on start each file
  is compared byte-for-byte against the re-rendered document — a
  missing file is re-materialized (self-healing), a mismatching file
  is a hard error (the archive must not serve what was not notarized);
- the served body is a pure function of the journaled record, so
  restart replay reproduces **byte-identical** documents — the
  property the restart tests pin.

## Running

```sh
cargo run            # 127.0.0.1:8095, dev keyring, no anchoring
UNIDPP_LOG_URL=http://127.0.0.1:8092 \
UNIDPP_ARCHIVE_STATE_FILE=/var/lib/unidpp-archive/journal.jsonl \
UNIDPP_ARCHIVE_SNAPSHOT_DIR=/var/lib/unidpp-archive/snapshots \
cargo run
```

Example:

```sh
curl -s -X POST localhost:8095/snapshots -H 'content-type: application/json' \
  -d '{"passport_id":"urn:unidpp:passport:e8",
       "state_hash":"<64-hex>","log_head":"<64-hex>",
       "submitter":"urn:unidpp:actor:issuer-1"}'
curl -s localhost:8095/snapshots/s-000000000000          # byte-identical
curl -s 'localhost:8095/snapshots?passport_id=urn%3Aunidpp%3Apassport%3Ae8&at=2026-09-07T12:00:00Z'
```

## Tests

`cargo test` — 43 unit + 10 integration tests: notarization sign /
verify / tamper-reject, byte-identical re-serving (live and across
restart replay), as-of listing semantics, journal integrity (gaps,
torn tails, tampered records, tampered AIP files), keyring modes,
anchoring against a real spawned `unidpp-log` (full receipt chain:
operator signature + Merkle inclusion + commitment binding) and the
explicit unanchored fallback, admin auth, and input validation.
`cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`
are clean.
