//! The transparency-log anchoring hop: POST a snapshot commitment to
//! a `unidpp-log` instance's `POST /commitments` endpoint and parse
//! the inclusion receipt. When the log is not configured or not
//! reachable, the caller falls back to an unanchored (still
//! notarized) snapshot — the graded-trust doctrine: degrade
//! explicitly, never silently; the reason is recorded in the
//! snapshot's OAIS provenance and the audit journal.
//!
//! All transport rides the hand-rolled [`crate::http`] client (the
//! house pattern); `http://` only — the log is a sibling service on
//! loopback or inside the same trust boundary.

use std::time::Duration;

use serde_json::{json, Value};
use unidpp_model::Hash;

/// The default anchoring timeout (a log that cannot answer in time is
/// treated as unreachable — the snapshot must not hang on it).
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;

/// Where and how to reach the transparency log.
#[derive(Debug, Clone)]
pub struct LogAnchorConfig {
    /// Base URL of a `unidpp-log` instance (`UNIDPP_LOG_URL`), e.g.
    /// `http://127.0.0.1:8092`. `None` disables anchoring entirely.
    pub base_url: Option<String>,
    /// Optional Bearer token for the log's append guard
    /// (`UNIDPP_ARCHIVE_LOG_TOKEN`; matches the log's
    /// `UNIDPP_LOG_APPEND_TOKEN`).
    pub bearer: Option<String>,
    /// Per-request timeout (`UNIDPP_ARCHIVE_LOG_TIMEOUT_MS`).
    pub timeout: Duration,
}

impl Default for LogAnchorConfig {
    fn default() -> LogAnchorConfig {
        LogAnchorConfig {
            base_url: None,
            bearer: None,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl LogAnchorConfig {
    /// Anchoring disabled (no `UNIDPP_LOG_URL`).
    pub fn disabled() -> LogAnchorConfig {
        LogAnchorConfig::default()
    }

    /// Anchoring enabled against `base` with the default timeout.
    pub fn enabled(base: impl Into<String>) -> LogAnchorConfig {
        LogAnchorConfig {
            base_url: Some(base.into()),
            ..LogAnchorConfig::default()
        }
    }

    /// Resolve from environment variables.
    pub fn from_env() -> LogAnchorConfig {
        let mut cfg = LogAnchorConfig::default();
        if let Ok(url) = std::env::var("UNIDPP_LOG_URL") {
            if !url.trim().is_empty() {
                cfg.base_url = Some(url.trim().to_string());
            }
        }
        if let Ok(token) = std::env::var("UNIDPP_ARCHIVE_LOG_TOKEN") {
            if !token.trim().is_empty() {
                cfg.bearer = Some(token.trim().to_string());
            }
        }
        if let Ok(ms) = std::env::var("UNIDPP_ARCHIVE_LOG_TIMEOUT_MS") {
            if let Ok(ms) = ms.trim().parse::<u64>() {
                if ms > 0 {
                    cfg.timeout = Duration::from_millis(ms);
                }
            }
        }
        cfg
    }

    /// Whether anchoring will be attempted.
    pub fn is_enabled(&self) -> bool {
        self.base_url.is_some()
    }
}

/// Anchor `commitment` under `subject` and return the log's inclusion
/// receipt (the verbatim JSON of the `POST /commitments` response).
/// The receipt is validated for the anchored fields by the caller via
/// [`crate::model::anchor_summary_from_receipt`]; this function
/// checks only that the log answered with a JSON 2xx.
pub async fn anchor(
    config: &LogAnchorConfig,
    subject: &str,
    commitment: Hash,
) -> Result<Value, String> {
    let base = config
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "log anchoring not configured (UNIDPP_LOG_URL is unset)".to_string())?
        .trim_end_matches('/')
        .to_string();
    let url = format!("{base}/commitments");
    let body = json!({
        "subject": subject,
        "commitment": commitment.hex(),
    });
    let resp = crate::http::json_request(
        "POST",
        &url,
        Some(&body.to_string()),
        config.bearer.as_deref(),
        config.timeout,
    )
    .await
    .map_err(|e| format!("log unreachable: {e}"))?;
    if !(200..300).contains(&resp.status) {
        let snippet: String = resp.body_string().chars().take(200).collect();
        let detail = if snippet.is_empty() {
            String::new()
        } else {
            format!(": {snippet}")
        };
        return Err(format!(
            "log refused the commitment: {}{detail}",
            resp.status
        ));
    }
    serde_json::from_str(&resp.body_string())
        .map_err(|e| format!("log returned a non-JSON receipt: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_defaults_to_disabled() {
        // No UNIDPP_LOG_URL in the test environment (the integration
        // suite sets it explicitly around spawned servers).
        let cfg = LogAnchorConfig::disabled();
        assert!(!cfg.is_enabled());
        assert_eq!(cfg.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        let enabled = LogAnchorConfig::enabled("http://127.0.0.1:8092");
        assert!(enabled.is_enabled());
        assert_eq!(enabled.base_url.as_deref(), Some("http://127.0.0.1:8092"));
    }

    #[tokio::test]
    async fn anchoring_without_configuration_errors() {
        let err = anchor(
            &LogAnchorConfig::disabled(),
            "s",
            unidpp_model::sha256(&[b"x"]),
        )
        .await
        .unwrap_err();
        assert!(err.contains("not configured"));
    }

    #[tokio::test]
    async fn anchoring_to_a_dead_port_errors_as_unreachable() {
        // Bind an ephemeral listener, note the port, drop it — the
        // port is now closed, so the connect is refused immediately.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let cfg = LogAnchorConfig::enabled(format!("http://127.0.0.1:{port}"));
        let err = anchor(&cfg, "s", unidpp_model::sha256(&[b"x"]))
            .await
            .unwrap_err();
        assert!(err.contains("log unreachable"), "got: {err}");
    }

    #[tokio::test]
    async fn anchoring_to_a_garbage_url_errors() {
        let cfg = LogAnchorConfig {
            base_url: Some("not a url".into()),
            ..LogAnchorConfig::default()
        };
        assert!(anchor(&cfg, "s", unidpp_model::sha256(&[b"x"]))
            .await
            .is_err());
    }
}
