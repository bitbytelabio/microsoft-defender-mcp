//! Delegated (user) session state: secrets, audiences, consent, and the startup status line.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::DateTime;
use serde::{Deserialize, Serialize};

/// A secret credential string whose `Debug` implementation is permanently redacted.
///
/// It deliberately does not implement `Display`, `Serialize`, or `Clone` to prevent accidental
/// leakage across logs, tool responses, and IPC. Material can be inspected only via [`Secret::expose`]
/// for form encoding and token transmission.
pub struct Secret(String);

impl Secret {
    /// Create a new secret wrapper.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Expose the underlying secret value as a string slice for HTTP form encoding or headers.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<redacted>)")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Supported resource audiences for delegated sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// Microsoft Defender for Endpoint API.
    Endpoint,
    /// Microsoft Graph API.
    Graph,
}

impl Audience {
    /// Returns the canonical resource URL for this audience.
    pub fn resource_url(&self) -> &'static str {
        match self {
            Self::Endpoint => "https://api.securitycenter.microsoft.com",
            Self::Graph => "https://graph.microsoft.com",
        }
    }

    /// Returns the audience identifier as a lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Graph => "graph",
        }
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The consent state of an audience in a delegated session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentState {
    /// The audience was consented and an access token was granted.
    Granted {
        /// Scopes granted by the IdP response.
        scopes: Vec<String>,
        /// Expiry timestamp in seconds since Unix epoch.
        expires_at: i64,
    },
    /// Consent is missing for this audience.
    Missing {
        /// Optional AADSTS error code (e.g., 65001 for consent missing).
        aadsts: Option<u32>,
    },
}

impl ConsentState {
    /// Returns true if this consent state is [`ConsentState::Granted`].
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }
}

/// Reasons why silent re-authentication failed and the server cannot renew credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReauthReason {
    /// The session expired (AADSTS700082, AADSTS70043, AADSTS50173).
    SessionExpired,
    /// Multi-factor authentication is required (AADSTS50076, AADSTS50079).
    MfaRequired,
    /// Interactive sign-in is required (`interaction_required`).
    InteractionRequired,
    /// The user session or refresh token was revoked.
    SessionRevoked,
    /// A conditional access policy challenge occurred (claims challenge).
    ConditionalAccess,
}

impl ReauthReason {
    /// Return the snake_case string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SessionExpired => "session_expired",
            Self::MfaRequired => "mfa_required",
            Self::InteractionRequired => "interaction_required",
            Self::SessionRevoked => "session_revoked",
            Self::ConditionalAccess => "conditional_access",
        }
    }
}

impl fmt::Display for ReauthReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Decoded claims from an OpenID Connect ID token.
///
/// Decoded display-only via base64url payload extraction without cryptographic signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct IdTokenClaims {
    /// Preferred username of the signed-in user (e.g. `alice@contoso.com`).
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Tenant ID (GUID).
    #[serde(default)]
    pub tid: Option<String>,
    /// Object ID (GUID) of the user principal.
    #[serde(default)]
    pub oid: Option<String>,
    /// User principal name fallback.
    #[serde(default)]
    pub upn: Option<String>,
    /// Email fallback.
    #[serde(default)]
    pub email: Option<String>,
}

impl IdTokenClaims {
    /// Return the most descriptive account name available.
    pub fn account_name(&self) -> Option<&str> {
        self.preferred_username
            .as_deref()
            .or(self.upn.as_deref())
            .or(self.email.as_deref())
            .or(self.oid.as_deref())
    }
}

/// Errors occurring during ID token claim decoding.
#[derive(Debug, thiserror::Error)]
pub enum IdTokenError {
    /// The token does not have standard dot-separated JWT segments.
    #[error("invalid JWT format: expected at least two dot-separated segments")]
    InvalidFormat,
    /// Base64url decoding failed.
    #[error("failed to base64url decode ID token payload: {0}")]
    Base64(#[from] base64::DecodeError),
    /// JSON parsing of claims failed.
    #[error("failed to parse ID token JSON claims: {0}")]
    Json(#[from] serde_json::Error),
}

/// Decode claims from an unencrypted ID token JWT.
///
/// Uses URL_SAFE_NO_PAD base64 decoding (tolerant of trailing `=`).
pub fn decode_id_token_claims(id_token: &str) -> Result<IdTokenClaims, IdTokenError> {
    let mut parts = id_token.split('.');
    let _header = parts.next().ok_or(IdTokenError::InvalidFormat)?;
    let payload = parts.next().ok_or(IdTokenError::InvalidFormat)?;

    let unpadded = payload.trim_end_matches('=');
    let decoded = URL_SAFE_NO_PAD.decode(unpadded)?;
    let claims: IdTokenClaims = serde_json::from_slice(&decoded)?;
    Ok(claims)
}

/// In-memory state for an active delegated user session.
pub struct DelegatedSession {
    /// Account display name or UPN of the signed-in user.
    pub account: String,
    /// Entra ID tenant ID.
    pub tenant_id: String,
    /// Active rotating refresh token.
    pub refresh_token: Mutex<Secret>,
    /// Scopes requested at sign-in.
    pub scopes: Vec<String>,
    /// Initial and updated consent states per audience.
    pub consent: std::sync::RwLock<HashMap<Audience, ConsentState>>,
    /// Once set, any further token acquisition fails immediately without network calls.
    pub reauth: OnceLock<ReauthReason>,
}

impl DelegatedSession {
    /// Create a new DelegatedSession instance.
    pub fn new(
        account: impl Into<String>,
        tenant_id: impl Into<String>,
        refresh_token: Secret,
        scopes: Vec<String>,
        consent: HashMap<Audience, ConsentState>,
    ) -> Self {
        Self {
            account: account.into(),
            tenant_id: tenant_id.into(),
            refresh_token: Mutex::new(refresh_token),
            scopes,
            consent: std::sync::RwLock::new(consent),
            reauth: OnceLock::new(),
        }
    }

    /// Record a re-authentication requirement reason.
    pub fn set_reauth(&self, reason: ReauthReason) {
        let _ = self.reauth.set(reason);
    }

    /// Return the consent state for the specified audience.
    pub fn consent_state(&self, audience: &Audience) -> Option<ConsentState> {
        self.consent.read().unwrap().get(audience).cloned()
    }

    /// Update the consent state for the specified audience.
    pub fn set_consent(&self, audience: Audience, state: ConsentState) {
        self.consent.write().unwrap().insert(audience, state);
    }

    /// Formats the single status line for stderr per `contracts/auth-session.md §Status line`.
    pub fn status_line(&self) -> String {
        format_status_line(self)
    }
}

impl fmt::Debug for DelegatedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedSession")
            .field("account", &self.account)
            .field("tenant_id", &self.tenant_id)
            .field("refresh_token", &self.refresh_token)
            .field("scopes", &self.scopes)
            .field("consent", &self.consent)
            .field("reauth", &self.reauth)
            .finish()
    }
}

/// Helper to clean scope names by stripping audience resource URLs.
fn clean_scope_name(scope: &str) -> &str {
    scope
        .strip_prefix("https://api.securitycenter.microsoft.com/")
        .or_else(|| scope.strip_prefix("https://graph.microsoft.com/"))
        .unwrap_or(scope)
}

/// Formats the audience status section of the status line.
fn format_audience_section(
    audience: Audience,
    consent: Option<&ConsentState>,
    requested_scopes: &[String],
) -> String {
    let aud_name = audience.as_str();
    match consent {
        Some(ConsentState::Granted { scopes, expires_at }) => {
            let expires_str = DateTime::from_timestamp(*expires_at, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| format!("{expires_at}s"));

            if scopes.is_empty() {
                format!("{aud_name}: (expires {expires_str})")
            } else {
                let cleaned_scopes: Vec<&str> =
                    scopes.iter().map(|s| clean_scope_name(s.as_str())).collect();
                format!("{aud_name}: {} (expires {expires_str})", cleaned_scopes.join(" "))
            }
        }
        Some(ConsentState::Missing { aadsts }) => {
            let mut sec = format!("{aud_name}: consent missing");
            if let Some(code) = aadsts {
                sec.push_str(&format!(" (AADSTS{code})"));
            }

            // Find requested scopes matching this audience
            let prefix = format!("{}/", audience.resource_url());
            let missing_scopes: Vec<&str> = requested_scopes
                .iter()
                .filter(|s| s.starts_with(&prefix))
                .map(|s| clean_scope_name(s.as_str()))
                .collect();

            if !missing_scopes.is_empty() {
                sec.push_str(&format!(" — grant admin consent for {}", missing_scopes.join(" ")));
            }
            sec
        }
        None => format!("{aud_name}: not configured"),
    }
}

/// Format the single status line printed once on stderr at startup.
///
/// Shape:
/// `Signed in as <account> (tenant <tenant>) | endpoint: <endpoint_status> | graph: <graph_status>`
pub fn format_status_line(session: &DelegatedSession) -> String {
    let consent_guard = session.consent.read().unwrap();
    let endpoint_sec = format_audience_section(
        Audience::Endpoint,
        consent_guard.get(&Audience::Endpoint),
        &session.scopes,
    );
    let graph_sec = format_audience_section(
        Audience::Graph,
        consent_guard.get(&Audience::Graph),
        &session.scopes,
    );
    format!(
        "Signed in as {} (tenant {}) | {} | {}",
        session.account, session.tenant_id, endpoint_sec, graph_sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_debug_redaction() {
        let secret = Secret::new("SENTINEL-SUPER-SECRET-TOKEN");
        let debug_str = format!("{:?}", secret);
        assert_eq!(debug_str, "Secret(<redacted>)");
        assert!(!debug_str.contains("SENTINEL"));
        assert!(!debug_str.contains("SUPER-SECRET"));
        assert_eq!(secret.expose(), "SENTINEL-SUPER-SECRET-TOKEN");
    }

    #[test]
    fn test_reauth_reason_serde() {
        let reasons = [
            (ReauthReason::SessionExpired, "\"session_expired\""),
            (ReauthReason::MfaRequired, "\"mfa_required\""),
            (ReauthReason::InteractionRequired, "\"interaction_required\""),
            (ReauthReason::SessionRevoked, "\"session_revoked\""),
            (ReauthReason::ConditionalAccess, "\"conditional_access\""),
        ];

        for (reason, json) in reasons {
            let serialized = serde_json::to_string(&reason).expect("serialize");
            assert_eq!(serialized, json);
            let deserialized: ReauthReason = serde_json::from_str(json).expect("deserialize");
            assert_eq!(deserialized, reason);
        }
    }

    #[test]
    fn test_id_token_claim_decoding() {
        // Construct a mock JWT payload: header.payload.signature
        // Payload with preferred_username, tid, oid
        let payload_json = serde_json::json!({
            "preferred_username": "alice@contoso.com",
            "tid": "72f988bf-1234-5678-9abc-def012345678",
            "oid": "00000000-0000-0000-0000-000000000001",
            "sub": "user-sub-123"
        });
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.to_string());
        let jwt = format!("eyJhbGciOiJub25lIn0.{}.mock_signature", payload_b64);

        let claims = decode_id_token_claims(&jwt).expect("decode id token claims");
        assert_eq!(claims.preferred_username.as_deref(), Some("alice@contoso.com"));
        assert_eq!(claims.tid.as_deref(), Some("72f988bf-1234-5678-9abc-def012345678"));
        assert_eq!(claims.oid.as_deref(), Some("00000000-0000-0000-0000-000000000001"));
        assert_eq!(claims.account_name(), Some("alice@contoso.com"));
    }

    #[test]
    fn test_id_token_claim_decoding_with_padding() {
        let payload_json = serde_json::json!({
            "preferred_username": "bob@example.com",
            "tid": "tenant-xyz"
        });
        // Base64 with padding =
        let payload_b64_padded = format!("{}=", URL_SAFE_NO_PAD.encode(payload_json.to_string()));
        let jwt = format!("hdr.{}.sig", payload_b64_padded);

        let claims = decode_id_token_claims(&jwt).expect("decode id token claims with padding");
        assert_eq!(claims.preferred_username.as_deref(), Some("bob@example.com"));
        assert_eq!(claims.tid.as_deref(), Some("tenant-xyz"));
    }

    #[test]
    fn test_id_token_claim_decoding_invalid() {
        assert!(decode_id_token_claims("no-dots").is_err());
        assert!(decode_id_token_claims("hdr.invalid!base64.sig").is_err());
        let bad_json_b64 = URL_SAFE_NO_PAD.encode("not valid json");
        assert!(decode_id_token_claims(&format!("hdr.{}.sig", bad_json_b64)).is_err());
    }

    #[test]
    fn test_status_line_format_both_granted() {
        let mut consent = HashMap::new();
        consent.insert(
            Audience::Endpoint,
            ConsentState::Granted {
                scopes: vec!["Machine.Read".into(), "Alert.Read".into()],
                expires_at: 1791467112, // 2026-10-08T13:45:12Z
            },
        );
        consent.insert(
            Audience::Graph,
            ConsentState::Granted {
                scopes: vec!["ThreatHunting.Read.All".into(), "SecurityAlert.Read.All".into()],
                expires_at: 1791467112,
            },
        );

        let session = DelegatedSession::new(
            "alice@contoso.com",
            "72f988bf-1234-5678-9abc-def012345678",
            Secret::new("rt-secret"),
            vec![],
            consent,
        );

        let status = session.status_line();
        assert_eq!(
            status,
            "Signed in as alice@contoso.com (tenant 72f988bf-1234-5678-9abc-def012345678) | endpoint: Machine.Read Alert.Read (expires 2026-10-08T13:45:12Z) | graph: ThreatHunting.Read.All SecurityAlert.Read.All (expires 2026-10-08T13:45:12Z)"
        );
        assert!(!status.contains("rt-secret"));
    }

    #[test]
    fn test_status_line_format_consent_missing() {
        let mut consent = HashMap::new();
        consent.insert(
            Audience::Endpoint,
            ConsentState::Granted {
                scopes: vec!["Machine.Read".into(), "Alert.Read".into()],
                expires_at: 1791467112,
            },
        );
        consent.insert(
            Audience::Graph,
            ConsentState::Missing {
                aadsts: Some(65001),
            },
        );

        let requested_scopes = vec![
            "https://api.securitycenter.microsoft.com/Machine.Read".into(),
            "https://graph.microsoft.com/SecurityAlert.Read.All".into(),
        ];

        let session = DelegatedSession::new(
            "alice@contoso.com",
            "72f988bf-1234",
            Secret::new("rt-secret"),
            requested_scopes,
            consent,
        );

        let status = session.status_line();
        assert_eq!(
            status,
            "Signed in as alice@contoso.com (tenant 72f988bf-1234) | endpoint: Machine.Read Alert.Read (expires 2026-10-08T13:45:12Z) | graph: consent missing (AADSTS65001) — grant admin consent for SecurityAlert.Read.All"
        );
    }
}
