//! Azure AD token acquisition and caching — multi-scope support.
//!
//! Uses `client_credentials` grant against the Entra ID OAuth2 v2.0 endpoint.
//! Tokens are cached in memory per scope with a 60-second expiry buffer.
//! Cache key: `"{tenant}:{client}:{scope}"`.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;

use crate::constants::{
    ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_TENANT_ID, TOKEN_ENDPOINT, TOKEN_EXPIRY_BUFFER_SECS,
};
use crate::error::internal_error;

/// A cached access token with an expiry timestamp.
#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: i64,
}

impl CachedToken {
    fn is_valid(&self) -> bool {
        Utc::now().timestamp() + TOKEN_EXPIRY_BUFFER_SECS < self.expires_at
    }
}

/// Manages Azure AD token acquisition and in-memory caching per scope.
#[derive(Clone)]
pub struct TokenManager {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    pub http_client: reqwest::Client,
    /// Cache keyed by scope string.
    cache: Arc<RwLock<HashMap<String, CachedToken>>>,
}

impl TokenManager {
    /// Create a new TokenManager from environment variables.
    pub fn from_env(http_client: reqwest::Client) -> Result<Self, anyhow::Error> {
        let tenant_id = std::env::var(ENV_TENANT_ID)
            .map_err(|_| anyhow::anyhow!("{ENV_TENANT_ID} environment variable is required"))?;
        let client_id = std::env::var(ENV_CLIENT_ID)
            .map_err(|_| anyhow::anyhow!("{ENV_CLIENT_ID} environment variable is required"))?;
        let client_secret = std::env::var(ENV_CLIENT_SECRET)
            .map_err(|_| anyhow::anyhow!("{ENV_CLIENT_SECRET} environment variable is required"))?;

        Ok(Self {
            tenant_id,
            client_id,
            client_secret,
            http_client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get a valid access token for the given scope, refreshing if necessary.
    pub async fn get_token(&self, scope: &str) -> Result<String, rmcp::ErrorData> {
        // Fast path: read from cache
        {
            let guard = self.cache.read().await;
            if let Some(cached) = guard.get(scope)
                && cached.is_valid()
            {
                return Ok(cached.token.clone());
            }
        }

        // Slow path: refresh token
        let token = self.fetch_token(scope).await?;

        {
            let mut guard = self.cache.write().await;
            guard.insert(scope.to_string(), token.clone());
        }

        Ok(token.token)
    }

    async fn fetch_token(&self, scope: &str) -> Result<CachedToken, rmcp::ErrorData> {
        let url = TOKEN_ENDPOINT.replace("{tenant}", &self.tenant_id);

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("scope", scope),
        ];

        let resp = self
            .http_client
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| internal_error(format!("token request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let _body = resp.text().await.unwrap_or_default();
            tracing::error!(
                status = %status.as_u16(),
                scope = %scope,
                "Token acquisition failed"
            );
            return Err(internal_error(format!(
                "token acquisition failed (HTTP {}) for scope {}",
                status.as_u16(),
                scope
            )));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: i64,
        }

        let data: TokenResponse = resp
            .json()
            .await
            .map_err(|e| internal_error(format!("failed to parse token response: {e}")))?;

        let expires_at = Utc::now().timestamp() + data.expires_in;

        tracing::info!(
            scope = %scope,
            expires_in = %data.expires_in,
            "Token acquired"
        );

        Ok(CachedToken {
            token: data.access_token,
            expires_at,
        })
    }
}

#[cfg(test)]
impl TokenManager {
    /// Create a test token manager pre-seeded with valid dummy tokens for Graph and Endpoint scopes.
    pub fn for_test(http: reqwest::Client) -> Self {
        let mut cache = HashMap::new();
        let far_future = Utc::now().timestamp() + 86400 * 365;
        cache.insert(
            crate::constants::GRAPH_SCOPE.to_string(),
            CachedToken {
                token: "test-graph-token".to_string(),
                expires_at: far_future,
            },
        );
        cache.insert(
            crate::constants::ENDPOINT_SCOPE.to_string(),
            CachedToken {
                token: "test-endpoint-token".to_string(),
                expires_at: far_future,
            },
        );

        Self {
            tenant_id: "test-tenant-id".to_string(),
            client_id: "test-client-id".to_string(),
            client_secret: "test-client-secret".to_string(),
            http_client: http,
            cache: Arc::new(RwLock::new(cache)),
        }
    }
}
