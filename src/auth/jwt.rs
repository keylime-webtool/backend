use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use super::rbac::Role;
use crate::error::{AppError, AppResult};

/// JWT claims for dashboard session tokens (SR-010).
/// Tokens are short-lived (15 min default) with refresh rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user identifier from OIDC).
    pub sub: String,
    /// User's RBAC role.
    pub role: Role,
    /// Issued-at (unix timestamp).
    pub iat: i64,
    /// Expiration (unix timestamp).
    pub exp: i64,
    /// Session ID for server-side revocation (SR-011).
    pub session_id: String,
    /// Tenant ID for multi-tenancy isolation (SR-019).
    pub tenant_id: Option<String>,
}

/// Encode a new JWT token.
pub fn encode_token(
    subject: &str,
    role: Role,
    session_id: &str,
    tenant_id: Option<&str>,
    secret: &[u8],
    ttl_secs: i64,
) -> AppResult<String> {
    let now = Utc::now();
    let claims = Claims {
        sub: subject.to_string(),
        role,
        iat: now.timestamp(),
        exp: (now + Duration::seconds(ttl_secs)).timestamp(),
        session_id: session_id.to_string(),
        tenant_id: tenant_id.map(String::from),
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(AppError::from)
}

/// Decode and validate a JWT token.
pub fn decode_token(token: &str, secret: &[u8]) -> AppResult<Claims> {
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )?;
    Ok(data.claims)
}
