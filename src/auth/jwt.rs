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

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!!";

    #[test]
    fn encode_decode_roundtrip() {
        let token = encode_token("alice", Role::Operator, "sess-1", None, SECRET, 300).unwrap();
        let claims = decode_token(&token, SECRET).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.role, Role::Operator);
        assert_eq!(claims.session_id, "sess-1");
        assert!(claims.tenant_id.is_none());
    }

    #[test]
    fn preserves_tenant_id() {
        let token = encode_token("bob", Role::Admin, "sess-2", Some("t-42"), SECRET, 300).unwrap();
        let claims = decode_token(&token, SECRET).unwrap();
        assert_eq!(claims.tenant_id.as_deref(), Some("t-42"));
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = encode_token("alice", Role::Viewer, "sess-3", None, SECRET, 300).unwrap();
        let result = decode_token(&token, b"wrong-secret-key-32-bytes-long!!");
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let now = Utc::now();
        let claims = Claims {
            sub: "alice".to_string(),
            role: Role::Viewer,
            iat: (now - Duration::seconds(3600)).timestamp(),
            exp: (now - Duration::seconds(120)).timestamp(),
            session_id: "sess-4".to_string(),
            tenant_id: None,
        };
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        let result = decode_token(&token, SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn role_preserved_for_all_variants() {
        for role in [Role::Viewer, Role::Operator, Role::Admin] {
            let token = encode_token("u", role, "s", None, SECRET, 300).unwrap();
            let claims = decode_token(&token, SECRET).unwrap();
            assert_eq!(claims.role, role);
        }
    }
}
