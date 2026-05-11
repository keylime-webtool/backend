use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::jwt;
use crate::auth::rbac::{Permission, Role};
use crate::error::AppError;

/// Extract and validate JWT from Authorization header.
pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, AppError> {
    let raw = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let token =
        extract_bearer(raw).ok_or_else(|| AppError::Unauthorized("missing bearer token".into()))?;

    // TODO: get secret from app state
    let secret = b"placeholder";
    let claims = jwt::decode_token(token, secret)?;

    // TODO: check session revocation via SessionStore

    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Middleware factory that enforces a minimum permission level.
pub async fn require_permission(
    req: Request,
    next: Next,
    permission: Permission,
) -> Result<Response, AppError> {
    let claims = req
        .extensions()
        .get::<jwt::Claims>()
        .ok_or_else(|| AppError::Unauthorized("no claims in request".into()))?;

    check_permission(claims.role, permission)?;

    Ok(next.run(req).await)
}

/// Require at least Operator role.
pub async fn require_write(req: Request, next: Next) -> Result<Response, AppError> {
    require_permission(req, next, Permission::Write).await
}

/// Require Admin role.
pub async fn require_admin(req: Request, next: Next) -> Result<Response, AppError> {
    require_permission(req, next, Permission::Approve).await
}

// Placeholder for extracting the Role from claims
impl From<&jwt::Claims> for Role {
    fn from(claims: &jwt::Claims) -> Self {
        claims.role
    }
}

pub(crate) fn extract_bearer(header_value: Option<&str>) -> Option<&str> {
    header_value.and_then(|v| v.strip_prefix("Bearer "))
}

pub(crate) fn check_permission(role: Role, permission: Permission) -> Result<(), AppError> {
    if !role.has_permission(permission) {
        return Err(AppError::Forbidden(format!(
            "role {role:?} lacks {permission:?} permission"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer_valid() {
        assert_eq!(
            extract_bearer(Some("Bearer my-token-123")),
            Some("my-token-123")
        );
    }

    #[test]
    fn extract_bearer_missing_prefix() {
        assert!(extract_bearer(Some("Basic abc")).is_none());
    }

    #[test]
    fn extract_bearer_none() {
        assert!(extract_bearer(None).is_none());
    }

    #[test]
    fn extract_bearer_empty() {
        assert!(extract_bearer(Some("")).is_none());
    }

    #[test]
    fn check_permission_admin_has_all() {
        assert!(check_permission(Role::Admin, Permission::Read).is_ok());
        assert!(check_permission(Role::Admin, Permission::Write).is_ok());
        assert!(check_permission(Role::Admin, Permission::Approve).is_ok());
    }

    #[test]
    fn check_permission_viewer_read_only() {
        assert!(check_permission(Role::Viewer, Permission::Read).is_ok());
        assert!(check_permission(Role::Viewer, Permission::Write).is_err());
        assert!(check_permission(Role::Viewer, Permission::Approve).is_err());
    }

    #[test]
    fn check_permission_operator_no_approve() {
        assert!(check_permission(Role::Operator, Permission::Read).is_ok());
        assert!(check_permission(Role::Operator, Permission::Write).is_ok());
        assert!(check_permission(Role::Operator, Permission::Approve).is_err());
    }

    #[test]
    fn role_from_claims() {
        let claims = jwt::Claims {
            sub: "user".into(),
            role: Role::Operator,
            iat: 0,
            exp: 0,
            session_id: "s".into(),
            tenant_id: None,
        };
        let role: Role = Role::from(&claims);
        assert_eq!(role, Role::Operator);
    }
}
