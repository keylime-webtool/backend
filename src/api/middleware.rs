use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::jwt;
use crate::auth::rbac::{Permission, Role};
use crate::error::AppError;

/// Extract and validate JWT from Authorization header.
pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, AppError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing bearer token".into()))?;

    // TODO: get secret from app state
    let secret = b"placeholder";
    let claims = jwt::decode_token(header, secret)?;

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

    if !claims.role.has_permission(permission) {
        return Err(AppError::Forbidden(format!(
            "role {:?} lacks {:?} permission",
            claims.role, permission
        )));
    }

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
