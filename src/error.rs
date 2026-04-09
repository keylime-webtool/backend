use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Application-level error type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error(transparent)]
    Database(#[from] sqlx::Error),

    #[error(transparent)]
    Redis(#[from] redis::RedisError),

    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("keylime API error: {0}")]
    KeylimeApi(#[from] reqwest::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Standard API error response body.
#[derive(Debug, Serialize)]
struct ErrorBody {
    success: bool,
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            AppError::ServiceUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE")
            }
            AppError::KeylimeApi(_) => (StatusCode::BAD_GATEWAY, "KEYLIME_API_ERROR"),
            AppError::Internal(_) | AppError::Anyhow(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
            }
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
            AppError::Redis(_) => (StatusCode::INTERNAL_SERVER_ERROR, "CACHE_ERROR"),
            AppError::Jwt(_) => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN"),
        };

        let body = ErrorBody {
            success: false,
            error: ErrorDetail {
                code,
                message: self.to_string(),
            },
        };

        (status, axum::Json(body)).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn status_of(err: AppError) -> StatusCode {
        err.into_response().status()
    }

    #[test]
    fn not_found_returns_404() {
        assert_eq!(
            status_of(AppError::NotFound("x".into())),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn unauthorized_returns_401() {
        assert_eq!(
            status_of(AppError::Unauthorized("x".into())),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn forbidden_returns_403() {
        assert_eq!(
            status_of(AppError::Forbidden("x".into())),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn bad_request_returns_400() {
        assert_eq!(
            status_of(AppError::BadRequest("x".into())),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn conflict_returns_409() {
        assert_eq!(
            status_of(AppError::Conflict("x".into())),
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn service_unavailable_returns_503() {
        assert_eq!(
            status_of(AppError::ServiceUnavailable("x".into())),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn internal_returns_500() {
        assert_eq!(
            status_of(AppError::Internal("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn anyhow_returns_500() {
        assert_eq!(
            status_of(AppError::Anyhow(anyhow::anyhow!("boom"))),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn error_response_body_has_success_false() {
        let resp = AppError::NotFound("agent".into()).into_response();
        let (_, body) = resp.into_parts();
        let bytes = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { axum::body::to_bytes(body, usize::MAX).await.unwrap() });
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["success"], false);
        assert_eq!(json["error"]["code"], "NOT_FOUND");
    }
}
