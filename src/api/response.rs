use axum::response::IntoResponse;
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

/// Standard API response envelope.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: String,
    pub request_id: String,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now().to_rfc3339(),
            request_id: Uuid::new_v4().to_string(),
        }
    }
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        axum::Json(self).into_response()
    }
}

/// Paginated list response.
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub page: u64,
    pub page_size: u64,
    pub total_items: u64,
    pub total_pages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_response_ok_sets_success_true() {
        let resp = ApiResponse::ok("hello");
        assert!(resp.success);
        assert_eq!(resp.data, Some("hello"));
        assert!(resp.error.is_none());
    }

    #[test]
    fn api_response_ok_has_timestamp_and_request_id() {
        let resp = ApiResponse::ok(42);
        assert!(!resp.timestamp.is_empty());
        assert!(!resp.request_id.is_empty());
        // request_id should be a valid UUID
        assert!(uuid::Uuid::parse_str(&resp.request_id).is_ok());
    }

    #[test]
    fn api_response_serializes_correctly() {
        let resp = ApiResponse::ok(vec![1, 2, 3]);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["data"], serde_json::json!([1, 2, 3]));
        assert!(json["error"].is_null());
    }

    #[test]
    fn paginated_response_serializes_correctly() {
        let resp = PaginatedResponse {
            items: vec!["a", "b"],
            page: 1,
            page_size: 10,
            total_items: 2,
            total_pages: 1,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["page"], 1);
        assert_eq!(json["page_size"], 10);
        assert_eq!(json["total_items"], 2);
        assert_eq!(json["total_pages"], 1);
        assert_eq!(json["items"], serde_json::json!(["a", "b"]));
    }
}
