use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use zed_interfaces::registry::ApiError;

/// Error type for every handler: non-2xx responses always carry a JSON
/// `ApiError { code, message }` body per the contract crate.
#[derive(Debug)]
pub struct ApiErr {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub type ApiResult<T> = Result<T, ApiErr>;

impl ApiErr {
    pub fn not_found(what: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: format!("{what} not found"),
        }
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message: message.into(),
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "missing or invalid bearer token".to_string(),
        }
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code,
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let body = ApiError {
            code: self.code.to_string(),
            message: self.message,
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<sea_orm::DbErr> for ApiErr {
    fn from(err: sea_orm::DbErr) -> Self {
        tracing::error!(error = %err, "database error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: "internal database error".to_string(),
        }
    }
}

impl From<anyhow::Error> for ApiErr {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!(error = %err, "internal error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: "internal error".to_string(),
        }
    }
}

impl From<crate::files::ExtractError> for ApiErr {
    fn from(err: crate::files::ExtractError) -> Self {
        match err {
            crate::files::ExtractError::TooLarge => Self {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: "file_too_large",
                message: format!(
                    "files larger than {} bytes are not served individually; download the artifact instead",
                    crate::files::MAX_SERVED_FILE_BYTES
                ),
            },
            crate::files::ExtractError::InflationBudgetExceeded => Self {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: "archive_too_large",
                message: format!(
                    "this artifact inflates past the {} byte decompression budget; \
                     download the artifact instead of requesting files from it",
                    crate::files::max_inflated_bytes()
                ),
            },
            crate::files::ExtractError::Archive(err) => err.into(),
        }
    }
}
