use std::borrow::Borrow;
use std::str;
use actix_web::{HttpResponse, HttpResponseBuilder, ResponseError};
use actix_web::body::{BoxBody, MessageBody};
use actix_web::http::StatusCode;
use thiserror::Error as ErrorTrait;

#[derive(Debug, ErrorTrait)]
pub enum Error {
    #[error("Internal error.")]
    Sqlx {
        #[from]
        source: sqlx::Error
    },
    #[error("Internal error.")]
    Bcyrpt {
        #[from]
        source: bcrypt::BcryptError
    },
    // Errors thrown by
    #[error("Couldn't retrieve token.")]
    Jwt {
        #[from]
        source: jsonwebtoken::errors::Error
    },
    #[error("Internal error.")]
    IO {
        #[from]
        source: std::io::Error
    },
    #[error("Internal error.")]
    SimplifiedSql {
        #[from]
        source: SqlError
    },
    #[error("{}", code.canonical_reason().unwrap_or("Internal error."))]
    HttpStatus {
        code: StatusCode,
        body: String
    }
}

impl From<HttpResponse> for Error {
    fn from(value: HttpResponse) -> Self {
        let code = value.status();

        let body_bytes = value.into_body().try_into_bytes().unwrap();
        let body = str::from_utf8(&body_bytes).unwrap();

        Error::HttpStatus {
            code,
            body: body.into()
        }
    }
}

impl From<HttpResponseBuilder> for Error {
    fn from(mut value: HttpResponseBuilder) -> Self {
        value.finish().status().into()
    }
}

impl From<StatusCode> for Error {
    fn from(value: StatusCode) -> Self {
        Error::HttpStatus {
            code: value,
            body: value.canonical_reason().unwrap_or("Internal error").into()
        }
    }
}

/// This is a simplification of sqlx::Error so I don't have to directly interface
/// with sqlx::Error::Database; instead, I just convert sqlx::Error into SqlError
/// which contains what I need.
#[derive(Debug, ErrorTrait, PartialEq, Eq, Copy, Clone)]
pub enum SqlError {
    #[error("There already exists a row with this unique key")]
    RowConflict,
    #[error("Row doesn't exist")]
    NonExistentRow,
    #[error("Constraint check failed")]
    ConstraintFailed,
    #[error("Column doesn't exist")]
    NonExistentCol,
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Out of bounds index")]
    OutOfBoundsIndex,
    #[error("Failed to fetch pool connection")]
    PoolError,
    // Errors that are not relevant/will not be handled by the application.
    // Oftentimes fatal.
    #[error("Irrecoverable error")]
    Other
}

impl SqlError {
    pub fn not_found(error_msg: &str) -> impl Fn(sqlx::Error) -> Error + '_ {
        move |error| {
            let error = SqlError::from(error);

            if error == SqlError::NonExistentRow {
                Error::HttpStatus {
                    code: StatusCode::NOT_FOUND,
                    body: error_msg.to_string()
                }
            } else {
                Error::from(error)
            }
        }
    }
}

impl ResponseError for SqlError {
    fn status_code(&self) -> StatusCode {
        match self {
            SqlError::RowConflict => StatusCode::CONFLICT,
            SqlError::NonExistentRow => StatusCode::NOT_FOUND,
            SqlError::ConstraintFailed => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_msg = self.status_code().canonical_reason().unwrap_or("Undefined error.");

        HttpResponse::with_body(self.status_code(), BoxBody::new(error_msg))
    }
}

impl<E> From<E> for SqlError
    where E: Borrow<sqlx::Error> {
    fn from(value: E) -> Self {
        match value.borrow() {
            sqlx::Error::Database(error) if error.code() == Some("23000".into()) => {
                SqlError::RowConflict
            }
            sqlx::Error::Database(error) if error.code() == Some("HY000".into()) => {
                SqlError::ConstraintFailed
            }
            sqlx::Error::RowNotFound => {
                SqlError::NonExistentRow
            }
            sqlx::Error::Configuration(_) => {
                SqlError::InvalidConfig
            }
            sqlx::Error::ColumnIndexOutOfBounds { .. } => {
                SqlError::OutOfBoundsIndex
            }
            sqlx::Error::ColumnNotFound(_) => {
                SqlError::NonExistentCol
            }
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => SqlError::PoolError,
            _ => SqlError::Other,
        }
    }
}

pub trait IntoSimplifiedSqlError {
    type Success;

    fn simplified(self) -> Result<Self::Success, SqlError>;
}

impl<T, E> IntoSimplifiedSqlError for Result<T, E>
    where E: Borrow<sqlx::Error> {
    type Success = T;

    fn simplified(self) -> Result<Self::Success, SqlError> {
        match self {
            Ok(res) => Ok(res),
            Err(err) => Err(err.into())
        }
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Error::HttpStatus { code, .. } => *code,
            Error::SimplifiedSql { source } => source.status_code(),
            Error::Sqlx { source } => SqlError::from(source).status_code(),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let error_msg = self.status_code().canonical_reason().unwrap_or("Undefined error.");

        let body = if let Error::HttpStatus { body, .. } = self {
            Some(body.as_str())
        } else {
            None
        }.unwrap_or(error_msg);

        HttpResponse::with_body(self.status_code(), BoxBody::new(body.to_string()))
    }
}