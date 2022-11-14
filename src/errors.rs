use std::borrow::Borrow;
use std::fmt::{Display, Formatter};

use std::str;
use actix_web::{HttpResponse, HttpResponseBuilder, ResponseError};
use actix_web::body::{BoxBody, MessageBody};
use actix_web::http::StatusCode;
use jsonwebtoken::errors::ErrorKind;
use sqlx::mysql::MySqlQueryResult;
use thiserror::Error as ErrorTrait;

#[derive(Debug, ErrorTrait)]
pub enum Error {
    #[error("{}", .source)]
    Sqlx {
        #[from]
        source: sqlx::Error
    },
    #[error("{}", .source)]
    Bcyrpt {
        #[from]
        source: bcrypt::BcryptError
    },
    // Errors thrown by
    #[error("{}", .source)]
    Jwt {
        #[from]
        source: jsonwebtoken::errors::Error
    },
    #[error("{}", .source)]
    IO {
        #[from]
        source: std::io::Error
    },
    #[error("{}", .source)]
    SimplifiedSql {
        #[from]
        source: SqlError
    },
    #[error("Code: {}\nBody: {}\n{:?}", .code, .body, code.canonical_reason().unwrap_or("Internal error."))]
    HttpStatus {
        code: StatusCode,
        body: String
    },
    #[error("This part of Donut Planet is yet to be implemented.")]
    Unimplemented
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
    fn error_function_factory(sql_error: SqlError, error_msg: &str) -> impl Fn(Error) -> Error + '_ {
        move |error| {
            let Error::Sqlx { source } = error else {
                panic!("Unexpected error type {error:?} for SQL error")
            };

            let source = SqlError::from(source);

            if source == sql_error {
                Error::HttpStatus {
                    code: StatusCode::NOT_FOUND,
                    body: error_msg.to_string()
                }
            } else {
                Error::from(source)
            }
        }
    }

    pub fn not_found(error_msg: &str) -> impl Fn(Error) -> Error + '_ {
        SqlError::error_function_factory(SqlError::NonExistentRow, error_msg)
    }

    pub fn conflict(error_msg: &str) -> impl Fn(Error) -> Error + '_ {
        SqlError::error_function_factory(SqlError::RowConflict, error_msg)
    }

    pub fn constraint_fail(error_msg: &str) -> impl Fn(Error) -> Error + '_ {
        SqlError::error_function_factory(SqlError::ConstraintFailed, error_msg)
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
            // WARN: SQLSTATE will be 23000 for a foreign key constraint fail instead of HY000.
            // Sqlx doesn't seem to have an API to get the error number, so there is no way to
            // distinguish between them.
            sqlx::Error::Database(error) if error.code() == Some("23000".into()) => {
                SqlError::RowConflict
            }
            sqlx::Error::Database(error) if error.code() == Some("HY000".into()) => {
                SqlError::ConstraintFailed
            }
            sqlx::Error::RowNotFound => {
                SqlError::NonExistentRow
            }
            sqlx::Error::ColumnNotFound(_) => {
                SqlError::NonExistentCol
            }
            sqlx::Error::Configuration(_) => {
                SqlError::InvalidConfig
            }
            sqlx::Error::ColumnIndexOutOfBounds { .. } => {
                SqlError::OutOfBoundsIndex
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
        match self {
            Error::Sqlx { source } => SqlError::from(source).error_response(),
            Error::Jwt { source } => {
                match source.kind() {
                    ErrorKind::MissingRequiredClaim(_) |
                    ErrorKind::InvalidToken |
                    ErrorKind::ExpiredSignature |
                    ErrorKind::InvalidIssuer |
                    ErrorKind::InvalidAudience |
                    ErrorKind::InvalidSubject |
                    ErrorKind::ImmatureSignature |
                    ErrorKind::Base64(_) |
                    ErrorKind::Json(_) |
                    ErrorKind::Utf8(_) => { HttpResponse::BadRequest().body(format!("{self}")) }
                    _ => { HttpResponse::InternalServerError().finish() }
                }
            }
            Error::SimplifiedSql { source } => source.error_response(),
            Error::HttpStatus { code, body } => HttpResponse::with_body(*code, BoxBody::new(body.to_string())),
            Error::Bcyrpt { .. } => HttpResponse::InternalServerError().finish(),
            Error::IO { .. } => HttpResponse::InternalServerError().finish(),
            Error::Unimplemented => HttpResponse::ServiceUnavailable().body(self.to_string())
        }
    }
}