use std::fmt::{Display, Formatter};
use actix_web::ResponseError;
use thiserror::Error;
use crate::HttpError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An internal error occurred")]
    Sqlx {
        #[from]
        source: sqlx::Error
    },
    #[error("Internal error")]
    Bcyrpt {
        #[from]
        source: bcrypt::BcryptError
    },
    #[error("Couldn't retrieve token")]
    Jwt {
        #[from]
        source: jsonwebtoken::errors::Error
    },
    #[error("Internal error")]
    IO {
        #[from]
        source: std::io::Error
    },
    #[error("Internal error")]
    SimplifiedSql {
        #[from]
        source: SqlError
    },
    #[error("{}", .source)]
    HttpError {
        #[from]
        source: HttpError
    }
}

#[derive(Debug, Error)]
pub enum SqlError {
    #[error("There already exists a row with this unique key")]
    RowConflict,
    #[error("Row doesn't exist")]
    NonExistentRow,
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
    #[error("Irrecoverable error: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>)
}

impl From<sqlx::Error> for SqlError {
    fn from(value: sqlx::Error) -> Self {
        match value {
            sqlx::Error::Database(error) if error.code().unwrap() == "23000" => {
                SqlError::RowConflict
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
            _ => SqlError::Other(Box::new(value)),
        }
    }
}

pub trait IntoSimplifiedSqlError {
    type Success;

    fn simplified(self) -> Result<Self::Success, SqlError>;
}

impl<T> IntoSimplifiedSqlError for Result<T, sqlx::Error> {
    type Success = T;

    fn simplified(self) -> Result<Self::Success, SqlError> {
        match self {
            Ok(res) => Ok(res),
            Err(err) => Err(err.into())
        }
    }
}

impl ResponseError for Error {}