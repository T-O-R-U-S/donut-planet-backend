use std::fmt::{Display, Formatter};
use actix_web::ResponseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid login credentials.")]
    InvalidCredentials,
    #[error("Internal error")]
    Sqlx {
        #[from]
        source: sqlx::Error
    },
    #[error("Internal error")]
    Bcyrpt {
        #[from]
        source: bcrypt::BcryptError
    },
    #[error("Internal error")]
    IO {
        #[from]
        source: std::io::Error
    },
}

impl ResponseError for Error {}