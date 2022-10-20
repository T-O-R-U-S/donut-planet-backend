#![feature(async_fn_in_trait)]

mod errors;

use actix_web::web;
use sqlx::{Error, MySql, Pool};
use sqlx::pool::PoolConnection;
use crate::errors::SqlError;

pub trait GetDatabase {
    async fn get_db(self) -> Result<PoolConnection<MySql>, sqlx::Error>;
}

impl GetDatabase for web::Data<Pool<MySql>> {
    async fn get_db(self) -> Result<PoolConnection<MySql>, sqlx::Error> {
        return self.into_inner().acquire().await
    }
}