#![feature(async_fn_in_trait)]

mod errors;

use actix_web::web;
use sqlx::{MySql, Pool};
use sqlx::pool::PoolConnection;

pub trait GetDatabase {
    async fn get_db(self) -> Result<PoolConnection<MySql>, sqlx::Error>;
}

impl GetDatabase for web::Data<Pool<MySql>> {
    async fn get_db(self) -> Result<PoolConnection<MySql>, sqlx::Error> {
        return self.into_inner().acquire().await
    }
}