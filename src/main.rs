mod errors;

use errors::Error;

use std::fmt::{Debug, Display, Formatter};
use sqlx::mysql::MySqlPoolOptions;
use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use actix_web::web::{Data, Json};
use actix_files::Files;

use serde::{Serialize, Deserialize};

use std::fs::read_to_string;
use actix_web::error::InternalError;
use actix_web::http::StatusCode;
use sqlx::{MySql, Pool};

#[derive(Serialize, Deserialize)]
struct LoginDetails {
    email: String,
    password: String
}

#[derive(Serialize, Deserialize)]
struct SignupDetails {
    username: String,
    email: String,
    password: String,
}

#[post("/signup")]
async fn signup(data: Data<Pool<MySql>>, form: Json<SignupDetails>) -> Result<impl Responder, Error> {
    let mut database = data.into_inner().acquire().await
        .expect("Internal error.");

    let hashed_password = bcrypt::hash_with_result(
        form.password.as_bytes(),
        12
    )?;

    let hashed_password = hashed_password.to_string();

    sqlx::query!(
        "\
        INSERT INTO users(username, email, password_hash)
            VALUES (?, ?, ?);
        ",
        form.username,
        form.email,
        hashed_password
    )
        .execute(&mut database)
        .await?;

    Ok("hi")
}

#[post("/login")]
async fn login(data: Data<Pool<MySql>>, form: Json<LoginDetails>) -> Result<impl Responder, Error> {
    let mut database = data.into_inner().acquire().await
        .expect("Internal error.");

    let row = sqlx::query!(
        "\
            SELECT password_hash
            FROM users
            WHERE email = ?
        ",
        &form.email
    )
        .fetch_one(&mut database)
        .await?;

    if bcrypt::verify(&form.password, &row.password_hash)? {
        Ok("nice")
    } else {
        Ok("invalid login credentials")
    }
}

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let conn_url: String = read_to_string("secrets/conn_url.secret").expect("Failed to read connection URL string");

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(conn_url.as_str()).await?;


    println!("Connected to DB!");

    println!("Server binding to 127.0.0.1:8080");

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .service(login)
            .service(signup)
            .service(
                Files::new("/", "./frontend")
                    .index_file("index.html")
                    .show_files_listing()
                    .use_last_modified(true)
                    .prefer_utf8(true)
            )
            .wrap(middleware::Logger::new("%t :: %a %{User-Agent}i => %s in %Dms"))
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await?
    )
}
