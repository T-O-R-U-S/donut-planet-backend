#![feature(type_alias_impl_trait)]

extern crate core;

mod errors;
mod structs;

use std::collections::HashMap;
use errors::Error;

use std::fmt::{Debug};
use sqlx::mysql::MySqlPoolOptions;
use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use actix_web::web::{Data, Json};
use actix_files::Files;

use donut_planet::GetDatabase;


use actix_web::cookie::{Cookie};
use chrono::{Duration, Timelike, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, self as jwt, TokenData, Validation, Algorithm};
use sqlx::{MySql, Pool};
use crate::errors::SqlError;

use structs::{
    LoginDetails,
    SignupDetails,
    UserData,
    PostData,
};
use crate::structs::JwtData;

pub type WebResult = Result<HttpResponse, Error>;

const PRIVATE_KEY: &str = include_str!("../secrets/private_key.secret");

// Creates a new user (provided there are no conflicts).
#[post("/signup")]
async fn signup(data: Data<Pool<MySql>>,
                form: Json<SignupDetails>) -> WebResult {
    let mut database = data.get_db().await?;

    let hashed_password = bcrypt::hash_with_result(
        form.password.as_bytes(),
        12
    )?;

    let hashed_password = hashed_password.to_string();

    sqlx::query!(
        "\
        INSERT INTO users(username, email, password_hash)
            VALUES (?, ?, ?)
        ",
        form.username,
        form.email,
        hashed_password
    )
        .execute(&mut database)
        .await
        .map_err(Error::from)
        .map_err(SqlError::conflict("The email/username you've selected is already taken."))
        .map_err(SqlError::constraint_fail("Double-check your email."))?;

    Ok(HttpResponse::Ok().body("You've signed up!"))
}

// Returns the JWT if credentials are correct
#[post("/login")]
async fn login((data, encoding_key): (Data<Pool<MySql>>, Data<EncodingKey>), form: Json<LoginDetails>) -> WebResult {
    let mut database = data.get_db().await?;

    let form = form.into_inner();

    let user = sqlx::query!(
        "\
            SELECT password_hash, username, id
            FROM users
            WHERE email = ?
        ",
        &form.email
    )
        .fetch_one(&mut database)
        .await
        .map_err(Error::from)
        .map_err(SqlError::not_found("There is no account with that email address."))?;

    if bcrypt::verify(&form.password, &user.password_hash)? {
        let mut time = Utc::now();

        time += Duration::days(30);

        let user_jwt = jwt::encode(
            &Header::default(),
            &JwtData {
                username: user.username,
                email: form.email,
                id: user.id,
                exp: time.timestamp()
            },
            &encoding_key
        )?;

        Ok(HttpResponse::Ok()
            .cookie(Cookie::new("jwt", user_jwt))
            .body("Successfully logged in!"))
    } else {
        Err(HttpResponse::Unauthorized()
            .body("Invalid login credentials.")
            .into()
        )
    }
}

// Creates a post
#[post("/post")]
async fn create_post(req: HttpRequest, (decoding_key, data): (Data<DecodingKey>, Data<Pool<MySql>>),
                     form: Json<PostData>) -> WebResult {
    let user = authorize_user(req, decoding_key)?;

    let mut database = data.get_db().await?;

    sqlx::query!(
        "insert into posts(author, title, content) values (?, ?, ?)",
        user.id,
        form.title,
        form.content
    )
        .execute(&mut database)
        .await?;

    Ok(HttpResponse::Ok().body("Post successfully created"))
}

#[get("/post")]
async fn recommend_post(data: Data<Pool<MySql>>) -> WebResult {
    let mut database = data.get_db().await?;

    // Not exactly the most efficient algorithm to randomly select posts... but it'll do
    // for a small database.
    let posts = sqlx::query_as!(
        PostData,
        "\
    SELECT title, content, author
    FROM posts
    ORDER BY RAND() ASC
    LIMIT 40")
        .fetch_all(&mut database)
        .await?;

    Ok(
        HttpResponse::Ok()
            .body(serde_json::to_string(&posts).unwrap())
    )
}

#[get("/post/{id}")]
async fn get_post(data: Data<Pool<MySql>>, id: web::Path<u64>) -> WebResult {
    let mut database = data.get_db().await?;

    let post = sqlx::query!(
        "\
        SELECT title, content, author
        FROM posts
        WHERE id = ?
        ",
        id.into_inner()
    )
        .fetch_one(&mut database)
        .await
        .map_err(Error::from)
        .map_err(SqlError::not_found("That post doesn't exist."))?;

    Ok(
        HttpResponse::Ok().json(
            PostData {
                title: post.title,
                content: post.content,
                author: post.author
            }
        )
    )
}

#[post("/post/{id}")]
async fn edit_post(req: HttpRequest, (data, decoding_key): (Data<Pool<MySql>>, Data<DecodingKey>), id: web::Path<u64>, form: Json<PostData>) -> WebResult {
    let mut database = data.get_db().await?;

    let form = form.into_inner();

    let user = authorize_user(req, decoding_key)?;

    sqlx::query!(
        "\
        UPDATE posts
        SET
            posts.title = ?,
            posts.content = ?
        WHERE
            posts.author = ? AND
            posts.id = ?
        ",
        form.title,
        form.content,
        user.id,
        id.into_inner(),
    )
        .execute(&mut database)
        .await
        .map_err(Error::from)
        .map_err(SqlError::not_found("Post doesn't exist, or it does not belong to this account."))?;

    Ok(HttpResponse::Ok().body("Edits published!"))
}

#[get("/user/{id}")]
async fn get_user(data: Data<Pool<MySql>>, id: web::Path<u64>) -> WebResult {
    let mut database = data.get_db().await?;

    let user = sqlx::query!(
        "
        SELECT id, username, profile_picture, bio
        FROM users
        WHERE id = ?
        ",
        id.into_inner()
    )
        .fetch_one(&mut database)
        .await?;

    Ok(
        HttpResponse::Ok().json(
            UserData {
                id: user.id,
                username: user.username,
                bio: user.bio,
                profile_picture: user.profile_picture
            }
        )
    )
}

#[post("/like/{id}")]
async fn like_post(req: HttpRequest, (data, decoding_key): (Data<Pool<MySql>>, Data<DecodingKey>), id: web::Path<u64>) -> WebResult {
    let user = authorize_user(req, decoding_key)?;

    let mut database = data.get_db().await?;

    let id = id.into_inner();

    let query = sqlx::query!(
        "
            INSERT INTO ratings(user_id, post_id, val) VALUES (?, ?, '1')
        ",
        user.id,
        id
    )
        .execute(&mut database)
        .await;

    match query {
        Ok(_) => Ok(HttpResponse::Ok().body("Liked this post.")),
        Err(error) if SqlError::from(&error) == SqlError::RowConflict => {
            sqlx::query!(
                "
                UPDATE ratings SET val = '1' WHERE user_id = ? AND post_id = ?
                ",
                user.id,
                id
            )
                .execute(&mut database)
                .await?;

            Ok(HttpResponse::Ok().body("Liked this post."))
        }
        Err(_) => Err(HttpResponse::InternalServerError().into())
    }
}

#[post("/dislike/{id}")]
async fn dislike_post(req: HttpRequest, (data, decoding_key): (Data<Pool<MySql>>, Data<DecodingKey>), id: web::Path<u64>) -> WebResult {
    let user = authorize_user(req, decoding_key)?;

    let mut database = data.get_db().await?;

    let id = id.into_inner();

    let query = sqlx::query!(
        "\
            INSERT INTO ratings(user_id, post_id, val) VALUES (?, ?, '-1')
        ",
        user.id,
        id,
    )
        .execute(&mut database)
        .await;

    match query.into() {
        Ok(_) => Ok(HttpResponse::Ok().body("Disliked this post.")),
        Err(error) if SqlError::from(&error) == SqlError::RowConflict => {
            sqlx::query!(
                "\
                UPDATE ratings SET val = '-1' WHERE user_id = ? AND post_id = ?
                ",
                user.id,
                id
            )
                .execute(&mut database)
                .await?;

            Ok(HttpResponse::Ok().body("Disliked this post."))
        }
        Err(_) => Err(HttpResponse::InternalServerError().into())
    }
}

#[get("/like/{id}")]
async fn get_rating(req: HttpRequest, (data, decoding_key): (Data<Pool<MySql>>, Data<DecodingKey>), id: web::Path<u64>) -> WebResult {
    let user = authorize_user(req, decoding_key)?;

    let mut database = data.get_db().await?;

    let id = id.into_inner();

    let likes = sqlx::query!(
        "
            SELECT COUNT(id) as likes FROM ratings WHERE post_id = ? AND val = '1'
        ",
        id
    )
        .fetch_one(&mut database)
        .await
        .map_err(Error::from)
        .map_err(SqlError::not_found("The post you're looking for doesn't exist."))?;

    let dislikes = sqlx::query!(
        "
            SELECT COUNT(id) as dislikes FROM ratings WHERE post_id = ? AND val = '-1'
        ",
        id
    )
        .fetch_one(&mut database)
        .await?;

    let rating: i64 = likes.likes - dislikes.dislikes;

    Ok(HttpResponse::Ok().body(rating.to_string()))
}

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let conn_url: &str = include_str!("../secrets/conn_url.secret");

    let pool = MySqlPoolOptions::new()
        .max_connections(24)
        .connect(conn_url).await?;

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let encoding_key = EncodingKey::from_secret(PRIVATE_KEY.as_bytes());

    let decoding_key = DecodingKey::from_secret(PRIVATE_KEY.as_bytes());

    println!("Connected to DB!");

    println!("Server binding to 127.0.0.1:8080");

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(Data::new(encoding_key.clone()))
            .app_data(Data::new(decoding_key.clone()))
            .service(
                // TODO: Add rate limiter!
                web::scope("/api")
                    .service(login)
                    .service(signup)
                    .service(create_post)
                    .service(edit_post)
                    .service(get_post)
                    .service(recommend_post)
                    .service(like_post)
                    .service(dislike_post)
                    .service(get_rating)
                    .wrap(
                        middleware::Logger::new("%t :: %a %{User-Agent}i => %s in %Dms")
                            .log_target("api")
                    )
            )
            .service(
                Files::new("/", "./frontend")
                    .index_file("index.html")
                    .show_files_listing()
                    .use_last_modified(true)
                    .prefer_utf8(true)
            )
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await?
    )
}

fn authorize_user(request: HttpRequest, decoding_key: Data<DecodingKey>) -> Result<JwtData, Error> {
    let user = request.cookie("jwt")
        .ok_or_else(HttpResponse::Forbidden)?;

    let mut validation = Validation::new(Algorithm::default());

    validation.validate_exp = true;

    let token: TokenData<JwtData> = jwt::decode(user.value(), &decoding_key, &validation)?;

    Ok(token.claims)
}