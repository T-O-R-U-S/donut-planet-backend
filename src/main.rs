#![feature(type_alias_impl_trait)]

mod errors;

use errors::Error;

use std::fmt::{Debug};
use sqlx::mysql::MySqlPoolOptions;
use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use actix_web::web::{Data, Json};
use actix_files::Files;

use serde::{Serialize, Deserialize};

use donut_planet::GetDatabase;


use actix_web::cookie::{Cookie};
use actix_web::http::StatusCode;
use jsonwebtoken::{EncodingKey, Header};
use sqlx::{MySql, Pool};
use crate::errors::SqlError;

type webResult = Result<impl Responder, Error>;

/// Login details (private)
#[derive(Deserialize)]
struct LoginDetails {
    email: String,
    password: String
}

/// Sign up details (private)
#[derive(Deserialize)]
struct SignupDetails {
    username: String,
    email: String,
    password: String,
}

/// Public user data
#[derive(Serialize, Deserialize)]
struct UserData {
    id: u64,
    username: String,
    bio: Option<String>,
    profile_picture: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PostData {
    title: Option<String>,
    content: Option<String>,
    author: Option<u64>
}

const PRIVATE_KEY: &str = include_str!("../secrets/private_key.secret");

// Creates a new user (provided there are no conflicts).
#[post("/signup")]
async fn signup((data, encoding_key): (Data<Pool<MySql>>, Data<EncodingKey>),
                form: Json<SignupDetails>) -> webResult {
    let mut database = data.get_db().await?;

    let encoding_key = encoding_key.as_ref();

    let hashed_password = bcrypt::hash_with_result(
        form.password.as_bytes(),
        12
    )?;

    let hashed_password = hashed_password.to_string();

    sqlx::query!(
        "\
        INSERT INTO users(username, email, password_hash, auth_token)
            VALUES (?, ?, ?, ?);
        ",
        form.username,
        form.email,
        hashed_password,
        jsonwebtoken::encode(&Header::default(),
                                &(&form.username, &form.email),
                                &encoding_key)?
    )
        .execute(&mut database)
        .await?;

    Ok(HttpResponse::Ok().body("You've signed up!"))
}

// Returns the JWT if credentials are correct
#[post("/login")]
async fn login(data: Data<Pool<MySql>>, form: Json<LoginDetails>) -> webResult {
    let mut database = data.get_db().await?;

    let user = sqlx::query!(
        "\
            SELECT password_hash, auth_token
            FROM users
            WHERE email = ?
        ",
        &form.email
    )
        .fetch_one(&mut database)
        .await
        .map_err(SqlError::not_found("There is no account with that email address."))?;

    if bcrypt::verify(&form.password, &user.password_hash)? {
        Ok(HttpResponse::Ok()
            .cookie(Cookie::new("auth", user.auth_token))
            .finish())
    } else {
        Err(HttpResponse::BadRequest()
            .status(StatusCode::UNAUTHORIZED)
            .body("Invalid login credentials.").into())
    }
}

// Creates a post
#[post("/post")]
async fn create_post(req: HttpRequest, data: Data<Pool<MySql>>,
                     form: Json<PostData>) -> webResult {
    let auth_session = req.cookie("auth").ok_or_else(HttpResponse::Forbidden)?;

    let auth_string = auth_session.value();

    let mut database = data.get_db().await?;

    let user = sqlx::query!(
        "\
        SELECT id FROM users WHERE
        auth_token = ?
        ",
        auth_string
    )
        .fetch_one(&mut database)
        .await
        .map_err(SqlError::not_found("Invalid auth token."))?;

    sqlx::query!(
        "insert into posts(author, title, content) values (?, ?, ?);",
        user.id,
        form.title,
        form.content
    )
        .execute(&mut database)
        .await?;

    Ok(HttpResponse::Ok().body("Post successfully created"))
}

#[get("/post")]
async fn recommend_post(data: Data<Pool<MySql>>) -> webResult {
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
async fn get_post(data: Data<Pool<MySql>>, id: web::Path<u64>) -> webResult {
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
async fn edit_post(req: HttpRequest, data: Data<Pool<MySql>>, id: web::Path<u64>) -> webResult {
    let mut database = data.get_db().await?;

    let auth_session = req.cookie("auth").ok_or_else(HttpResponse::Forbidden)?;

    let auth_string = auth_session.value();

    let post = sqlx::query!(
        "\
        SELECT author
        FROM posts
        WHERE id = ?
        ",
        id.into_inner()
    )
        .fetch_one(&mut database)
        .await
        .map_err(SqlError::not_found("Post doesn't exist."))?;

    Ok(HttpResponse::ServiceUnavailable().finish())
}

#[get("/user/{id}")]
async fn get_user(data: Data<Pool<MySql>>, id: web::Path<u64>) -> webResult {
    let mut database = data.get_db().await?;

    let user = sqlx::query!(
        "\
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

#[actix_web::main]
async fn main() -> Result<(), Error> {
    let conn_url: &str = include_str!("../secrets/conn_url.secret");

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(conn_url).await?;

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let encoding_key = EncodingKey::from_secret(PRIVATE_KEY.as_bytes());

    println!("Connected to DB!");

    println!("Server binding to 127.0.0.1:8080");

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .app_data(Data::new(encoding_key.clone()))
            .service(
                // TODO: Add rate limiter!
                web::scope("/api")
                    .service(login)
                    .service(signup)
                    .service(create_post)
                    .service(get_post)
                    .service(recommend_post)
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
