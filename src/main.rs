mod errors;

use errors::Error;
use errors::SqlError;
use errors::IntoSimplifiedSqlError;

use std::fmt::{Debug, Formatter};
use sqlx::mysql::MySqlPoolOptions;
use actix_web::{get, middleware, post, web, App, HttpResponse, HttpServer, Responder, ResponseError, HttpRequest};
use actix_web::web::{Data, Json};
use actix_files::Files;

use serde::{Serialize, Deserialize};

use donut_planet::GetDatabase;

use std::fs::read_to_string;
use actix_web::cookie::{Cookie, CookieBuilder};
use actix_web::error::{HttpError, InternalError};
use actix_web::http::StatusCode;
use jsonwebtoken::{EncodingKey, Header};
use sqlx::{MySql, Pool};



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
    title: String,
    content: String,
    author: Option<u64>
}

const PRIVATE_KEY: &str = include_str!("../secrets/private_key.secret");

// Creates a new user (provided there are no conflicts).
#[post("/signup")]
async fn signup(data: Data<Pool<MySql>>, form: Json<SignupDetails>) -> Result<impl Responder, Error> {
    let mut database = data.get_db().await?;

    let hashed_password = bcrypt::hash_with_result(
        form.password.as_bytes(),
        12
    )?;

    let hashed_password = hashed_password.to_string();

    let query = sqlx::query!(
        "\
        INSERT INTO users(username, email, password_hash, auth_token)
            VALUES (?, ?, ?, ?);
        ",
        form.username,
        form.email,
        hashed_password,
        jsonwebtoken::encode(&Header::default(),
                                        &(&form.username, &form.email),
                                        &EncodingKey::from_secret(PRIVATE_KEY.as_bytes()))?
    )
        .execute(&mut database)
        .await;

    match query.simplified() {
        Ok(user) => println!("{user:#?}"),
        Err(SqlError::RowConflict) => {
                return Ok(HttpResponse::Conflict()
                    .body("Username or email already taken."))
        }
        Err(e) => {
            println!("{e:#?}");
            return Err(e.into())
        }
    };

    Ok(HttpResponse::Ok().body("You've signed up!"))
}

// Returns the JWT if credentials are correct
#[post("/login")]
async fn login(data: Data<Pool<MySql>>, form: Json<LoginDetails>) -> Result<impl Responder, Error> {
    let mut database = data.get_db().await?;

    let query = sqlx::query!(
        "\
            SELECT password_hash, id, auth_token
            FROM users
            WHERE email = ?
        ",
        &form.email
    )
        .fetch_one(&mut database)
        .await;

    let query = match query.simplified() {
        Ok(user) => user,
        Err(SqlError::NonExistentRow) => return Ok(
            HttpResponse::NotFound()
                .finish()
        ),
        _ => return Ok(HttpResponse::InternalServerError().finish())
    };

    if bcrypt::verify(&form.password, &query.password_hash)? {
        Ok(HttpResponse::Ok()
            .cookie(Cookie::new("auth", query.auth_token))
            .finish())
    } else {
        Ok(HttpResponse::BadRequest()
            .status(StatusCode::UNAUTHORIZED)
            .body("Invalid login credentials."))
    }
}

// Creates a post
#[post("/post")]
async fn create_post(req: HttpRequest, data: Data<Pool<MySql>>, form: Json<PostData>) -> Result<impl Responder, Error> {
    let mut database = data.get_db().await?;

    let auth_session = match req.cookie("auth") {
        None => return Ok(
            HttpResponse::Forbidden()
                .body("You must log in to post!")
        ),
        Some(cookie) => cookie.value().to_string()
    };

    let query = sqlx::query!(
        "\
        SELECT id FROM users WHERE
        auth_token = ?
        ",
        auth_session
    )
        .fetch_one(&mut database)
        .await;

    let user_id = match query {
        Ok(row) => row.id,
        Err(sqlx::Error::RowNotFound) => return Ok(
            HttpResponse::BadRequest()
                .finish()
        ),
        Err(e) => return Err(e.into())
    };

    sqlx::query!(
        "insert into posts(user, title, content) values (?, ?, ?);",
        user_id,
        form.title,
        form.content
    )
        .execute(&mut database)
        .await?;

    Ok(HttpResponse::Ok().body("Post successfully created"))
}

#[get("/post/{id}")]
async fn get_post(data: Data<Pool<MySql>>, id: web::Path<u64>) -> Result<impl Responder, Error> {
    let mut database = data.get_db().await?;

    let query = sqlx::query!(
        "\
        SELECT title, content, user
        FROM posts
        WHERE id = ?
        ",
        id.into_inner()
    )
        .fetch_one(&mut database)
        .await;

    let post = match query {
        Ok(post) => post,
        Err(e) => {
            return match SqlError::from(e) {
                SqlError::NonExistentRow => {
                    Ok(
                        HttpResponse::NotFound().finish()
                    )
                }
                _ => Ok(
                    HttpResponse::InternalServerError().finish()
                )
            }
        }
    };

    Ok(
        HttpResponse::Ok().json(
            PostData {
                title: post.title.unwrap_or("".into()),
                content: post.content.unwrap_or("".into()),
                author: Some(post.user)
            }
        )
    )
}

#[get("/user/{id}")]
async fn get_user(data: Data<Pool<MySql>>, id: web::Path<u64>) -> Result<impl Responder, Error> {
    let mut database = data.get_db().await?;

    let query = sqlx::query!(
        "\
        SELECT id, username, profile_picture, bio
        FROM users
        WHERE id = ?
        ",
        id.into_inner()
    )
        .fetch_one(&mut database)
        .await;

    let user = match query.simplified() {
        Ok(user) => user,
        Err(SqlError::NonExistentRow) => {
            return Ok(
                HttpResponse::NotFound().finish()
            )
        }
        Err(e) => return Err(e.into())
    };

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


    println!("Connected to DB!");

    println!("Server binding to 127.0.0.1:8080");

    Ok(HttpServer::new(move || {
        App::new()
            .app_data(Data::new(pool.clone()))
            .service(login)
            .service(signup)
            .service(create_post)
            .service(get_post)
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
