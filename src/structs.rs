use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Login details (private)
#[derive(Deserialize)]
pub struct LoginDetails {
    pub email: String,
    pub password: String
}

/// Sign up details (private)
#[derive(Deserialize)]
pub struct SignupDetails {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Public user data
#[derive(Serialize, Deserialize)]
pub struct UserData {
    pub id: u64,
    pub username: String,
    pub bio: Option<String>,
    pub profile_picture: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PostData {
    pub title: String,
    pub content: String,
    pub author: Option<u64>
}

#[derive(Serialize, Deserialize)]
pub struct JwtData {
    pub username: String,
    pub email: String,
    // User ID (generated by SQL)
    pub id: u64,
    /// Expiry
    pub exp: i64
}