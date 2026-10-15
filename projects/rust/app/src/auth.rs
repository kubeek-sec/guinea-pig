//! Member sessions: bearer tokens signed with the instance key.
use axum::http::HeaderMap;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::store::{Member, Store};

pub const ALGORITHM: Algorithm = Algorithm::HS256;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64,
}

fn signing_key() -> Option<String> {
    std::env::var("TOOLSHED_TOKEN_KEY").ok().filter(|k| !k.is_empty())
}

fn ttl() -> i64 {
    std::env::var("TOOLSHED_TOKEN_TTL")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(3600)
}

pub fn issue(member: &Member) -> Option<String> {
    let key = signing_key()?;
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: member.id.to_string(),
        email: member.email.clone(),
        role: member.role.clone(),
        iat: now,
        exp: now + ttl(),
    };
    encode(&Header::new(ALGORITHM), &claims, &EncodingKey::from_secret(key.as_bytes())).ok()
}

pub fn authenticate(store: &Store, email: &str, password: &str) -> Option<Member> {
    let member = store.member_by_email(email).ok().flatten()?;
    match bcrypt::verify(password, &member.password) {
        Ok(true) => Some(member),
        _ => None,
    }
}

pub fn from_headers(store: &Store, headers: &HeaderMap) -> Option<Member> {
    let header = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = header.strip_prefix("Bearer ")?;
    let key = signing_key()?;
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(key.as_bytes()),
        &Validation::new(ALGORITHM),
    )
    .ok()?
    .claims;
    let id = claims.sub.parse::<i64>().ok()?;
    store.member(id).ok().flatten()
}
