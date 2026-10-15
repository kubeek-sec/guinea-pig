//! The HTTP surface of the workshop.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axum::extract::{Multipart, Query, State as AxumState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;

use crate::auth;
use crate::store::{Member, Store};
use crate::VERSION;

const SORTABLE: [&str; 3] = ["name", "category", "daily_rate"];
const ACCEPTED: [&str; 4] = ["jpg", "jpeg", "png", "webp"];
const DEFAULT_DAYS: i64 = 7;
const MAX_PHOTO_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct State {
    pub store: Store,
    pub uploads: String,
}

fn fail(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn server_error() -> Response {
    fail(StatusCode::INTERNAL_SERVER_ERROR, "the workshop records are unavailable")
}

fn signed_in(state: &State, headers: &HeaderMap) -> Result<Member, Response> {
    auth::from_headers(&state.store, headers)
        .ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "authentication required"))
}

fn staff(state: &State, headers: &HeaderMap) -> Result<Member, Response> {
    let member = signed_in(state, headers)?;
    if member.role == "staff" {
        Ok(member)
    } else {
        Err(fail(StatusCode::FORBIDDEN, "staff only"))
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn router(state: State) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/openapi.yml", get(openapi))
        .route("/", get(home))
        .route("/api/tools", get(list_tools))
        .route("/api/tools/search", get(search_tools))
        .route("/api/tools/:id", get(get_tool))
        .route("/api/session", post(sign_in))
        .route("/api/members/me", get(whoami))
        .route("/api/members/:id", get(get_member))
        .route("/api/rentals", get(my_rentals).post(take_out))
        .route("/api/rentals/:id/return", post(bring_back))
        .route("/api/photos", post(upload_photo))
        .route("/api/photos/:name", get(fetch_photo))
        .with_state(state)
}

async fn health() -> Response {
    Json(json!({ "status": "ok", "version": VERSION })).into_response()
}

async fn openapi() -> Response {
    match tokio::fs::read_to_string("openapi.yml").await {
        Ok(body) => ([(header::CONTENT_TYPE, "application/yaml")], body).into_response(),
        Err(_) => fail(StatusCode::NOT_FOUND, "no API description here"),
    }
}

async fn home(AxumState(state): AxumState<State>) -> Response {
    let Ok(tools) = state.store.top_tools(20) else {
        return server_error();
    };
    let rows: String = tools
        .iter()
        .map(|t| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{:.2} &euro;</td><td>{}</td></tr>\n",
                escape(&t.name),
                escape(&t.category),
                t.daily_rate,
                if t.available { "on the rack" } else { "<span class=\"out\">out</span>" }
            )
        })
        .collect();
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Toolshed</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:48rem}}
table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}}
.out{{color:#999}}</style></head>
<body><h1>Toolshed</h1><p>Tools the workshop lends to its members.</p>
<table><tr><th>Tool</th><th>Category</th><th>Per day</th><th>Status</th></tr>
{rows}
</table><p><a href="/openapi.yml">API description</a></p></body></html>"#
    ))
    .into_response()
}

async fn list_tools(AxumState(state): AxumState<State>,
                    Query(params): Query<HashMap<String, String>>) -> Response {
    let sort = params.get("sort").cloned().unwrap_or_else(|| "name".to_string());
    if !SORTABLE.contains(&sort.as_str()) {
        return fail(StatusCode::BAD_REQUEST, &format!("cannot sort on '{sort}'"));
    }
    match state.store.tools_ordered_by(&sort) {
        Ok(tools) => Json(json!({ "tools": tools })).into_response(),
        Err(_) => server_error(),
    }
}

async fn search_tools(AxumState(state): AxumState<State>,
                      Query(params): Query<HashMap<String, String>>) -> Response {
    let term = params.get("q").cloned().unwrap_or_default();
    match state.store.search_tools(&term) {
        Ok(tools) => Json(json!({ "query": term, "tools": tools })).into_response(),
        Err(_) => server_error(),
    }
}

async fn get_tool(AxumState(state): AxumState<State>,
                  axum::extract::Path(id): axum::extract::Path<i64>) -> Response {
    match state.store.tool(id) {
        Ok(Some(tool)) => Json(tool).into_response(),
        Ok(None) => fail(StatusCode::NOT_FOUND, "no such tool"),
        Err(_) => server_error(),
    }
}

#[derive(Deserialize)]
struct Credentials {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

async fn sign_in(AxumState(state): AxumState<State>, Json(body): Json<Credentials>) -> Response {
    let Some(member) = auth::authenticate(&state.store, &body.email, &body.password) else {
        return fail(StatusCode::UNAUTHORIZED, "bad credentials");
    };
    match auth::issue(&member) {
        Some(token) => Json(json!({ "token": token, "role": member.role })).into_response(),
        None => fail(StatusCode::INTERNAL_SERVER_ERROR, "cannot issue a token"),
    }
}

async fn whoami(AxumState(state): AxumState<State>, headers: HeaderMap) -> Response {
    match signed_in(&state, &headers) {
        Ok(member) => Json(member).into_response(),
        Err(refusal) => refusal,
    }
}

async fn get_member(AxumState(state): AxumState<State>, headers: HeaderMap,
                    axum::extract::Path(id): axum::extract::Path<i64>) -> Response {
    if let Err(refusal) = staff(&state, &headers) {
        return refusal;
    }
    match state.store.member(id) {
        Ok(Some(member)) => Json(member).into_response(),
        Ok(None) => fail(StatusCode::NOT_FOUND, "no such member"),
        Err(_) => server_error(),
    }
}

async fn my_rentals(AxumState(state): AxumState<State>, headers: HeaderMap) -> Response {
    let member = match signed_in(&state, &headers) {
        Ok(m) => m,
        Err(refusal) => return refusal,
    };
    match state.store.rentals_of(member.id) {
        Ok(rentals) => Json(json!({ "rentals": rentals })).into_response(),
        Err(_) => server_error(),
    }
}

#[derive(Deserialize)]
struct TakeOut {
    tool_id: i64,
    #[serde(default)]
    days: Option<i64>,
    #[serde(default)]
    notes: Option<String>,
}

async fn take_out(AxumState(state): AxumState<State>, headers: HeaderMap,
                  Json(body): Json<TakeOut>) -> Response {
    let member = match signed_in(&state, &headers) {
        Ok(m) => m,
        Err(refusal) => return refusal,
    };
    let tool = match state.store.tool(body.tool_id) {
        Ok(Some(t)) => t,
        Ok(None) => return fail(StatusCode::NOT_FOUND, "no such tool"),
        Err(_) => return server_error(),
    };
    if !tool.available {
        return fail(StatusCode::CONFLICT, "already out");
    }
    let days = body.days.filter(|d| *d > 0).unwrap_or(DEFAULT_DAYS);
    let today = chrono::Utc::now().date_naive();
    let due = today + chrono::Duration::days(days);
    let notes = body.notes.unwrap_or_default();
    match state.store.create_rental(member.id, tool.id, &today.to_string(), &due.to_string(), &notes) {
        Ok(id) => {
            if state.store.set_tool_available(tool.id, false).is_err() {
                return server_error();
            }
            (StatusCode::CREATED, Json(json!({ "id": id, "due_on": due.to_string() }))).into_response()
        }
        Err(_) => server_error(),
    }
}

async fn bring_back(AxumState(state): AxumState<State>, headers: HeaderMap,
                    axum::extract::Path(id): axum::extract::Path<i64>) -> Response {
    let member = match signed_in(&state, &headers) {
        Ok(m) => m,
        Err(refusal) => return refusal,
    };
    let rental = match state.store.rental_of(id, member.id) {
        Ok(Some(r)) => r,
        Ok(None) => return fail(StatusCode::NOT_FOUND, "no such rental"),
        Err(_) => return server_error(),
    };
    if state.store.close_rental(rental.id).is_err()
        || state.store.set_tool_available(rental.tool_id, true).is_err()
    {
        return server_error();
    }
    Json(json!({ "status": "returned" })).into_response()
}

async fn upload_photo(AxumState(state): AxumState<State>, headers: HeaderMap,
                      mut multipart: Multipart) -> Response {
    let member = match signed_in(&state, &headers) {
        Ok(m) => m,
        Err(refusal) => return refusal,
    };
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() != Some("photo") {
            continue;
        }
        let filename = field.file_name().unwrap_or_default().to_string();
        let ext = Path::new(&filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_lowercase();
        if !ACCEPTED.contains(&ext.as_str()) {
            let label = if ext.is_empty() { "file".to_string() } else { format!(".{ext}") };
            return fail(StatusCode::BAD_REQUEST, &format!("{label} not accepted"));
        }
        let Ok(bytes) = field.bytes().await else {
            return fail(StatusCode::BAD_REQUEST, "no photo");
        };
        if bytes.len() > MAX_PHOTO_BYTES {
            return fail(StatusCode::BAD_REQUEST, "photo too large");
        }
        let mut token = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut token);
        let name = format!("{}.{ext}", hex::encode(token));
        if tokio::fs::write(PathBuf::from(&state.uploads).join(&name), &bytes).await.is_err() {
            return server_error();
        }
        return (StatusCode::CREATED,
                Json(json!({ "name": name, "owner": member.email }))).into_response();
    }
    fail(StatusCode::BAD_REQUEST, "no photo")
}

async fn fetch_photo(AxumState(state): AxumState<State>,
                     axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    let Some(base) = Path::new(&name).file_name() else {
        return fail(StatusCode::NOT_FOUND, "no such photo");
    };
    let file = PathBuf::from(&state.uploads).join(base);
    match tokio::fs::read(&file).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "application/octet-stream"),
             (header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
            bytes,
        )
            .into_response(),
        Err(_) => fail(StatusCode::NOT_FOUND, "no such photo"),
    }
}
