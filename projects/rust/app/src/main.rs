//! Toolshed — the lending service of a neighbourhood workshop.
mod auth;
mod store;
mod web;

use std::net::SocketAddr;

use store::Store;

pub const VERSION: &str = "1.4.2";

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| fallback.to_string())
}

#[tokio::main]
async fn main() {
    let db_file = env_or("TOOLSHED_DB", "var/toolshed.db");
    let uploads = env_or("TOOLSHED_UPLOADS", "var/uploads");
    std::fs::create_dir_all(&uploads).expect("create the upload directory");

    let store = Store::open(&db_file).expect("open the database");
    let app = web::router(web::State { store, uploads });

    let port: u16 = env_or("PORT", "8000").parse().expect("PORT must be a number");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind the port");
    println!("toolshed {VERSION} listening on {addr}");
    axum::serve(listener, app).await.expect("serve");
}
