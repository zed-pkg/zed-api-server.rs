#[path = "routes/account.rs"]
mod account;
mod account_router;
mod audit;
mod auth;
mod binary_artifact;
mod config;
mod embeddings;
mod entities;
mod error;
mod files;
mod ratelimit;
mod rbac;
mod routes;
mod server;
mod shared_auth;
mod state;
mod storage;
mod tokens;
mod verify;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    server::run().await
}
