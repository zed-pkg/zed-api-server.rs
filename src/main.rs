mod audit;
mod auth;
mod config;
mod embeddings;
mod entities;
mod error;
mod files;
mod ratelimit;
mod rbac;
mod routes;
mod server;
mod state;
mod storage;
mod tokens;
mod verify;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    server::run().await
}
