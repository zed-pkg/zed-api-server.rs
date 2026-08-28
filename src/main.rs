#[path = "routes/account.rs"]
mod account;
mod account_router;
mod api_docs;
mod audit;
mod auth;
mod binary_artifact;
#[cfg(test)]
mod binary_artifact_adversarial_tests;
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
mod storage_report;
mod tokens;
mod verify;

const HELP: &str = "zed-api-server\n\nUSAGE:\n    zed-api-server [COMMAND]\n\nCOMMANDS:\n    serve                         Start the registry server (default)\n    migrate                       Apply database migrations and exit\n    healthcheck                   Check configured dependencies and exit\n    create-token [OPTIONS]        Create an API token\n    revoke-token [OPTIONS]        Revoke an API token\n\nOPTIONS:\n    -h, --help                    Print help\n    -V, --version                 Print version\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyCommand {
    Help,
    Version,
}

fn early_command(args: &[String]) -> Option<EarlyCommand> {
    match args.get(1).map(String::as_str) {
        Some("-h" | "--help" | "help") => Some(EarlyCommand::Help),
        Some("-V" | "--version" | "version") => Some(EarlyCommand::Version),
        _ => None,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    match early_command(&args) {
        Some(EarlyCommand::Help) => {
            print!("{HELP}");
            Ok(())
        }
        Some(EarlyCommand::Version) => {
            println!("zed-api-server {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        None => server::run().await,
    }
}

#[cfg(test)]
mod tests {
    use super::{EarlyCommand, early_command};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn help_and_version_are_zero_io_early_commands() {
        for flag in ["-h", "--help", "help"] {
            assert_eq!(
                early_command(&args(&["zed-api-server", flag])),
                Some(EarlyCommand::Help)
            );
        }
        for flag in ["-V", "--version", "version"] {
            assert_eq!(
                early_command(&args(&["zed-api-server", flag])),
                Some(EarlyCommand::Version)
            );
        }
    }

    #[test]
    fn operational_commands_still_enter_the_server_dispatcher() {
        for command in [
            "serve",
            "migrate",
            "healthcheck",
            "create-token",
            "revoke-token",
        ] {
            assert_eq!(early_command(&args(&["zed-api-server", command])), None);
        }
    }
}
