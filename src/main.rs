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
mod flags;
mod ratelimit;
mod rbac;
mod registry_host;
mod routes;
mod server;
mod shared_auth;
mod state;
mod storage;
mod tokens;
mod verify;

fn contract_command(args: &[String]) -> Option<&str> {
    match args.get(1).map(String::as_str) {
        Some(command @ ("serve" | "migrate" | "healthcheck" | "help" | "version")) => Some(command),
        _ => None,
    }
}

fn delegates_argv(args: &[String]) -> bool {
    matches!(
        args.get(1).map(String::as_str),
        Some("create-token" | "revoke-token")
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if delegates_argv(&args) {
        flags::process_environment_only().map_err(anyhow::Error::msg)?;
    } else if let Some(output) =
        flags::process_control(contract_command(&args)).map_err(anyhow::Error::msg)?
    {
        print!("{output}");
        return Ok(());
    }
    server::run().await
}

#[cfg(test)]
mod tests {
    use super::{contract_command, delegates_argv};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn contract_commands_are_identified_without_consuming_token_options() {
        for command in ["serve", "migrate", "healthcheck", "help", "version"] {
            assert_eq!(
                contract_command(&args(&["zed-api-server", command])),
                Some(command)
            );
        }
        assert_eq!(contract_command(&args(&["zed-api-server", "--help"])), None);
    }

    #[test]
    fn token_subcommands_retain_their_private_argument_parsers() {
        for command in ["create-token", "revoke-token"] {
            assert!(delegates_argv(&args(&[
                "zed-api-server",
                command,
                "--name",
                "ci"
            ])));
        }
        assert!(!delegates_argv(&args(&["zed-api-server", "serve"])));
    }
}
