//! Formal virtual-host boundary for `registry*.zpkg.net`.
//!
//! The server intentionally keeps browser/account compatibility routes below
//! `/v1`, so a prefix-based Ingress rule cannot establish that the registry
//! hostname is registry-only. This module is the sole authority for that host:
//! a total, state-free transition function maps every `(host, method, path)` to
//! bypass, allow, reject-route, or reject-method before a handler can run.

use axum::Json;
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundaryDecision {
    /// A non-registry Host gets the complete API surface.
    Bypass,
    /// A known machine-registry route and valid method may continue.
    Allow { route: &'static str, mutating: bool },
    /// The Host is registry-only and the path is outside that surface.
    RejectRoute,
    /// The path is known, but this method is not part of its API contract.
    RejectMethod { allow: &'static str },
}

#[derive(Debug, Clone, Copy)]
struct RouteSpec {
    name: &'static str,
    methods: &'static [&'static str],
}

const READ: &[&str] = &["GET", "HEAD", "OPTIONS"];
const POST: &[&str] = &["POST", "OPTIONS"];
const PUT: &[&str] = &["PUT", "OPTIONS"];
const VERSION: &[&str] = &["GET", "HEAD", "PUT", "OPTIONS"];

/// Total transition function. It performs no I/O and mutates no state.
pub(crate) fn decide(host: Option<&str>, method: &Method, path: &str) -> BoundaryDecision {
    if !host.is_some_and(is_registry_host) {
        return BoundaryDecision::Bypass;
    }
    let Some(route) = registry_route(path) else {
        return BoundaryDecision::RejectRoute;
    };
    if !route.methods.contains(&method.as_str()) {
        return BoundaryDecision::RejectMethod {
            allow: allow_header(route.methods),
        };
    }
    BoundaryDecision::Allow {
        route: route.name,
        mutating: !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS"),
    }
}

pub(crate) async fn enforce_registry_host(request: Request, next: Next) -> Response {
    let host = request_host(request.headers()).or_else(|| {
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str().to_ascii_lowercase())
    });
    match decide(host.as_deref(), request.method(), request.uri().path()) {
        BoundaryDecision::Bypass | BoundaryDecision::Allow { .. } => next.run(request).await,
        BoundaryDecision::RejectRoute => problem(
            StatusCode::NOT_FOUND,
            "not_registry_route",
            "use api.zpkg.net for non-registry APIs",
            None,
        ),
        BoundaryDecision::RejectMethod { allow } => problem(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method is not valid for this registry route",
            Some(allow),
        ),
    }
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
}

fn is_registry_host(raw_host: &str) -> bool {
    let host = strip_port(raw_host).trim_end_matches('.');
    host == "registry.zpkg.net" || (host.starts_with("registry.") && host.ends_with(".zpkg.net"))
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host;
    }
    host.rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or(host, |(name, _)| name)
}

fn registry_route(path: &str) -> Option<RouteSpec> {
    if path.is_empty()
        || path.len() > 2048
        || path.contains('%')
        || path.contains("..")
        || path.contains('\\')
        || path.contains("//")
    {
        return None;
    }
    let segments = path
        .strip_prefix('/')?
        .trim_end_matches('/')
        .split('/')
        .collect::<Vec<_>>();

    let spec = match segments.as_slice() {
        ["healthz"] => RouteSpec {
            name: "healthz",
            methods: READ,
        },
        ["v1", "packages"] => RouteSpec {
            name: "list_packages",
            methods: READ,
        },
        ["v1", "packages", org, package] if slug(org) && slug(package) => RouteSpec {
            name: "get_package",
            methods: READ,
        },
        ["v1", "packages", org, package, "versions", version]
            if slug(org) && slug(package) && version_segment(version) =>
        {
            RouteSpec {
                name: "version",
                methods: VERSION,
            }
        }
        ["v1", "packages", org, package, "versions", version, "yank"]
            if slug(org) && slug(package) && version_segment(version) =>
        {
            RouteSpec {
                name: "yank",
                methods: POST,
            }
        }
        ["v1", "packages", org, package, "embedding"] if slug(org) && slug(package) => RouteSpec {
            name: "embedding",
            methods: PUT,
        },
        [
            "v1",
            "packages",
            org,
            package,
            "versions",
            version,
            "dependency-graph",
        ] if slug(org) && slug(package) && version_segment(version) => RouteSpec {
            name: "declared_graph",
            methods: READ,
        },
        [
            "v1",
            "packages",
            org,
            package,
            "versions",
            version,
            "dependency-graph",
            "export",
            format,
        ] if slug(org) && slug(package) && version_segment(version) && slug(format) => RouteSpec {
            name: "declared_graph_export",
            methods: READ,
        },
        ["v1", "artifacts", digest] if sha256(digest) => RouteSpec {
            name: "artifact",
            methods: READ,
        },
        ["v1", "files", org, package, version, rest @ ..]
            if slug(org)
                && slug(package)
                && version_segment(version)
                && !rest.is_empty()
                && rest.iter().all(|segment| file_segment(segment)) =>
        {
            RouteSpec {
                name: "files",
                methods: READ,
            }
        }
        ["v1", "search"] => RouteSpec {
            name: "search",
            methods: READ,
        },
        ["v1", "search", "semantic"] => RouteSpec {
            name: "semantic_search",
            methods: POST,
        },
        ["v1", "orgs"] => RouteSpec {
            name: "claim_org",
            methods: POST,
        },
        ["v1", "orgs", org, "audit"] if slug(org) => RouteSpec {
            name: "audit",
            methods: READ,
        },
        ["v1", "orgs", org, "audit", "verify"] if slug(org) => RouteSpec {
            name: "audit_verify",
            methods: READ,
        },
        ["v1", "resolutions", digest, "dependency-graph"] if resolution_digest(digest) => {
            RouteSpec {
                name: "resolution_graph",
                methods: READ,
            }
        }
        _ => return None,
    };
    Some(spec)
}

fn slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn version_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

fn file_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn resolution_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(sha256)
}

fn allow_header(methods: &'static [&'static str]) -> &'static str {
    if methods == READ {
        "GET, HEAD, OPTIONS"
    } else if methods == POST {
        "POST, OPTIONS"
    } else if methods == PUT {
        "PUT, OPTIONS"
    } else if methods == VERSION {
        "GET, HEAD, PUT, OPTIONS"
    } else {
        "OPTIONS"
    }
}

fn problem(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    allow: Option<&'static str>,
) -> Response {
    let mut response = (
        status,
        Json(json!({ "ok": false, "error": code, "message": message })),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("static header"),
    );
    if let Some(allow) = allow {
        headers.insert(header::ALLOW, allow.parse().expect("static header"));
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::{BoundaryDecision, decide, enforce_registry_host};

    #[test]
    fn transition_table_covers_the_machine_registry_surface() {
        let sha = "a".repeat(64);
        let resolution = format!("sha256:{}", "b".repeat(64));
        let cases = [
            ("GET", "/healthz", "healthz"),
            ("GET", "/v1/packages", "list_packages"),
            ("GET", "/v1/packages/acme/http-kit", "get_package"),
            (
                "PUT",
                "/v1/packages/acme/http-kit/versions/1.0.0",
                "version",
            ),
            (
                "POST",
                "/v1/packages/acme/http-kit/versions/1.0.0/yank",
                "yank",
            ),
            ("PUT", "/v1/packages/acme/http-kit/embedding", "embedding"),
            (
                "GET",
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph",
                "declared_graph",
            ),
            (
                "GET",
                "/v1/packages/acme/http-kit/versions/1.0.0/dependency-graph/export/json",
                "declared_graph_export",
            ),
            ("GET", "/v1/search", "search"),
            ("POST", "/v1/search/semantic", "semantic_search"),
            ("POST", "/v1/orgs", "claim_org"),
            ("GET", "/v1/orgs/acme/audit", "audit"),
            ("GET", "/v1/orgs/acme/audit/verify", "audit_verify"),
        ];
        for (method, path, route) in cases {
            let method = method.parse().expect("test method");
            assert!(
                matches!(
                    decide(Some("registry.zpkg.net"), &method, path),
                    BoundaryDecision::Allow { route: actual, .. } if actual == route
                ),
                "{method} {path}",
            );
        }

        for (path, route) in [
            (format!("/v1/artifacts/{sha}"), "artifact"),
            (
                "/v1/files/acme/http-kit/1.0.0/README.md".to_owned(),
                "files",
            ),
            (
                format!("/v1/resolutions/{resolution}/dependency-graph"),
                "resolution_graph",
            ),
        ] {
            assert!(matches!(
                decide(Some("registry.zpkg.net"), &Method::GET, &path),
                BoundaryDecision::Allow { route: actual, .. } if actual == route
            ));
        }
    }

    #[test]
    fn account_auth_docs_and_unknown_routes_fail_closed() {
        for path in [
            "/",
            "/docs",
            "/openapi.json",
            "/api/v1/auth/config",
            "/api/v1/account/me",
            "/v1/account/me",
            "/v1/me",
            "/v1/session/bootstrap",
            "/v1/admin",
            "/v1/%2e%2e/secret",
        ] {
            assert_eq!(
                decide(Some("registry.zpkg.net"), &Method::GET, path),
                BoundaryDecision::RejectRoute,
                "{path}",
            );
        }
    }

    #[test]
    fn only_registry_virtual_hosts_are_constrained() {
        for host in [
            "registry.zpkg.net",
            "registry.zpkg.net:443",
            "registry.aws.zpkg.net",
            "registry.hetzner.zpkg.net.",
        ] {
            assert_eq!(
                decide(Some(host), &Method::GET, "/v1/account/me"),
                BoundaryDecision::RejectRoute,
                "{host}",
            );
        }
        for host in [
            "api.zpkg.net",
            "zed-api-server.zed.svc.cluster.local",
            "localhost:8080",
        ] {
            assert_eq!(
                decide(Some(host), &Method::GET, "/v1/account/me"),
                BoundaryDecision::Bypass,
                "{host}",
            );
        }
    }

    #[test]
    fn wrong_method_is_a_controlled_state() {
        assert_eq!(
            decide(
                Some("registry.zpkg.net"),
                &Method::DELETE,
                "/v1/packages/acme/http-kit"
            ),
            BoundaryDecision::RejectMethod {
                allow: "GET, HEAD, OPTIONS"
            }
        );
    }

    #[tokio::test]
    async fn middleware_blocks_account_handler_but_allows_registry_handler() {
        let app = Router::new()
            .route("/v1/account/me", get(|| async { "account" }))
            .route("/v1/packages/acme/http-kit", get(|| async { "package" }))
            .layer(middleware::from_fn(enforce_registry_host));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/account/me")
                    .header("host", "registry.zpkg.net")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(denied.status(), StatusCode::NOT_FOUND);

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/packages/acme/http-kit")
                    .header("host", "registry.zpkg.net")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::OK);

        let full_api = app
            .oneshot(
                Request::builder()
                    .uri("/v1/account/me")
                    .header("host", "api.zpkg.net")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(full_api.status(), StatusCode::OK);
    }
}
