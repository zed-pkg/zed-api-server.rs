#!/usr/bin/env python3
"""Apply the reviewed canonical route aliases and package-scoped R2 key contract."""

from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one reviewed match, found {count}")
    target.write_text(text.replace(old, new, 1))


replace(
    "src/storage.rs",
    '''pub fn artifact_key(sha256: &str, extension: &str) -> String {
    format!("artifacts/{sha256}.{extension}")
}''',
    '''pub fn artifact_key(
    org: &str,
    name: &str,
    version: &str,
    sha256: &str,
    extension: &str,
) -> String {
    format!("zed/v1/packages/{org}/{name}/{version}/{sha256}.{extension}")
}''',
)
replace(
    "src/storage.rs",
    'assert_eq!(artifact_key("abc123", "tar.gz"), "artifacts/abc123.tar.gz");',
    '''assert_eq!(
            artifact_key("acme", "http-kit", "1.2.0", "abc123", "tar.gz"),
            "zed/v1/packages/acme/http-kit/1.2.0/abc123.tar.gz"
        );''',
)
replace(
    "src/storage.rs",
    "// Keys are server-generated (`artifacts/<sha>.<ext>`), never user input.",
    "// Keys are server-generated from validated package coordinates and the digest, never raw paths.",
)
replace(
    "src/routes/publish.rs",
    "let key = artifact_key(&actual_sha, meta.format.extension());",
    '''let key = artifact_key(
        &org_slug,
        &name,
        &ver,
        &actual_sha,
        meta.format.extension(),
    );''',
)

replace(
    "src/routes/mod.rs",
    'pub const ROUTE_FILES: &str = "/v1/files/{org}/{name}/{version}/{*path}";',
    '''pub const ROUTE_FILES: &str = "/v1/files/{org}/{name}/{version}/{*path}";

// Canonical product API. The package-manager registry is a bounded subset of
// `/api/v1`; legacy `/v1` routes remain as temporary compatibility aliases.
pub const CANONICAL_ROUTE_PACKAGE: &str = "/api/v1/registry/packages/{org}/{name}";
pub const CANONICAL_ROUTE_VERSION: &str =
    "/api/v1/registry/packages/{org}/{name}/versions/{version}";
pub const CANONICAL_ROUTE_YANK: &str =
    "/api/v1/registry/packages/{org}/{name}/versions/{version}/yank";
pub const CANONICAL_ROUTE_ARTIFACT: &str = "/api/v1/registry/artifacts/{sha256}";
pub const CANONICAL_ROUTE_SEARCH: &str = "/api/v1/registry/search";
pub const CANONICAL_ROUTE_PACKAGES_LIST: &str = "/api/v1/registry/packages";
pub const CANONICAL_ROUTE_SEMANTIC: &str = "/api/v1/registry/search/semantic";
pub const CANONICAL_ROUTE_EMBEDDING: &str =
    "/api/v1/registry/packages/{org}/{name}/embedding";
pub const CANONICAL_ROUTE_ORGS: &str = "/api/v1/registry/orgs";
pub const CANONICAL_ROUTE_AUDIT: &str = "/api/v1/registry/orgs/{org}/audit";
pub const CANONICAL_ROUTE_AUDIT_VERIFY: &str =
    "/api/v1/registry/orgs/{org}/audit/verify";
pub const CANONICAL_ROUTE_FILES: &str =
    "/api/v1/registry/files/{org}/{name}/{version}/{*path}";''',
)
replace(
    "src/routes/mod.rs",
    '''    let artifact_routes = Router::new()
        .route(ROUTE_ARTIFACT, get(artifacts::get_artifact))
        .route(ROUTE_FILES, get(artifacts::get_file))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            artifact_serve_concurrency(max_artifact_bytes),
        ));''',
    '''    let artifact_routes = Router::new()
        .route(ROUTE_ARTIFACT, get(artifacts::get_artifact))
        .route(ROUTE_FILES, get(artifacts::get_file))
        .route(CANONICAL_ROUTE_ARTIFACT, get(artifacts::get_artifact))
        .route(CANONICAL_ROUTE_FILES, get(artifacts::get_file))
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            artifact_serve_concurrency(max_artifact_bytes),
        ));''',
)
replace(
    "src/routes/mod.rs",
    '''    let publish_route = Router::new()
        .route(
            ROUTE_VERSION,
            get(packages::get_version).put(publish::publish),
        )
        .layer(DefaultBodyLimit::max(max_artifact_bytes));''',
    '''    let publish_route = Router::new()
        .route(
            ROUTE_VERSION,
            get(packages::get_version).put(publish::publish),
        )
        .route(
            CANONICAL_ROUTE_VERSION,
            get(packages::get_version).put(publish::publish),
        )
        .layer(DefaultBodyLimit::max(max_artifact_bytes));''',
)
replace(
    "src/routes/mod.rs",
    '''        .route(ROUTE_PACKAGES_LIST, get(list::list_packages))
        .route(ROUTE_PACKAGE, get(packages::get_package))
        .route(
            ROUTE_EMBEDDING,
            axum::routing::put(semantic::upsert_embedding),
        )
        .route(ROUTE_YANK, post(yank::yank))
        .route(ROUTE_SEARCH, get(search::search))
        .route(ROUTE_SEMANTIC, post(semantic::semantic_search))
        .route(ROUTE_ORGS, post(orgs::claim_org))
        .route(ROUTE_AUDIT, get(audit::get_audit_log))
        .route(ROUTE_AUDIT_VERIFY, get(audit::verify_audit_log))''',
    '''        .route(ROUTE_PACKAGES_LIST, get(list::list_packages))
        .route(ROUTE_PACKAGE, get(packages::get_package))
        .route(
            ROUTE_EMBEDDING,
            axum::routing::put(semantic::upsert_embedding),
        )
        .route(ROUTE_YANK, post(yank::yank))
        .route(ROUTE_SEARCH, get(search::search))
        .route(ROUTE_SEMANTIC, post(semantic::semantic_search))
        .route(ROUTE_ORGS, post(orgs::claim_org))
        .route(ROUTE_AUDIT, get(audit::get_audit_log))
        .route(ROUTE_AUDIT_VERIFY, get(audit::verify_audit_log))
        .route(CANONICAL_ROUTE_PACKAGES_LIST, get(list::list_packages))
        .route(CANONICAL_ROUTE_PACKAGE, get(packages::get_package))
        .route(
            CANONICAL_ROUTE_EMBEDDING,
            axum::routing::put(semantic::upsert_embedding),
        )
        .route(CANONICAL_ROUTE_YANK, post(yank::yank))
        .route(CANONICAL_ROUTE_SEARCH, get(search::search))
        .route(CANONICAL_ROUTE_SEMANTIC, post(semantic::semantic_search))
        .route(CANONICAL_ROUTE_ORGS, post(orgs::claim_org))
        .route(CANONICAL_ROUTE_AUDIT, get(audit::get_audit_log))
        .route(
            CANONICAL_ROUTE_AUDIT_VERIFY,
            get(audit::verify_audit_log),
        )''',
)
replace(
    "src/routes/mod.rs",
    '''    #[tokio::test]
    async fn healthz_works_without_a_database() {''',
    '''    #[test]
    fn canonical_registry_routes_are_nested_under_the_product_api() {
        for route in [
            CANONICAL_ROUTE_PACKAGE,
            CANONICAL_ROUTE_VERSION,
            CANONICAL_ROUTE_ARTIFACT,
            CANONICAL_ROUTE_SEARCH,
            CANONICAL_ROUTE_ORGS,
            CANONICAL_ROUTE_FILES,
        ] {
            assert!(route.starts_with("/api/v1/registry/"), "{route}");
        }
    }

    #[tokio::test]
    async fn healthz_works_without_a_database() {''',
)

replace(
    "src/account_router.rs",
    "        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT))",
    '''        .route("/api/v1/auth/config", get(account::auth_config))
        .route("/api/v1/auth/exchange", post(account::exchange_supabase))
        .route(
            "/api/v1/users/me",
            get(account::me).put(account::update_user_settings),
        )
        .route("/api/v1/home", get(account::home))
        .route("/api/v1/search", get(account::search))
        .route("/api/v1/orgs", post(account::create_org))
        .route("/api/v1/orgs/{org}", get(account::org_dashboard))
        .route(
            "/api/v1/orgs/{org}/invitations",
            post(account::invite_org_member),
        )
        .route(
            "/api/v1/orgs/{org}/projects",
            post(account::create_project),
        )
        .route(
            "/api/v1/orgs/{org}/projects/{project}/invitations",
            post(account::invite_project_member),
        )
        .route(
            "/api/v1/orgs/{org}/packages",
            post(account::create_package),
        )
        .route(
            "/api/v1/orgs/{org}/packages/{package}/settings",
            put(account::update_package_settings),
        )
        .route(
            "/api/v1/orgs/{org}/packages/{package}/public",
            post(account::make_package_public),
        )
        .route(
            "/api/v1/orgs/{org}/packages/{package}/licenses",
            post(account::add_package_license),
        )
        .route(
            "/api/v1/orgs/{org}/packages/{package}/uploads",
            post(account::register_package_upload),
        )
        .layer(DefaultBodyLimit::max(ACCOUNT_BODY_LIMIT))''',
)
replace(
    "src/account_router.rs",
    '''    fn account_routes_are_namespaced_away_from_legacy_tokens() {
        for route in [
            "/v1/account/me",
            "/v1/account/home",
            "/v1/account/orgs/{org}",
            "/v1/account/orgs/{org}/packages/{package}/public",
        ] {
            assert!(route.starts_with("/v1/account/"));
        }
    }''',
    '''    fn account_routes_keep_legacy_aliases_and_use_the_product_api_canonically() {
        for route in [
            "/v1/account/me",
            "/v1/account/home",
            "/v1/account/orgs/{org}",
            "/v1/account/orgs/{org}/packages/{package}/public",
        ] {
            assert!(route.starts_with("/v1/account/"));
        }
        for route in [
            "/api/v1/users/me",
            "/api/v1/home",
            "/api/v1/orgs/{org}",
            "/api/v1/orgs/{org}/packages/{package}/public",
        ] {
            assert!(route.starts_with("/api/v1/"));
            assert!(!route.contains("/account/"));
        }
    }''',
)
replace(
    ".github/workflows/registry-publish-e2e.yml",
    "http://127.0.0.1:8080/v1/packages/e2e/registry-smoke/versions/0.1.0",
    "http://127.0.0.1:8080/api/v1/registry/packages/e2e/registry-smoke/versions/0.1.0",
)
