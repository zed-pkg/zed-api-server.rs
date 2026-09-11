//! Canonical public API-documentation routes and discovery manifest.
//!
//! These routes are deliberately composed outside the authenticated registry
//! router. They remain same-origin and public without weakening token,
//! rate-limit, timeout, or body-limit policy on package operations.

use axum::{
    Router,
    body::Body,
    http::{Response, StatusCode, header},
    routing::get,
};

pub const DISCOVERY_PATH: &str = "/.well-known/api-docs";
pub const OPENAPI_PATH: &str = "/openapi.json";
pub const OPENAPI_ALIAS: &str = "/api/docs.json";
pub const DOCS_PATH: &str = "/api/docs";
pub const DOCS_ALIAS: &str = "/docs/api";
pub const OPENAPI_SHA256: &str = "021d7cc2cbe37045db98b8dbf6c73fccafb2d4bfd17443555a3adc66cfa52030";

const OPENAPI_ETAG: &str = "\"021d7cc2cbe37045db98b8dbf6c73fccafb2d4bfd17443555a3adc66cfa52030\"";
const OPENAPI_MEDIA_TYPE: &str = "application/vnd.oai.openapi+json;version=3.1";
const OPENAPI: &str = include_str!("../openapi/zed.openapi.json");
const MANIFEST: &str = include_str!("../openapi/api-docs.manifest.json");
const DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zed Package Registry API documentation</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { margin: 0 auto; max-width: 72rem; padding: 2rem; }
    code { overflow-wrap: anywhere; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border-bottom: 1px solid currentColor; padding: .55rem; text-align: left; }
    .mutating { font-weight: 700; }
  </style>
</head>
<body>
  <h1>Zed Package Registry API</h1>
  <p id="provenance">Loading the canonical OpenAPI contract…</p>
  <table>
    <thead><tr><th>Method</th><th>Path</th><th>Operation</th><th>Summary</th></tr></thead>
    <tbody id="operations"></tbody>
  </table>
  <script>
    (async () => {
      const manifestResponse = await fetch('/.well-known/api-docs', {redirect: 'error'});
      if (!manifestResponse.ok) throw new Error('manifest unavailable');
      const manifest = await manifestResponse.json();
      const specResponse = await fetch(manifest.public.openapi.path, {redirect: 'error'});
      if (!specResponse.ok) throw new Error('OpenAPI unavailable');
      const spec = await specResponse.json();
      document.querySelector('#provenance').textContent =
        `${spec.info.title} ${spec.info.version} · SHA-256 ${manifest.public.openapi.sha256}`;
      const rows = [];
      for (const [path, item] of Object.entries(spec.paths)) {
        for (const method of ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace']) {
          const operation = item[method];
          if (!operation) continue;
          rows.push({path, method: method.toUpperCase(), operation});
        }
      }
      rows.sort((a, b) => a.operation.operationId.localeCompare(b.operation.operationId));
      const body = document.querySelector('#operations');
      for (const row of rows) {
        const tr = document.createElement('tr');
        if (row.operation['x-ore-mcp-mutating']) tr.className = 'mutating';
        for (const value of [row.method, row.path, row.operation.operationId, row.operation.summary]) {
          const td = document.createElement('td');
          td.textContent = value;
          tr.appendChild(td);
        }
        body.appendChild(tr);
      }
    })().catch((error) => {
      document.querySelector('#provenance').textContent = `Documentation error: ${error.message}`;
    });
  </script>
</body>
</html>
"#;

/// Return the state-free documentation router.
///
/// The server composes this beside, rather than inside, the registry router so
/// documentation never inherits application authentication or token quotas.
pub fn router() -> Router {
    Router::new()
        .route(DISCOVERY_PATH, get(discovery))
        .route(OPENAPI_PATH, get(openapi))
        .route(OPENAPI_ALIAS, get(openapi))
        .route(DOCS_PATH, get(docs))
        .route(DOCS_ALIAS, get(docs))
}

async fn discovery() -> Response<Body> {
    response(MANIFEST, "application/json", false, false)
}

async fn openapi() -> Response<Body> {
    response(OPENAPI, OPENAPI_MEDIA_TYPE, false, true)
}

async fn docs() -> Response<Body> {
    response(DOCS_HTML, "text/html; charset=utf-8", true, false)
}

fn response(
    body: &'static str,
    content_type: &'static str,
    html: bool,
    openapi_etag: bool,
) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "public, max-age=300")
        .header("x-openapi-sha256", OPENAPI_SHA256)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    if openapi_etag {
        builder = builder.header(header::ETAG, OPENAPI_ETAG);
    }
    if html {
        builder = builder.header(
            "content-security-policy",
            "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
        );
    }
    builder
        .body(Body::from(body))
        .expect("static API documentation response must be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes,
        http::{Method, Request},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    async fn fetch(path: &str, method: Method) -> Response<Body> {
        router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .expect("request must build"),
            )
            .await
            .expect("documentation router must respond")
    }

    #[tokio::test]
    async fn openapi_alias_is_exact_byte_for_byte() {
        let canonical = fetch(OPENAPI_PATH, Method::GET).await;
        let alias = fetch(OPENAPI_ALIAS, Method::GET).await;
        assert_eq!(canonical.status(), StatusCode::OK);
        assert_eq!(alias.status(), StatusCode::OK);
        assert_eq!(
            canonical
                .headers()
                .get("x-openapi-sha256")
                .expect("digest header")
                .to_str()
                .expect("digest header text"),
            OPENAPI_SHA256
        );
        assert_eq!(
            canonical
                .headers()
                .get(header::ETAG)
                .expect("ETag")
                .to_str()
                .expect("ETag text"),
            OPENAPI_ETAG
        );
        let canonical = to_bytes(canonical.into_body(), 8 * 1024 * 1024)
            .await
            .expect("canonical body must be bounded");
        let alias = to_bytes(alias.into_body(), 8 * 1024 * 1024)
            .await
            .expect("alias body must be bounded");
        assert_eq!(canonical, alias);
        assert_eq!(canonical.as_ref(), OPENAPI.as_bytes());
    }

    #[tokio::test]
    async fn manifest_names_canonical_routes_digest_and_mcp_pair() {
        let response = fetch(DISCOVERY_PATH, Method::GET).await;
        let body = to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("manifest body must be bounded");
        let manifest: Value = serde_json::from_slice(&body).expect("manifest must be JSON");
        assert_eq!(manifest["schemaVersion"], "ore.api-docs.v1");
        assert_eq!(manifest["public"]["openapi"]["path"], OPENAPI_PATH);
        assert_eq!(manifest["public"]["openapi"]["sha256"], OPENAPI_SHA256);
        assert_eq!(manifest["mcp"]["repository"], "zed-pkg/zed-mcp-server.rs");
        assert_eq!(manifest["mcp"]["mode"], "read-only");
        assert_eq!(manifest["internal"]["available"], false);
    }

    #[tokio::test]
    async fn get_routes_provide_head_without_a_body() {
        let response = fetch(OPENAPI_PATH, Method::HEAD).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("content type")
                .to_str()
                .expect("content type text"),
            OPENAPI_MEDIA_TYPE
        );
        let body = to_bytes(response.into_body(), 1)
            .await
            .expect("HEAD response must be empty");
        assert!(body.is_empty());
    }

    #[test]
    fn checked_in_openapi_covers_every_machine_registry_route() {
        let value: Value = serde_json::from_str(OPENAPI).expect("OpenAPI must be JSON");
        let paths = value["paths"].as_object().expect("paths must be an object");

        let expected = [
            ("/healthz".to_owned(), "get"),
            (crate::routes::ROUTE_PACKAGES_LIST.to_owned(), "get"),
            (crate::routes::ROUTE_PACKAGE.to_owned(), "get"),
            (crate::routes::ROUTE_VERSION.to_owned(), "get"),
            (crate::routes::ROUTE_VERSION.to_owned(), "put"),
            (crate::routes::ROUTE_DECLARED_GRAPH.to_owned(), "get"),
            (crate::routes::ROUTE_RESOLUTION_GRAPH.to_owned(), "get"),
            (crate::routes::ROUTE_YANK.to_owned(), "post"),
            (crate::routes::ROUTE_ARTIFACT.to_owned(), "get"),
            (
                crate::routes::ROUTE_FILES.replace("{*path}", "{path}"),
                "get",
            ),
            (crate::routes::ROUTE_SEARCH.to_owned(), "get"),
            (crate::routes::ROUTE_SEMANTIC.to_owned(), "post"),
            (crate::routes::ROUTE_EMBEDDING.to_owned(), "put"),
            (crate::routes::ROUTE_ORGS.to_owned(), "post"),
            (crate::routes::ROUTE_AUDIT.to_owned(), "get"),
            (crate::routes::ROUTE_AUDIT_VERIFY.to_owned(), "get"),
        ];

        for (path, method) in &expected {
            assert!(
                paths
                    .get(path)
                    .and_then(Value::as_object)
                    .is_some_and(|item| item.contains_key(*method)),
                "OpenAPI is missing {} {}",
                method.to_ascii_uppercase(),
                path
            );
        }
        let operation_count = paths
            .values()
            .filter_map(Value::as_object)
            .map(|item| {
                [
                    "get", "post", "put", "patch", "delete", "head", "options", "trace",
                ]
                .into_iter()
                .filter(|method| item.contains_key(*method))
                .count()
            })
            .sum::<usize>();
        assert_eq!(paths.len(), 15);
        assert_eq!(operation_count, expected.len());
    }

    #[test]
    fn checked_in_openapi_excludes_the_authenticated_account_control_plane() {
        let value: Value = serde_json::from_str(OPENAPI).expect("OpenAPI must be JSON");
        let paths = value["paths"].as_object().expect("paths must be an object");

        assert!(paths.keys().all(|path| !path.starts_with("/api/v1/")));
        for account_path in ["/v1/account/me", "/v1/me", "/v1/session/bootstrap"] {
            assert!(
                !paths.contains_key(account_path),
                "machine registry OpenAPI must not absorb account route {account_path}"
            );
        }
    }

    #[test]
    fn checked_in_openapi_has_unique_operations_and_safe_mcp_metadata() {
        let value: Value = serde_json::from_str(OPENAPI).expect("OpenAPI must be JSON");
        assert_eq!(value["openapi"], "3.1.0");
        let paths = value["paths"].as_object().expect("paths must be an object");
        let mut operation_ids = std::collections::BTreeSet::new();
        let mut exposed_read_only = 0usize;
        for (path, item) in paths {
            assert!(!path.starts_with("/internal/"));
            let item = item.as_object().expect("path item must be an object");
            for method in [
                "get", "post", "put", "patch", "delete", "head", "options", "trace",
            ] {
                let Some(operation) = item.get(method) else {
                    continue;
                };
                let operation_id = operation["operationId"]
                    .as_str()
                    .expect("operationId must be a string");
                assert!(operation_ids.insert(operation_id.to_owned()));
                assert_eq!(operation["x-ore-visibility"], "public");
                assert!(matches!(
                    operation["x-ore-stability"].as_str(),
                    Some("stable" | "beta" | "experimental")
                ));
                let mutating = operation["x-ore-mcp-mutating"]
                    .as_bool()
                    .expect("mutation flag must be Boolean");
                let exposed = operation["x-ore-mcp-expose"]
                    .as_bool()
                    .expect("MCP exposure flag must be Boolean");
                assert_eq!(mutating, !matches!(method, "get" | "head" | "options"));
                assert!(!(mutating && exposed));
                if exposed && !mutating {
                    exposed_read_only += 1;
                }
            }
        }
        assert_eq!(operation_ids.len(), 16);
        assert_eq!(exposed_read_only, 11);
    }
}
