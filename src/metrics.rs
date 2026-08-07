use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use parking_lot::Mutex;

use crate::storage::{Storage, StorageStats};

const LATENCY_BUCKETS_MS: &[u64] = &[1, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000];

#[derive(Debug, Default)]
struct RouteMetrics {
    requests_total: u64,
    errors_total: u64,
    latency_buckets: Vec<u64>,
    latency_sum_ms: u128,
}

impl RouteMetrics {
    fn new() -> Self {
        Self {
            latency_buckets: vec![0; LATENCY_BUCKETS_MS.len()],
            ..Self::default()
        }
    }

    fn observe(&mut self, status: u16, latency: Duration) {
        self.requests_total = self.requests_total.saturating_add(1);
        if status >= 400 {
            self.errors_total = self.errors_total.saturating_add(1);
        }
        let millis = latency.as_millis();
        self.latency_sum_ms = self.latency_sum_ms.saturating_add(millis);
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if millis <= u128::from(*bound) {
                self.latency_buckets[index] = self.latency_buckets[index].saturating_add(1);
            }
        }
    }
}

#[derive(Default)]
struct MetricsInner {
    routes: Mutex<BTreeMap<String, RouteMetrics>>,
    storage: RwLock<Option<Arc<dyn Storage>>>,
}

#[derive(Clone, Default)]
pub struct AppMetrics {
    inner: Arc<MetricsInner>,
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub routes: BTreeMap<String, RouteMetricsSnapshot>,
    pub storage: Option<StorageStats>,
}

#[derive(Debug, Clone, Default)]
pub struct RouteMetricsSnapshot {
    pub requests_total: u64,
    pub errors_total: u64,
    pub latency_buckets: Vec<u64>,
    pub latency_sum_ms: u128,
}

impl AppMetrics {
    pub fn attach_storage(&self, storage: Arc<dyn Storage>) {
        let mut attached = match self.inner.storage.write() {
            Ok(attached) => attached,
            Err(poisoned) => poisoned.into_inner(),
        };
        *attached = Some(storage);
    }

    pub fn observe(&self, route: &str, status: u16, latency: Duration) {
        let mut routes = self.inner.routes.lock();
        routes
            .entry(route.to_string())
            .or_insert_with(RouteMetrics::new)
            .observe(status, latency);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let routes = self
            .inner
            .routes
            .lock()
            .iter()
            .map(|(route, metrics)| {
                (
                    route.clone(),
                    RouteMetricsSnapshot {
                        requests_total: metrics.requests_total,
                        errors_total: metrics.errors_total,
                        latency_buckets: metrics.latency_buckets.clone(),
                        latency_sum_ms: metrics.latency_sum_ms,
                    },
                )
            })
            .collect();
        let storage = {
            let attached = match self.inner.storage.read() {
                Ok(attached) => attached,
                Err(poisoned) => poisoned.into_inner(),
            };
            attached.as_ref().cloned()
        }
        .map(|storage| storage.stats());
        MetricsSnapshot { routes, storage }
    }
}

pub fn render_prometheus(snapshot: &MetricsSnapshot) -> String {
    let mut output = String::from(
        "# HELP zed_registry_http_requests_total Total HTTP requests handled by route.\n\
# TYPE zed_registry_http_requests_total counter\n\
# HELP zed_registry_http_errors_total Total HTTP responses with status >= 400 by route.\n\
# TYPE zed_registry_http_errors_total counter\n\
# HELP zed_registry_http_request_duration_ms HTTP request latency by route in milliseconds.\n\
# TYPE zed_registry_http_request_duration_ms histogram\n\
# HELP zed_registry_artifact_storage_backend_info Active artifact storage backend.\n\
# TYPE zed_registry_artifact_storage_backend_info gauge\n\
# HELP zed_registry_artifact_storage_objects Current number of content-addressed artifact objects held by the backend when available.\n\
# TYPE zed_registry_artifact_storage_objects gauge\n\
# HELP zed_registry_artifact_storage_bytes Current artifact bytes held by the backend when available.\n\
# TYPE zed_registry_artifact_storage_bytes gauge\n\
# HELP zed_registry_artifact_storage_capacity_bytes Configured artifact byte capacity when bounded and available.\n\
# TYPE zed_registry_artifact_storage_capacity_bytes gauge\n\
# HELP zed_registry_artifact_storage_utilization_ratio Artifact byte utilization divided by configured capacity when bounded and available.\n\
# TYPE zed_registry_artifact_storage_utilization_ratio gauge\n",
    );
    for (route, metrics) in &snapshot.routes {
        let route = escape_label(route);
        let _ = writeln!(
            output,
            "zed_registry_http_requests_total{{route=\"{route}\"}} {}",
            metrics.requests_total
        );
        let _ = writeln!(
            output,
            "zed_registry_http_errors_total{{route=\"{route}\"}} {}",
            metrics.errors_total
        );
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            let count = metrics.latency_buckets.get(index).copied().unwrap_or(0);
            let _ = writeln!(
                output,
                "zed_registry_http_request_duration_ms_bucket{{route=\"{route}\",le=\"{bound}\"}} {count}"
            );
        }
        let _ = writeln!(
            output,
            "zed_registry_http_request_duration_ms_bucket{{route=\"{route}\",le=\"+Inf\"}} {}",
            metrics.requests_total
        );
        let _ = writeln!(
            output,
            "zed_registry_http_request_duration_ms_sum{{route=\"{route}\"}} {}",
            metrics.latency_sum_ms
        );
        let _ = writeln!(
            output,
            "zed_registry_http_request_duration_ms_count{{route=\"{route}\"}} {}",
            metrics.requests_total
        );
    }

    if let Some(storage) = snapshot.storage {
        let backend = escape_label(storage.backend);
        let _ = writeln!(
            output,
            "zed_registry_artifact_storage_backend_info{{backend=\"{backend}\"}} 1"
        );
        if let Some(object_count) = storage.object_count {
            let _ = writeln!(
                output,
                "zed_registry_artifact_storage_objects{{backend=\"{backend}\"}} {object_count}"
            );
        }
        if let Some(used_bytes) = storage.used_bytes {
            let _ = writeln!(
                output,
                "zed_registry_artifact_storage_bytes{{backend=\"{backend}\"}} {used_bytes}"
            );
        }
        if let Some(capacity_bytes) = storage.capacity_bytes {
            let _ = writeln!(
                output,
                "zed_registry_artifact_storage_capacity_bytes{{backend=\"{backend}\"}} {capacity_bytes}"
            );
        }
        if let Some(utilization) = storage.utilization_ratio() {
            let _ = writeln!(
                output,
                "zed_registry_artifact_storage_utilization_ratio{{backend=\"{backend}\"}} {utilization}"
            );
        }
    }

    output
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;

    use crate::storage::{MemoryStorage, Storage, StorageStats};

    use super::{AppMetrics, MetricsSnapshot, render_prometheus};

    #[test]
    fn counts_errors_and_latency_buckets() {
        let metrics = AppMetrics::default();
        metrics.observe("GET /healthz", 200, Duration::from_millis(4));
        metrics.observe("GET /healthz", 503, Duration::from_millis(60));
        let snapshot = metrics.snapshot();
        let route = snapshot.routes.get("GET /healthz").unwrap();
        assert_eq!(route.requests_total, 2);
        assert_eq!(route.errors_total, 1);
        assert_eq!(route.latency_sum_ms, 64);
        assert_eq!(route.latency_buckets[0], 0);
        assert_eq!(route.latency_buckets[1], 1);
        assert_eq!(route.latency_buckets[5], 2);
    }

    #[tokio::test]
    async fn attached_memory_storage_is_sampled_on_each_snapshot() {
        let metrics = AppMetrics::default();
        let storage = Arc::new(MemoryStorage::new(100).unwrap());
        metrics.attach_storage(storage.clone());
        storage
            .put("artifacts/ab/cd", Bytes::from_static(b"payload"))
            .await
            .unwrap();

        assert_eq!(
            metrics.snapshot().storage,
            Some(StorageStats {
                backend: "memory",
                object_count: Some(1),
                used_bytes: Some(7),
                capacity_bytes: Some(100),
            })
        );
    }

    #[test]
    fn prometheus_output_contains_storage_gauges_without_package_labels() {
        let snapshot = MetricsSnapshot {
            routes: Default::default(),
            storage: Some(StorageStats {
                backend: "memory",
                object_count: Some(2),
                used_bytes: Some(10),
                capacity_bytes: Some(20),
            }),
        };
        let rendered = render_prometheus(&snapshot);
        assert!(rendered.contains(
            "zed_registry_artifact_storage_backend_info{backend=\"memory\"} 1"
        ));
        assert!(rendered.contains(
            "zed_registry_artifact_storage_objects{backend=\"memory\"} 2"
        ));
        assert!(rendered.contains(
            "zed_registry_artifact_storage_bytes{backend=\"memory\"} 10"
        ));
        assert!(rendered.contains(
            "zed_registry_artifact_storage_capacity_bytes{backend=\"memory\"} 20"
        ));
        assert!(rendered.contains(
            "zed_registry_artifact_storage_utilization_ratio{backend=\"memory\"} 0.5"
        ));
        assert!(!rendered.contains("org="));
        assert!(!rendered.contains("package="));
    }

    #[test]
    fn prometheus_output_escapes_route_labels() {
        let metrics = AppMetrics::default();
        metrics.observe("GET /\"bad\"", 200, Duration::from_millis(1));
        let rendered = render_prometheus(&metrics.snapshot());
        assert!(rendered.contains("route=\"GET /\\\"bad\\\"\""));
    }
}
