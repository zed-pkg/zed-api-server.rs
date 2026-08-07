# Artifact storage metrics

The registry exposes process metrics at `GET /metrics` in Prometheus text
format. Artifact-storage telemetry is intentionally low-cardinality: the only
label is the configured backend (`memory`, `local`, or `r2`). Package names,
organizations, versions, and object keys are never labels.

## Metrics

| Metric | Type | Meaning |
| --- | --- | --- |
| `zed_registry_artifact_storage_backend_info{backend}` | gauge | Always `1` for the active backend. |
| `zed_registry_artifact_storage_objects{backend}` | gauge | Current content-addressed object count when the backend exposes an in-process count. |
| `zed_registry_artifact_storage_bytes{backend}` | gauge | Current artifact bytes held by the backend when available. |
| `zed_registry_artifact_storage_capacity_bytes{backend}` | gauge | Configured byte capacity for a bounded backend. |
| `zed_registry_artifact_storage_utilization_ratio{backend}` | gauge | `used_bytes / capacity_bytes` for a bounded backend. |

The process-memory backend exports every metric above. Local filesystem and R2
export `backend_info` only: recursively scanning a filesystem or object store on
every scrape would make `/metrics` expensive and operationally surprising.
Provider-native storage metrics should cover those backends.

The gauges are sampled synchronously from the active storage object when the
metrics snapshot is rendered. No polling loop, timer, background task, or
per-artifact metric series is created.

## Suggested alerts for the memory backend

A warning can fire when utilization remains above 80% for 15 minutes:

```promql
zed_registry_artifact_storage_utilization_ratio{backend="memory"} > 0.80
```

A critical alert can fire when utilization remains above 90% for 5 minutes:

```promql
zed_registry_artifact_storage_utilization_ratio{backend="memory"} > 0.90
```

Object growth without equivalent byte growth can be inspected with:

```promql
rate(zed_registry_artifact_storage_objects{backend="memory"}[15m])
```

Prometheus gauges do not themselves preserve a historical counter across a pod
restart; use changes in the sampled series as an operational signal rather than
as an accounting ledger.

## Volatility and reset contract

Process-memory artifacts disappear when the API process exits. Registry
metadata stored in Postgres does not disappear automatically, so a restart can
leave metadata that references artifacts no longer present in memory. The
memory backend is therefore suitable for bounded tests and disposable
certification stacks, not durable production publication.

Reset the API process-memory store and its disposable metadata database as one
unit. Do not expose a memory-backed registry as a multi-replica service: each
pod would otherwise hold a different artifact set and report independent
occupancy gauges.
