# backend

Docker Compose stack for the demo (DESIGN.md §11, "demo choice" column). The sensor ships sanitized CloudEvents to it
over **TLS 1.3 + mTLS only**. TLS 1.2 handshakes are refused on every sensor-facing port (4318, 8443, 13133).

```sh
backend/certs/gen_certs.sh ep-demo      # local CA, server cert, endpoint client identity (out/, gitignored)
docker compose -f backend/docker-compose.yml up -d --build
scripts/e2e_backend.sh                  # sensor -> backend end to end: crash, hang, offline drill
```

| Service | Role | Port (localhost) |
| --- | --- | --- |
| `otel-collector` | OTLP/HTTP ingress, **TLS 1.3 + mTLS** (client cert must chain to our CA) → Prometheus + Loki | 4318; health 13133 (TLS 1.3 + mTLS) |
| `ingress` (nginx) | **TLS 1.3-only mTLS** termination for the control plane; forwards the verified cert CN/O | 8443 |
| `control-plane` | FastAPI: incident index (SQLite, dedupe by event id), sanitized bundle store | internal 8000 |
| `object-store` | S3-compatible bundle storage (SeaweedFS) | internal |
| `prometheus` | metrics via native OTLP receiver | 9090 |
| `loki` | logs/events via native OTLP; `service_instance_id` label, `event_type` structured metadata | 3100 |
| `grafana` | dashboard "Ieso - endpoint timeline": endpoint telemetry, incidents, investigation reports + evidence chain (anonymous admin, demo only) | 3000 |

Control plane API (all calls through the mTLS ingress):

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/events` | Incident-class CloudEvents; `INSERT OR IGNORE` by id; `source` must match the certificate CN |
| `PUT /v1/bundles/{incident_id}` | Sanitized bundle; `X-Bundle-SHA256` verified; stored under `bundles/<tenant>/<endpoint>/` |
| `GET /v1/incidents?endpoint=&kind=&signature=` | Incident index (FR-17) |
| `GET /v1/incidents/{id}` / `.../bundle` | Incident details / bundle download |
| `GET /v1/stats` | Accepted / duplicate counters (at-least-once delivery check) |

Notes:
- **Transport scope:** the TLS 1.3 + mTLS rule covers every hop between endpoint and backend. Grafana, Prometheus
  and Loki are operator UIs bound to localhost, and the services talk to each other on the internal Docker network;
  both are plain HTTP in this demo.
- **Object store:** DESIGN.md first named MinIO, but MinIO no longer publishes container images. SeaweedFS speaks the
  same S3 API, so production S3 is a configuration change.
- **Identity:** tenant and endpoint come from the client certificate, never from the payload. The collector doesn't
  yet check `service.instance.id` against the certificate; at scale that check lives in the ingress tier.
- **Tests:** `cd backend/control-plane && pip install -r requirements-dev.txt && pytest -q`
