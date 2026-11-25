# Go telemetry API

This service is the Mac-side ingestion and metrics API for the DNS sinkhole. It is deliberately outside the DNS request path: if the Mac, API, database, or Wi-Fi is unavailable, the ESP32 continues resolving and blocking from its local list. Firmware sends batches through a bounded volatile queue and retries the same failed batch.

## API

All routes except liveness and readiness require `Authorization: Bearer <DEVICE_API_TOKEN>`.

| Method and path | Purpose |
| --- | --- |
| `GET /healthz` | Process liveness; does not require PostgreSQL. |
| `GET /readyz` | Readiness; confirms PostgreSQL responds. |
| `POST /api/v1/telemetry/batches` | Store an idempotent batch of DNS events and device/client counter snapshots. |
| `GET /api/v1/metrics/summary?from=<RFC3339>&to=<RFC3339>` | Return numeric summary for a time range; defaults to the previous 24 hours. |

The ingest request is capped at 1 MiB, 128 DNS events, and 32 client snapshots. Retries use the same `device_id`, `boot_id`, and `sequence`; the database unique key makes duplicate batches safe. Event indexes must be unique within a batch. API errors do not include SQL details or request contents.

DNS counters and client counts describe that batch only; query events are authoritative for dashboard time-window counts. `telemetry_dropped` and `telemetry_upload_failures` are cumulative since the current device boot.

The ESP32 currently buffers up to 128 events and uploads batches of up to 32, flushing after about one second when a batch is not full. The API persists client and DNS event rows using PostgreSQL protocol batches to reduce per-row network round trips. This absorbs short bursts; sustained event rates above upload capacity can still overflow the device's volatile queue.

### Daily blocklist review

`cmd/review-blocklist` selects distinct domains that received an upstream `NOERROR` response during a local calendar day in `Asia/Kolkata`, intersects them with HaGeZi Pro++, and excludes domains in the snapshot corresponding to the list currently installed on the ESP32. DNS names that are not valid blocklist hostnames, such as service names containing underscores, are skipped and counted in the report. It writes a candidate text file, a merged source (installed list plus candidates), and a JSON report under `outputs/candidates/` with owner-only permissions. `--refresh-reference` downloads the latest source to a temporary file and validates it before replacing the local reference. The command does not build an image or flash the device.

Run it from this directory to refresh the reference and prepare today's candidate files:

```sh
set -a
source .env.local
set +a
go run ./cmd/review-blocklist --refresh-reference
```

Use `--date YYYY-MM-DD` to review a specific local day. `../outputs/installed-pro-plus-onlydomains.txt` is the preserved baseline for the currently installed version; update that snapshot only after a new blocklist has passed validation and the ESP32 reports it ready. From the repository root, build the resulting merged source with:

```sh
python3 tools/build_blocklist.py \
  --source outputs/candidates/blocklist-source-YYYY-MM-DD.txt \
  --output outputs/candidates/pro-plus-fnv40-YYYY-MM-DD.nbl \
  --manifest outputs/candidates/pro-plus-fnv40-YYYY-MM-DD.manifest.json
```

Inspect the manifest, then use `tools/flash_blocklist.py --image ... --manifest ...` for a validated dry run. The existing flash script requires explicit confirmation before it writes. Raw blocklist delivery is separate from firmware OTA.

### Event meaning

Each DNS event represents a completed decision/outcome:

- `action=blocked`, `outcome=blocked_sent`: the block matched and the ESP32 successfully sent the synthetic DNS response.
- `action=blocked`, `outcome=blocked_send_error`: it matched, but the response could not be sent.
- `action=forwarded`, `outcome=upstream_response`: the upstream DNS response arrived and was returned to the client. `response_code=0` and `answer_count>0` counts as resolved.
- `action=forwarded`, `outcome=upstream_timeout` or `upstream_send_error`: the upstream attempt failed.
- `action=forwarded`, `outcome=queue_full`: a valid, allowed query could not be queued for upstream forwarding.
- `action=rejected`: malformed or unsupported DNS input; it is excluded from valid query totals.

For a successful block, `response_code` must be NXDOMAIN (`3`). For an upstream response, both the response code and measured latency are required. `response_code` is the DNS RCODE delivered to the client, and `answer_count` is the answer-section record count in that response.

The ESP32 emits events when it handles DNS over UDP. This is DNS telemetry, not a general Wi-Fi packet capture: it cannot see arbitrary device traffic, HTTPS URLs, or DNS requests that bypass the ESP32. The event queue is volatile and bounded, so prolonged backend outages can drop records; delivery failures and drops are counted in later batches.

### Metrics and denominators

`GET /api/v1/metrics/summary` returns counts for the selected event time range:

- `total_queries`: accepted blocked plus forwarded events; rejected inputs excluded.
- `successful_blocks`: block responses actually sent. `block_success_rate_percent` is successful blocks divided by block matches; `block_rate_percent` is successful blocks divided by accepted queries.
- `forwarded_queries`: valid, unblocked events handed to the forwarding path, including queue-full failures. This is a decision count; the Serial Monitor `forwarded` counter counts upstream packets successfully sent.
- `upstream_attempts`, `upstream_replies`, `resolved_responses`, and `upstream_failures`: actual upstream sends, responses/answers, and timeout/send-error counts. The upstream success/failure percentages use upstream attempts as the denominator; queue-full events are excluded because they never reached the resolver.
- `service_failures` and `service_failure_percent`: block-send errors, upstream timeout/send errors, queue-full errors, or client-send errors divided by accepted queries.
- `mean_upstream_latency_ms`: mean measured latency for upstream responses with a latency value.

Percentages with a zero denominator are returned as `0`.

PostgreSQL tables and the `dns_event_metrics` second-bucket view are defined by the versioned migrations in `internal/store/migrations/`. Grafana can query this PostgreSQL view directly using its built-in PostgreSQL datasource. The database stores client IPs and queried DNS names; keep it bound to the local machine/LAN and set retention before using it beyond a short home-lab trial.

## Local startup

Requirements: Go 1.25+, PostgreSQL 14+, and an HTTPS certificate trusted by the client. The API defaults to loopback. To accept telemetry from the ESP32, set `LISTEN_ADDR` to the Mac's LAN address and use a certificate whose SAN contains that exact address.

1. Create a local database and user, then set `DATABASE_URL`.
2. Set `DEVICE_API_TOKEN` to a unique random value with at least 32 characters. Do not put a real token in this example file or commit it.
3. Provide `TLS_CERT_FILE` and `TLS_KEY_FILE`. Create a local root CA at `certs/ca.crt` with its private key at `certs/ca.key`, then create a server certificate and private key at the paths configured in `.env.local`. Include the Mac's reserved LAN IPv4 address as an IP SAN in the server certificate. Copy only the CA certificate into ESP32 firmware; never copy either private key.
4. Start the server from this directory:

   ```sh
   go run ./cmd/server
   ```

The server applies the versioned schema migrations on startup. Reserve the Mac's LAN address in the router before relying on the firmware endpoint. Set `MAC_LAN_IP` in your shell to that reserved address for the examples below. Do not port-forward this API from the router.

Example summary request:

```sh
curl --cacert ./certs/ca.crt \
  -H "Authorization: Bearer $DEVICE_API_TOKEN" \
  "https://${MAC_LAN_IP}:8443/api/v1/metrics/summary"
```

An example accepted payload is in `examples/telemetry-batch.json`. Once the Mac server and certificate are set up, it can be submitted with:

```sh
curl --cacert ./certs/ca.crt \
  -H "Authorization: Bearer $DEVICE_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @./examples/telemetry-batch.json \
  "https://${MAC_LAN_IP}:8443/api/v1/telemetry/batches"
```

