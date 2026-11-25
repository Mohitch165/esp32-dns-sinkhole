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
| `GET /api/v1/blocklist/manifest` | Return the authenticated OTA image manifest, or `available:false`. |
| `GET /api/v1/blocklist/images/<sha256>` | Stream the immutable blocklist image after server-side SHA, CRC, count, and ordering checks. |
| `POST /api/v1/blocklist/status` | Store ESP32 download, flash, install, rollback, and current-list status. |
| `GET /api/v1/blocklist/status?device_id=...&request_id=...` | Read an update status for the Mac updater. |

The ingest request is capped at 1 MiB, 128 DNS events, and 32 client snapshots. Retries use the same `device_id`, `boot_id`, and `sequence`; the database unique key makes duplicate batches safe. Event indexes must be unique within a batch. API errors do not include SQL details or request contents.

DNS counters and client counts describe that batch only; query events are authoritative for dashboard time-window counts. `telemetry_dropped` and `telemetry_upload_failures` are cumulative since the current device boot.

The ESP32 currently buffers up to 128 events and uploads batches of up to 32, flushing after about one second when a batch is not full. The API persists client and DNS event rows using PostgreSQL protocol batches to reduce per-row network round trips. This absorbs short bursts; sustained event rates above upload capacity can still overflow the device's volatile queue.

### Automated 48-hour blocklist update

`cmd/review-blocklist` supports both local calendar dates and rolling `--lookback 48h` windows. It selects successful forwarded DNS events whose upstream response code is `NOERROR`, compares names to the refreshed local HaGeZi Pro++ domains-only feed using parent-domain coverage, and excludes names already covered by the installed snapshot. The JSON report includes one previously resolved DNS probe for each candidate so the updater can confirm the candidate was allowed before deployment and blocked afterwards. Unmatchable DNS names are listed in the report rather than silently discarded.

The full host workflow is in `tools/update_blocklist.py`. It runs a review and merge, verifies the merged source retained every installed domain, builds the image, checks partition capacity, sorted hashes, collisions, CRC32 and SHA-256, verifies the Mac backup against the ESP32's reported count/CRC, and then publishes an immutable image plus manifest. The ESP32 downloads it over certificate-verified HTTPS, pauses DNS during the raw data-partition write, validates readback, and reports each stage. The host then checks that DNS blocks a candidate and still blocks a known old entry. Any failed transfer, install, or smoke check publishes the backed-up image as a new OTA rollback and logs the failure under ignored `outputs/logs/`.

Install the macOS `launchd` job from the repository root after deploying the receiver firmware once using the Arduino IDE network port:

```sh
python3 tools/install_blocklist_automation.py --install
```

The scheduler runs at login and checks hourly. It performs a run when 48 hours have elapsed since the last successful review/update and retries failures after six hours. If the Mac is asleep or off, the next login/wake catches up. The updater starts the Go API from the root checkout if its health check is unavailable; PostgreSQL still needs to be installed and running. To review/build without touching the device, run `python3 tools/update_blocklist.py --dry-run`. To run a full cycle immediately, run `python3 tools/update_blocklist.py --force`. To remove the schedule, run `python3 tools/install_blocklist_automation.py --uninstall`.

Generated DNS reports, active snapshots, backups, images, and logs are ignored by Git and use owner-only permissions. The automation fails closed if the receiver firmware has not reported a valid current list or the local backup differs from the ESP32. The first firmware containing the receiver must be sent once through the existing Arduino network OTA service; subsequent blocklist refreshes and rollback are fully automatic HTTPS data-partition updates and do not use USB.

For a one-off report without OTA, run the review command from this directory:

```sh
set -a
source .env.local
set +a
go run ./cmd/review-blocklist --refresh-reference --lookback 48h
```

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

