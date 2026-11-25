CREATE TABLE IF NOT EXISTS devices (
    device_id           text PRIMARY KEY,
    firmware_version    text NOT NULL DEFAULT '',
    blocklist_version   text NOT NULL DEFAULT '',
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL
);

-- DNS counters describe the events in each submitted batch. The telemetry
-- delivery counters added by migration 002 are cumulative since boot. Use
-- dns_events for authoritative time-window activity counts.
CREATE TABLE IF NOT EXISTS telemetry_batches (
    id                  bigserial PRIMARY KEY,
    device_id           text NOT NULL REFERENCES devices(device_id) DEFERRABLE INITIALLY DEFERRED,
    boot_id             text NOT NULL,
    batch_sequence      bigint NOT NULL CHECK (batch_sequence >= 0),
    captured_at         timestamptz NOT NULL,
    firmware_version    text NOT NULL DEFAULT '',
    blocklist_version   text NOT NULL DEFAULT '',
    received            bigint NOT NULL CHECK (received >= 0),
    blocked_matches     bigint NOT NULL CHECK (blocked_matches >= 0),
    blocked_responses   bigint NOT NULL CHECK (blocked_responses >= 0),
    forwarded           bigint NOT NULL CHECK (forwarded >= 0),
    upstream_replies    bigint NOT NULL CHECK (upstream_replies >= 0),
    upstream_timeouts   bigint NOT NULL CHECK (upstream_timeouts >= 0),
    queue_full          bigint NOT NULL CHECK (queue_full >= 0),
    malformed           bigint NOT NULL CHECK (malformed >= 0),
    send_errors         bigint NOT NULL CHECK (send_errors >= 0),
    UNIQUE (device_id, boot_id, batch_sequence)
);

CREATE TABLE IF NOT EXISTS client_counter_snapshots (
    id                  bigserial PRIMARY KEY,
    batch_id            bigint NOT NULL REFERENCES telemetry_batches(id) ON DELETE CASCADE,
    device_id           text NOT NULL REFERENCES devices(device_id),
    client_ip           inet NOT NULL,
    queries             bigint NOT NULL CHECK (queries >= 0),
    blocked             bigint NOT NULL CHECK (blocked >= 0),
    forwarded           bigint NOT NULL CHECK (forwarded >= 0),
    failures            bigint NOT NULL CHECK (failures >= 0),
    UNIQUE (batch_id, client_ip)
);

CREATE TABLE IF NOT EXISTS dns_events (
    id                      bigserial PRIMARY KEY,
    batch_id                bigint NOT NULL REFERENCES telemetry_batches(id) ON DELETE CASCADE,
    device_id               text NOT NULL REFERENCES devices(device_id),
    boot_id                 text NOT NULL,
    batch_sequence          bigint NOT NULL,
    event_index             integer NOT NULL CHECK (event_index >= 0),
    occurred_at             timestamptz NOT NULL,
    client_ip               inet NOT NULL,
    domain                  text NOT NULL DEFAULT '',
    query_type              integer NOT NULL CHECK (query_type BETWEEN 1 AND 65535),
    action                  text NOT NULL CHECK (action IN ('blocked','forwarded','rejected')),
    outcome                 text NOT NULL CHECK (outcome IN (
                                'blocked_sent','blocked_send_error','upstream_response',
                                'upstream_timeout','upstream_send_error','queue_full',
                                'client_send_error','malformed','unsupported_query'
                            )),
    response_code           smallint CHECK (response_code BETWEEN 0 AND 15),
    answer_count            integer NOT NULL DEFAULT 0 CHECK (answer_count >= 0),
    upstream_latency_ms     integer CHECK (upstream_latency_ms >= 0),
    UNIQUE (device_id, boot_id, batch_sequence, event_index),
    CHECK (
        (action = 'blocked' AND outcome IN ('blocked_sent','blocked_send_error')) OR
        (action = 'forwarded' AND outcome IN ('upstream_response','upstream_timeout',
            'upstream_send_error','queue_full','client_send_error')) OR
        (action = 'rejected' AND outcome IN ('malformed','unsupported_query','client_send_error'))
    )
);

CREATE INDEX IF NOT EXISTS dns_events_occurred_at_idx
    ON dns_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS dns_events_device_time_idx
    ON dns_events (device_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS dns_events_client_time_idx
    ON dns_events (client_ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS dns_events_domain_time_idx
    ON dns_events (domain, occurred_at DESC) WHERE domain <> '';
CREATE INDEX IF NOT EXISTS dns_events_outcome_time_idx
    ON dns_events (outcome, occurred_at DESC);
CREATE INDEX IF NOT EXISTS telemetry_batches_device_time_idx
    ON telemetry_batches (device_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS client_snapshots_ip_batch_idx
    ON client_counter_snapshots (client_ip, batch_id DESC);

-- Grafana can query this view directly through its PostgreSQL datasource.
CREATE OR REPLACE VIEW dns_event_metrics AS
WITH counts AS (
    SELECT
        date_trunc('minute', occurred_at) AS time,
        device_id,
        count(*) FILTER (WHERE action IN ('blocked','forwarded')) AS total_queries,
        count(*) FILTER (WHERE action = 'blocked') AS block_matches,
        count(*) FILTER (WHERE action = 'blocked' AND outcome = 'blocked_sent') AS successful_blocks,
        count(*) FILTER (WHERE action = 'forwarded') AS forwarded_queries,
        count(*) FILTER (WHERE action = 'forwarded' AND outcome IN ('upstream_response','upstream_timeout','upstream_send_error')) AS upstream_attempts,
        count(*) FILTER (WHERE action = 'forwarded' AND outcome = 'upstream_response') AS upstream_replies,
        count(*) FILTER (WHERE outcome = 'upstream_response' AND response_code = 0 AND answer_count > 0) AS resolved_responses,
        count(*) FILTER (WHERE outcome IN ('upstream_timeout','upstream_send_error')) AS upstream_failures,
        count(*) FILTER (WHERE action IN ('blocked','forwarded') AND outcome IN (
            'blocked_send_error','upstream_timeout','upstream_send_error','queue_full','client_send_error')) AS service_failures,
        avg(upstream_latency_ms) FILTER (WHERE outcome = 'upstream_response') AS mean_upstream_latency_ms
    FROM dns_events
    GROUP BY date_trunc('minute', occurred_at), device_id
)
SELECT
    counts.*,
    COALESCE(100.0 * successful_blocks / NULLIF(block_matches, 0), 0) AS block_success_rate_percent,
    COALESCE(100.0 * successful_blocks / NULLIF(total_queries, 0), 0) AS block_rate_percent,
    COALESCE(100.0 * upstream_replies / NULLIF(upstream_attempts, 0), 0) AS upstream_success_percent,
    COALESCE(100.0 * upstream_failures / NULLIF(upstream_attempts, 0), 0) AS upstream_failure_percent,
    COALESCE(100.0 * service_failures / NULLIF(total_queries, 0), 0) AS service_failure_percent
FROM counts;
