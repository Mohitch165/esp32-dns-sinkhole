ALTER TABLE dns_events
    ADD COLUMN upstream_latency_us integer CHECK (upstream_latency_us >= 0);

CREATE OR REPLACE VIEW dns_event_metrics AS
WITH counts AS (
    SELECT
        date_trunc('second', occurred_at) AS time,
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
        avg(COALESCE(upstream_latency_us, upstream_latency_ms * 1000)::numeric / 1000.0)
            FILTER (WHERE outcome = 'upstream_response') AS mean_upstream_latency_ms
    FROM dns_events
    GROUP BY date_trunc('second', occurred_at), device_id
)
SELECT
    counts.*,
    COALESCE(100.0 * successful_blocks / NULLIF(block_matches, 0), 0) AS block_success_rate_percent,
    COALESCE(100.0 * successful_blocks / NULLIF(total_queries, 0), 0) AS block_rate_percent,
    COALESCE(100.0 * upstream_replies / NULLIF(upstream_attempts, 0), 0) AS upstream_success_percent,
    COALESCE(100.0 * upstream_failures / NULLIF(upstream_attempts, 0), 0) AS upstream_failure_percent,
    COALESCE(100.0 * service_failures / NULLIF(total_queries, 0), 0) AS service_failure_percent
FROM counts;

CREATE OR REPLACE VIEW dns_event_latency AS
SELECT
    occurred_at AS time,
    device_id,
    COALESCE(upstream_latency_us, upstream_latency_ms * 1000)::double precision / 1000.0 AS upstream_latency_ms
FROM dns_events
WHERE outcome = 'upstream_response'
  AND COALESCE(upstream_latency_us, upstream_latency_ms * 1000) IS NOT NULL;

GRANT SELECT ON dns_event_latency TO grafana_reader;

CREATE OR REPLACE VIEW dns_client_activity AS
SELECT occurred_at AS time, device_id, client_ip::text AS client_ip, action, outcome
FROM dns_events;

CREATE OR REPLACE VIEW dns_domain_activity AS
SELECT occurred_at AS time, device_id, domain, action, outcome
FROM dns_events
WHERE domain <> '';

GRANT SELECT ON dns_client_activity, dns_domain_activity TO grafana_reader;
