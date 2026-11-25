BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH inventory AS (
  SELECT c.relname AS name, pg_total_relation_size(c.oid) AS bytes
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r'
), samples AS (
  SELECT id, occurred_at, client_ip, query_type, action, outcome, response_code,
         CASE WHEN action = 'blocked' OR domain IN ('example.com','example.org')
           THEN domain ELSE '[domain hidden]' END AS domain,
         round(COALESCE(upstream_latency_us, upstream_latency_ms * 1000)::numeric / 1000, 2) AS latency_ms
  FROM dns_events ORDER BY id DESC LIMIT 8
)
SELECT json_build_object(
  'snapshot_at', now(),
  'database_version', split_part(version(), ' ', 2),
  'storage_bytes', (SELECT sum(bytes) FROM inventory),
  'tables', (SELECT json_agg(json_build_object('name', name, 'bytes', bytes)) FROM inventory),
  'counts', json_build_object(
    'devices', (SELECT count(*) FROM devices),
    'telemetry_batches', (SELECT count(*) FROM telemetry_batches),
    'dns_events', (SELECT count(*) FROM dns_events),
    'client_counter_snapshots', (SELECT count(*) FROM client_counter_snapshots),
    'blocklist_update_status', (SELECT count(*) FROM blocklist_update_status)),
  'stats', (SELECT json_build_object(
    'blocked', count(*) FILTER (WHERE action = 'blocked'),
    'forwarded', count(*) FILTER (WHERE action = 'forwarded'),
    'rejected', count(*) FILTER (WHERE action = 'rejected'),
    'clients', count(DISTINCT client_ip),
    'domains', count(DISTINCT domain),
    'from', min(occurred_at), 'to', max(occurred_at)) FROM dns_events),
  'samples', (SELECT json_agg(json_build_object(
    'id', s.id, 'occurred_at', s.occurred_at,
    'client', 'Client ' || lpad((SELECT count(DISTINCT e.client_ip) FROM dns_events e WHERE e.client_ip <= s.client_ip)::text, 2, '0'),
    'query_type', s.query_type, 'action', s.action, 'outcome', s.outcome,
    'response_code', s.response_code, 'domain', s.domain, 'latency_ms', s.latency_ms
  ) ORDER BY s.id DESC) FROM samples s),
  'foreign_keys', (SELECT json_agg(json_build_object(
    'table', conrelid::regclass::text, 'definition', pg_get_constraintdef(oid)))
    FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace),
  'views', (SELECT json_agg(table_name ORDER BY table_name) FROM information_schema.views WHERE table_schema = 'public'),
  'status', (SELECT json_build_object('stage', stage, 'entries', entry_count, 'updated_at', updated_at)
    FROM blocklist_update_status WHERE request_id = 'current' ORDER BY updated_at DESC LIMIT 1)
);
COMMIT;
