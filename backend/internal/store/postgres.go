package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"local/esp32-sinkhole/backend/internal/telemetry"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create schema migration table: %w", err)
	}
	migrations, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("list schema migrations: %w", err)
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Name() < migrations[j].Name() })
	seenVersions := make(map[int]struct{}, len(migrations))
	for _, migration := range migrations {
		name := migration.Name()
		if migration.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		version, parseErr := strconv.Atoi(prefix)
		if !ok || parseErr != nil || version < 1 {
			return fmt.Errorf("invalid migration filename %q: expected a numeric prefix", name)
		}
		if _, exists := seenVersions[version]; exists {
			return fmt.Errorf("duplicate migration version %d", version)
		}
		seenVersions[version] = struct{}{}
		var applied bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}
		schema, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if err := executeMigration(ctx, tx, string(schema)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

func executeMigration(ctx context.Context, tx pgx.Tx, schema string) error {
	for _, statement := range strings.Split(schema, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := tx.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func InsertBatch(ctx context.Context, pool *pgxpool.Pool, batch telemetry.Batch) (bool, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin telemetry transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var batchID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO telemetry_batches
			(device_id, boot_id, batch_sequence, captured_at, firmware_version, blocklist_version,
			 received, blocked_matches, blocked_responses, forwarded, upstream_replies,
			 upstream_timeouts, queue_full, malformed, send_errors, telemetry_dropped,
			 telemetry_upload_failures)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (device_id, boot_id, batch_sequence) DO NOTHING
		RETURNING id`,
		batch.DeviceID, batch.BootID, batch.Sequence, batch.CapturedAt,
		batch.FirmwareVersion, batch.Blocklist,
		batch.Counters.Received, batch.Counters.BlockedMatches, batch.Counters.BlockedResponses,
		batch.Counters.Forwarded, batch.Counters.UpstreamReplies, batch.Counters.UpstreamTimeouts,
		batch.Counters.QueueFull, batch.Counters.Malformed, batch.Counters.SendErrors,
		batch.Counters.TelemetryDropped, batch.Counters.TelemetryUploadFailures,
	).Scan(&batchID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return false, fmt.Errorf("commit duplicate telemetry batch: %w", err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("insert telemetry batch: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO devices (device_id, firmware_version, blocklist_version, last_seen_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (device_id) DO UPDATE SET
			firmware_version = EXCLUDED.firmware_version,
			blocklist_version = EXCLUDED.blocklist_version,
			last_seen_at = EXCLUDED.last_seen_at`,
		batch.DeviceID, batch.FirmwareVersion, batch.Blocklist, batch.CapturedAt,
	)
	if err != nil {
		return false, fmt.Errorf("upsert device: %w", err)
	}

	clientBatch := &pgx.Batch{}
	for _, client := range batch.Clients {
		clientBatch.Queue(`
			INSERT INTO client_counter_snapshots
				(batch_id, device_id, client_ip, queries, blocked, forwarded, failures)
			VALUES ($1,$2,$3::inet,$4,$5,$6,$7)`,
			batchID, batch.DeviceID, client.ClientIP, client.Queries,
			client.Blocked, client.Forwarded, client.Failures,
		)
	}
	if err := executeInsertBatch(ctx, tx, clientBatch, "insert client counter snapshot"); err != nil {
		return false, err
	}

	eventBatch := &pgx.Batch{}
	for _, event := range batch.Events {
		var clientIP any
		if event.ClientIP != "" {
			clientIP = event.ClientIP
		}
		var domain any
		if event.Domain != "" {
			domain = strings.ToLower(strings.TrimSuffix(event.Domain, "."))
		}
		eventBatch.Queue(`
			INSERT INTO dns_events
				(batch_id, device_id, boot_id, batch_sequence, event_index, occurred_at,
				 client_ip, domain, query_type, action, outcome, response_code,
				 answer_count, upstream_latency_ms, upstream_latency_us)
			VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10,$11,$12,$13,$14,$15)`,
			batchID, batch.DeviceID, batch.BootID, batch.Sequence, event.Index, event.OccurredAt,
			clientIP, domain, event.QueryType, event.Action, event.Outcome,
			event.ResponseCode, event.AnswerCount, event.UpstreamLatencyMS, event.UpstreamLatencyUS,
		)
	}
	if err := executeInsertBatch(ctx, tx, eventBatch, "insert DNS event"); err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit telemetry transaction: %w", err)
	}
	return false, nil
}

func UpsertBlocklistUpdateStatus(ctx context.Context, pool *pgxpool.Pool, status telemetry.BlocklistUpdateStatus) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO blocklist_update_status
			(device_id, request_id, image_sha256, payload_crc32, stage, entry_count, message, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (device_id, request_id) DO UPDATE SET
			image_sha256 = EXCLUDED.image_sha256,
			payload_crc32 = EXCLUDED.payload_crc32,
			stage = EXCLUDED.stage,
			entry_count = EXCLUDED.entry_count,
			message = EXCLUDED.message,
			updated_at = now()`,
		status.DeviceID, status.RequestID, status.ImageSHA256, status.PayloadCRC32,
		status.Stage, status.EntryCount, status.Message,
	)
	if err != nil {
		return fmt.Errorf("upsert blocklist update status: %w", err)
	}
	return nil
}

func GetBlocklistUpdateStatus(ctx context.Context, pool *pgxpool.Pool, deviceID, requestID string) (telemetry.BlocklistUpdateStatus, error) {
	var status telemetry.BlocklistUpdateStatus
	err := pool.QueryRow(ctx, `
		SELECT device_id, request_id, image_sha256, payload_crc32, stage, entry_count, message, updated_at
		FROM blocklist_update_status
		WHERE device_id=$1 AND request_id=$2`, deviceID, requestID,
	).Scan(&status.DeviceID, &status.RequestID, &status.ImageSHA256, &status.PayloadCRC32, &status.Stage,
		&status.EntryCount, &status.Message, &status.UpdatedAt)
	if err != nil {
		return telemetry.BlocklistUpdateStatus{}, err
	}
	return status, nil
}

func executeInsertBatch(ctx context.Context, tx pgx.Tx, batch *pgx.Batch, label string) error {
	if batch.Len() == 0 {
		return nil
	}
	results := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("%s %d: %w", label, i, err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("finish %s batch: %w", label, err)
	}
	return nil
}

func Summary(ctx context.Context, pool *pgxpool.Pool, from, to time.Time) (telemetry.MetricsSummary, error) {
	var summary telemetry.MetricsSummary
	summary.From, summary.To = from, to
	err := pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE action IN ('blocked','forwarded')),
			COUNT(*) FILTER (WHERE action = 'blocked'),
			COUNT(*) FILTER (WHERE action = 'blocked' AND outcome = 'blocked_sent'),
			COUNT(*) FILTER (WHERE action = 'forwarded'),
			COUNT(*) FILTER (WHERE action = 'forwarded' AND outcome IN ('upstream_response','upstream_timeout','upstream_send_error')),
			COUNT(*) FILTER (WHERE action = 'forwarded' AND outcome = 'upstream_response'),
			COUNT(*) FILTER (WHERE outcome = 'upstream_response' AND response_code = 0 AND answer_count > 0),
			COUNT(*) FILTER (WHERE outcome IN ('upstream_timeout','upstream_send_error')),
			COUNT(*) FILTER (WHERE action IN ('blocked','forwarded') AND outcome IN ('blocked_send_error','upstream_timeout','upstream_send_error','queue_full','client_send_error')),
			COALESCE(AVG(COALESCE(upstream_latency_us, upstream_latency_ms * 1000)::double precision / 1000.0) FILTER (WHERE outcome = 'upstream_response'), 0)
		FROM dns_events
		WHERE occurred_at >= $1 AND occurred_at < $2`, from, to).Scan(
		&summary.TotalQueries, &summary.BlockMatches, &summary.SuccessfulBlocks,
		&summary.ForwardedQueries, &summary.UpstreamAttempts, &summary.UpstreamReplies, &summary.ResolvedResponses,
		&summary.UpstreamFailures, &summary.ServiceFailures, &summary.MeanUpstreamLatencyMS,
	)
	if err != nil {
		return telemetry.MetricsSummary{}, fmt.Errorf("query metrics summary: %w", err)
	}
	summary.BlockSuccessRatePercent = percent(summary.SuccessfulBlocks, summary.BlockMatches)
	summary.BlockRatePercent = percent(summary.SuccessfulBlocks, summary.TotalQueries)
	summary.UpstreamSuccessPercent = percent(summary.UpstreamReplies, summary.UpstreamAttempts)
	summary.UpstreamFailurePercent = percent(summary.UpstreamFailures, summary.UpstreamAttempts)
	summary.ServiceFailurePercent = percent(summary.ServiceFailures, summary.TotalQueries)
	return summary, nil
}

func percent(numerator, denominator int64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) * 100 / float64(denominator)
}
