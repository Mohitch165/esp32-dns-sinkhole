package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"local/esp32-sinkhole/backend/internal/store"
	"local/esp32-sinkhole/backend/internal/telemetry"
)

const maxRequestBytes = 1 << 20

type Server struct {
	pool         *pgxpool.Pool
	tokenHash    [32]byte
	logger       *slog.Logger
	mux          *http.ServeMux
	blocklistDir string
}

func NewServer(pool *pgxpool.Pool, token string, logger *slog.Logger, blocklistDir string) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		pool:         pool,
		tokenHash:    sha256.Sum256([]byte(token)),
		logger:       logger,
		mux:          http.NewServeMux(),
		blocklistDir: blocklistDir,
	}
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /readyz", s.ready)
	s.mux.Handle("POST /api/v1/telemetry/batches", s.requireToken(http.HandlerFunc(s.ingestBatch)))
	s.mux.Handle("GET /api/v1/metrics/summary", s.requireToken(http.HandlerFunc(s.metricsSummary)))
	s.mux.Handle("GET /api/v1/blocklist/manifest", s.requireToken(http.HandlerFunc(s.blocklistManifest)))
	s.mux.Handle("GET /api/v1/blocklist/images/{sha256}", s.requireToken(http.HandlerFunc(s.blocklistImage)))
	s.mux.Handle("POST /api/v1/blocklist/status", s.requireToken(http.HandlerFunc(s.postBlocklistStatus)))
	s.mux.Handle("GET /api/v1/blocklist/status", s.requireToken(http.HandlerFunc(s.getBlocklistStatus)))
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		providedHash := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(header, prefix))))
		if subtle.ConstantTimeCompare(s.tokenHash[:], providedHash[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ingestBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var batch telemetry.Batch
	if err := decoder.Decode(&batch); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	if err := validateBatch(batch); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	duplicate, err := store.InsertBatch(ctx, s.pool, batch)
	if err != nil {
		s.logger.Error("telemetry batch persistence failed", "device_id", batch.DeviceID, "error", err)
		writeError(w, http.StatusInternalServerError, "persistence_failed")
		return
	}
	status := http.StatusAccepted
	if duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"accepted": !duplicate, "duplicate": duplicate})
}

func (s *Server) metricsSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	from := now.Add(-24 * time.Hour)
	to := now
	var err error
	if raw := r.URL.Query().Get("from"); raw != "" {
		from, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_from_timestamp")
			return
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		to, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_to_timestamp")
			return
		}
	}
	if !to.After(from) || to.Sub(from) > 90*24*time.Hour {
		writeError(w, http.StatusBadRequest, "invalid_time_range")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	summary, err := store.Summary(ctx, s.pool, from.UTC(), to.UTC())
	if err != nil {
		s.logger.Error("metrics query failed", "error", err)
		writeError(w, http.StatusInternalServerError, "metrics_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func validateBatch(batch telemetry.Batch) error {
	if !validIdentifier(batch.DeviceID, 64) || !validIdentifier(batch.BootID, 64) {
		return errors.New("invalid_device_or_boot_id")
	}
	if batch.Sequence < 0 || batch.CapturedAt.IsZero() {
		return errors.New("invalid_batch_metadata")
	}
	if batch.CapturedAt.After(time.Now().Add(5 * time.Minute)) {
		return errors.New("capture_time_in_future")
	}
	if len(batch.FirmwareVersion) > 64 || len(batch.Blocklist) > 128 {
		return errors.New("version_field_too_long")
	}
	if err := validateCounters(batch.Counters); err != nil {
		return err
	}
	if len(batch.Events) > telemetry.MaxBatchEvents || len(batch.Clients) > telemetry.MaxBatchClients {
		return errors.New("batch_limit_exceeded")
	}
	seenEventIndexes := make(map[int]struct{}, len(batch.Events))
	for _, event := range batch.Events {
		if event.Index < 0 {
			return errors.New("invalid_event_index")
		}
		if _, exists := seenEventIndexes[event.Index]; exists {
			return errors.New("duplicate_event_index")
		}
		seenEventIndexes[event.Index] = struct{}{}
		if event.OccurredAt.IsZero() || event.OccurredAt.After(batch.CapturedAt.Add(5*time.Minute)) {
			return errors.New("invalid_event_time")
		}
		if !validIP(event.ClientIP) {
			return errors.New("invalid_event_client_ip")
		}
		if len(event.Domain) > 253 || (event.Domain != "" && !validDomain(event.Domain)) {
			return errors.New("invalid_domain")
		}
		if event.QueryType < 1 || event.QueryType > 65535 || event.AnswerCount < 0 {
			return errors.New("invalid_dns_fields")
		}
		if event.ResponseCode != nil && (*event.ResponseCode < 0 || *event.ResponseCode > 15) {
			return errors.New("invalid_response_code")
		}
		if event.UpstreamLatencyMS != nil && *event.UpstreamLatencyMS < 0 {
			return errors.New("invalid_upstream_latency")
		}
		if event.UpstreamLatencyUS != nil && *event.UpstreamLatencyUS < 0 {
			return errors.New("invalid_upstream_latency")
		}
		if !validOutcome(event.Action, event.Outcome) {
			return errors.New("invalid_action_outcome")
		}
		if event.Outcome == "blocked_sent" && (event.ResponseCode == nil || *event.ResponseCode != 3) {
			return errors.New("blocked_response_must_be_nxdomain")
		}
		if event.Outcome == "upstream_response" && (event.ResponseCode == nil || (event.UpstreamLatencyMS == nil && event.UpstreamLatencyUS == nil)) {
			return errors.New("upstream_response_requires_rcode_and_latency")
		}
	}
	seenClients := make(map[string]struct{}, len(batch.Clients))
	for _, client := range batch.Clients {
		if !validIP(client.ClientIP) || client.Queries < 0 || client.Blocked < 0 || client.Forwarded < 0 || client.Failures < 0 {
			return errors.New("invalid_client_counters")
		}
		if _, exists := seenClients[client.ClientIP]; exists {
			return errors.New("duplicate_client_counter")
		}
		seenClients[client.ClientIP] = struct{}{}
	}
	return nil
}

func validateCounters(c telemetry.Counters) error {
	values := []int64{c.Received, c.BlockedMatches, c.BlockedResponses, c.Forwarded,
		c.UpstreamReplies, c.UpstreamTimeouts, c.QueueFull, c.Malformed, c.SendErrors,
		c.TelemetryDropped, c.TelemetryUploadFailures}
	for _, value := range values {
		if value < 0 {
			return errors.New("negative_counter")
		}
	}
	return nil
}

func validOutcome(action, outcome string) bool {
	switch action {
	case "blocked":
		return outcome == "blocked_sent" || outcome == "blocked_send_error"
	case "forwarded":
		return outcome == "upstream_response" || outcome == "upstream_timeout" ||
			outcome == "upstream_send_error" || outcome == "queue_full" || outcome == "client_send_error"
	case "rejected":
		return outcome == "malformed" || outcome == "unsupported_query" || outcome == "client_send_error"
	default:
		return false
	}
}

func validIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func validIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == ""
}

func validDomain(value string) bool {
	name := strings.TrimSuffix(strings.ToLower(value), ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, r := range label {
			// DNS labels can contain printable ASCII beyond hostname characters.
			// The firmware parser accepts these bytes, and SQL insertion is parameterized.
			if r < '!' || r > '~' {
				return false
			}
		}
	}
	return true
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("extra_json_value")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
