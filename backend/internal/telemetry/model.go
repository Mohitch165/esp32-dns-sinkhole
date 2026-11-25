package telemetry

import "time"

const (
	MaxBatchEvents  = 128
	MaxBatchClients = 32
)

type Batch struct {
	DeviceID        string           `json:"device_id"`
	BootID          string           `json:"boot_id"`
	Sequence        int64            `json:"sequence"`
	CapturedAt      time.Time        `json:"captured_at"`
	FirmwareVersion string           `json:"firmware_version"`
	Blocklist       string           `json:"blocklist_version"`
	Counters        Counters         `json:"counters"`
	Clients         []ClientCounters `json:"clients"`
	Events          []DNSEvent       `json:"events"`
}

type Counters struct {
	Received                int64 `json:"received"`
	BlockedMatches          int64 `json:"blocked_matches"`
	BlockedResponses        int64 `json:"blocked_responses"`
	Forwarded               int64 `json:"forwarded"`
	UpstreamReplies         int64 `json:"upstream_replies"`
	UpstreamTimeouts        int64 `json:"upstream_timeouts"`
	QueueFull               int64 `json:"queue_full"`
	Malformed               int64 `json:"malformed"`
	SendErrors              int64 `json:"send_errors"`
	TelemetryDropped        int64 `json:"telemetry_dropped"`
	TelemetryUploadFailures int64 `json:"telemetry_upload_failures"`
}

type ClientCounters struct {
	ClientIP  string `json:"client_ip"`
	Queries   int64  `json:"queries"`
	Blocked   int64  `json:"blocked"`
	Forwarded int64  `json:"forwarded"`
	Failures  int64  `json:"failures"`
}

type DNSEvent struct {
	Index             int       `json:"index"`
	OccurredAt        time.Time `json:"occurred_at"`
	ClientIP          string    `json:"client_ip"`
	Domain            string    `json:"domain"`
	QueryType         int       `json:"query_type"`
	Action            string    `json:"action"`
	Outcome           string    `json:"outcome"`
	ResponseCode      *int      `json:"response_code,omitempty"`
	AnswerCount       int       `json:"answer_count"`
	UpstreamLatencyMS *int      `json:"upstream_latency_ms,omitempty"`
	UpstreamLatencyUS *int      `json:"upstream_latency_us,omitempty"`
}

type MetricsSummary struct {
	From                    time.Time `json:"from"`
	To                      time.Time `json:"to"`
	TotalQueries            int64     `json:"total_queries"`
	BlockMatches            int64     `json:"block_matches"`
	SuccessfulBlocks        int64     `json:"successful_blocks"`
	BlockSuccessRatePercent float64   `json:"block_success_rate_percent"`
	BlockRatePercent        float64   `json:"block_rate_percent"`
	ForwardedQueries        int64     `json:"forwarded_queries"`
	UpstreamAttempts        int64     `json:"upstream_attempts"`
	UpstreamReplies         int64     `json:"upstream_replies"`
	ResolvedResponses       int64     `json:"resolved_responses"`
	UpstreamFailures        int64     `json:"upstream_failures"`
	ServiceFailures         int64     `json:"service_failures"`
	UpstreamSuccessPercent  float64   `json:"upstream_success_percent"`
	UpstreamFailurePercent  float64   `json:"upstream_failure_percent"`
	ServiceFailurePercent   float64   `json:"service_failure_percent"`
	MeanUpstreamLatencyMS   float64   `json:"mean_upstream_latency_ms"`
}

type BlocklistUpdateStatus struct {
	DeviceID     string    `json:"device_id"`
	RequestID    string    `json:"request_id"`
	ImageSHA256  string    `json:"image_sha256"`
	PayloadCRC32 string    `json:"payload_crc32"`
	Stage        string    `json:"stage"`
	EntryCount   int64     `json:"entry_count"`
	Message      string    `json:"message"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}
