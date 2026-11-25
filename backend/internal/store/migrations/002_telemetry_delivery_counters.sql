ALTER TABLE telemetry_batches
    ADD COLUMN telemetry_dropped bigint NOT NULL DEFAULT 0
        CHECK (telemetry_dropped >= 0),
    ADD COLUMN telemetry_upload_failures bigint NOT NULL DEFAULT 0
        CHECK (telemetry_upload_failures >= 0);
