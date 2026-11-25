CREATE TABLE IF NOT EXISTS blocklist_update_status (
    device_id       text NOT NULL,
    request_id      text NOT NULL,
    image_sha256    text NOT NULL DEFAULT '',
    payload_crc32   text NOT NULL DEFAULT '',
    stage           text NOT NULL CHECK (stage IN (
                        'ready','downloading','writing','installed','unchanged','failed'
                    )),
    entry_count     bigint NOT NULL DEFAULT 0 CHECK (entry_count >= 0),
    message         text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, request_id),
    CHECK (length(device_id) BETWEEN 1 AND 64),
    CHECK (length(request_id) BETWEEN 1 AND 64),
    CHECK (image_sha256 = '' OR image_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (payload_crc32 = '' OR payload_crc32 ~ '^[0-9a-f]{8}$'),
    CHECK (length(message) <= 256)
);

CREATE INDEX IF NOT EXISTS blocklist_update_status_updated_idx
    ON blocklist_update_status (updated_at DESC);
