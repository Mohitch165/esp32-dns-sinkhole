# Version 1 design decisions

## Target and storage

- Target the existing classic ESP32 DevKit: 4 MiB flash, no PSRAM.
- Keep the two OTA application slots for firmware updates.
- Store one active blocklist in a dedicated raw data partition. The stock Arduino partition selection names a similarly sized area `spiffs`; this project's `partitions.csv` replaces it with a raw `blocklist` partition. Select and verify the project table before flashing.
- Keep the previous list binary on the Mac. A list update is a short maintenance window: stop DNS service, write the new list, validate it, then resume. If validation fails, report the error and upload the Mac's previous binary. This is intentionally not a two-copy on-device update.

## Blocklist format and lookup

- Source: HaGeZi Multi PRO++ wildcard domains-only feed. The source is aggressive and can cause false positives; maintain an allowlist/override path before using it for the whole home network.
- Normalize names to lowercase ASCII A-labels, remove a trailing dot, and deduplicate on the Mac.
- Hash each domain with 64-bit FNV-1a and retain the low 40 bits. Store each hash as five big-endian bytes in ascending numeric order.
- Firmware computes the query-name hash and each parent-domain suffix hash, then binary-searches the sorted table in flash. It does not keep the full domain names in RAM. Single-label suffixes are skipped when walking parents to avoid treating a TLD such as `com` as a block entry.
- The builder's `NBL1` header records format version, hash algorithm, entry count, and payload CRC32. The Mac-side manifest also records SHA-256 values for the source and generated binary.
- Hash collisions are measured by the builder. The current feed build has none. A future feed update must be rebuilt and its collision count reviewed before deployment.

## DNS datapath

1. Receive and parse each client DNS datagram without waiting for an upstream response.
2. Canonicalize the question name and check it against the blocklist using binary search.
3. For a match, return NXDOMAIN immediately and update per-client and aggregate counters.
4. For an allowed name, allocate a bounded pending-request slot, send the query to the configured upstream resolver, and return to processing other packets.
5. When the upstream reply arrives, map its transaction ID to the saved client/request, restore the client's transaction ID, and forward it. Expired requests receive SERVFAIL and increment a timeout counter.

The upstream resolver address and port are configuration, persisted in NVS. The current firmware slice changes them through a nonblocking Serial command; the planned management API can expose the same setting later. The current prototype's Cloudflare resolver is the initial default, but is not baked into the forwarding logic. DNS query handling must not make an HTTP/API call.

On the first boot, the NVS namespace must be opened read/write so it can be created before resolver defaults are read. The current sketch does this; an earlier compile opened it read-only and printed an NVS warning when the namespace did not yet exist.

## Management and updates

- Keep management telemetry and configuration outside the DNS request path. The Mac dashboard/API receives batched DNS outcomes through a bounded FreeRTOS queue and separate HTTPS worker; it does not supply a decision for each DNS query. Queue writes are nonblocking, so a full queue can drop telemetry without stalling DNS.
- The Go API and PostgreSQL schema are in `backend/`. The Mac API currently listens on its LAN address with a locally issued TLS certificate; ESP32 DNS event ingestion uses authenticated HTTPS batches with idempotency keys and a local CA trust root. The default API bind address is loopback; bind to a LAN IP only for a trusted local device.
- Store event outcomes separately from match/attempt counters: a block is successful only when the synthetic response is sent; an allowed query is resolved only when an upstream response is returned. DNS from clients to the ESP32 remains ordinary DNS/UDP in this version.
- PostgreSQL stores client IP addresses and queried DNS names. Keep the development service local, do not expose it to the public internet, and define a retention/backup policy before using the telemetry for longer periods.
- Firmware OTA V1 uses the Arduino OTA upload service on the trusted home LAN, protected by a separate password configured in the local `secrets.h`. The device pauses DNS while an image is being written to the inactive OTA app slot, then reboots. This does not write to or replace the raw blocklist partition. The OTA transport is not HTTPS; the HTTPS management API remains a separate feature.
- The first firmware containing OTA support must be installed over USB. Later firmware builds can be uploaded over Wi-Fi. An interrupted transfer should leave the current app slot active; test interrupted transfers and post-boot health recovery before relying on OTA as the only recovery path.
- Treat unlisted queried domains as candidates for review, not automatic block entries. Normal applications also query domains that are absent from a blocklist.
- Before activating a received list, validate the header, exact byte count, CRC32, and strict hash ordering. Report a clear pass/failure result to the Mac.
- Firmware currently handles DNS over UDP and HTTPS telemetry. DNS-over-TCP fallback and the Mac-to-device list uploader remain future work before wider network deployment.

## Current sizing and remaining constraint

The generated Pro++ artifact is 1,322,691 bytes. It fits in a raw `0x160000`-byte partition (1,441,792 bytes) with 119,101 bytes remaining, enough for 23,820 more hashes at the current five-byte format. This assumes raw-partition storage, not SPIFFS file capacity. The current prototype sketch uses 958,325 bytes of its 1,310,720-byte OTA app slot, leaving 352,395 bytes before adding the final DNS, API, and OTA code; measure the completed firmware before selecting the partition table.

Before adding the OTA service, the flash-reader and asynchronous DNS sketch compiled to 985,533 bytes in the 1,310,720-byte OTA slot, with 65,688 bytes of globals. Recompile the OTA-enabled sketch and measure heap use before adding the HTTPS telemetry endpoint, Mac list uploader, and DNS-over-TCP fallback.
