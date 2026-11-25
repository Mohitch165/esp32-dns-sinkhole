# Design decisions

This document describes the current trial implementation, including firmware `0.2.1` and the Mac-hosted OTA workflow.

## Execution boundaries

The ESP32 handles DNS decisions from its flash blocklist and configured upstream resolver. DNS processing never waits on a Mac API decision. Completed outcomes enter a nonblocking telemetry queue. The Go API persists them in PostgreSQL and Grafana reads database views.

| Execution context | Responsibility |
| --- | --- |
| ESP32 main loop | Parse DNS, match flash hashes, forward queries, handle replies and timeouts |
| Telemetry worker | Batch completed outcomes and retry authenticated HTTPS uploads |
| Blocklist OTA worker | Poll the manifest, validate downloads, install and report list status |
| Mac updater | Review queries, merge source, validate images, retain backups and verify/rollback OTA |
| macOS login agent | Check hourly and run when the 48-hour interval has elapsed |

A shared recursive HTTPS mutex prevents telemetry and blocklist workers from opening concurrent TLS sessions. Each transfer closes before status posts open another connection. The manifest poll interval is 30 seconds.

## Flash layout

The classic ESP32 trial board has 4 MiB flash and no detected PSRAM. The custom partition table reserves two application slots and one raw blocklist partition.

| Partition | Offset | Size |
| --- | --- | ---: |
| `nvs` | `0x9000` | `0x5000` |
| `otadata` | `0xe000` | `0x2000` |
| `app0` | `0x10000` | `0x140000` |
| `app1` | `0x150000` | `0x140000` |
| `blocklist` | `0x290000` | `0x160000` |
| `coredump` | `0x3f0000` | `0x10000` |

The trial ESP32-D0WD-V3 uses DIO at 40 MHz. An earlier 80 MHz build failed during flash initialization. Firmware OTA writes the inactive application slot and reboots. Blocklist OTA writes the dedicated data partition and resumes DNS after validation.

## Blocklist representation

Domains are normalized to lowercase ASCII A-labels, deduplicated on the Mac, and hashed with FNV-1a. The low 40 bits are stored as five big-endian bytes per entry, in strict ascending order. The device computes the queried domain and parent suffix hashes, then binary-searches the flash list. Single-label suffixes are excluded when walking parents.

The `NBL1` image begins with a 16-byte header containing the format, hash algorithm, entry count, and payload CRC32. The manifest records source and image SHA-256 values. The included image contains 264,535 hashes with zero measured source collisions and occupies 1,322,691 bytes. Its raw partition has 119,101 bytes of remaining capacity, sufficient for 23,820 additional hashes.

The compact representation bounds flash usage. A collision-free source build does not mathematically eliminate collisions with every possible future query.

## Asynchronous DNS forwarding

The proxy parses a question and decides whether to block or forward it. Blocked requests receive NXDOMAIN. Allowed requests use one of 32 pending slots. The proxy sends upstream without waiting, maps response transaction IDs back to the original clients, and returns to packet processing. The timeout is 2,500 ms. Expired requests receive SERVFAIL.

Resolver address and port are configurable through Serial Monitor and persisted in NVS. Opening the NVS namespace read/write allows first-boot creation. The trial default is `1.1.1.1:53`. Current client transport is DNS over UDP on the IPv4 LAN.

## Telemetry memory and delivery

The queue holds 128 events, and the worker builds batches of up to 32 with an approximately one-second flush interval. Firmware `0.2.1` stores event slots using aligned 32-bit internal memory accesses. FreeRTOS queues transfer slot indices. The worker copies each event into ordinary byte-accessible memory before serializing it. Slot ownership transfers through the queues and returns to the free pool after consumption.

Batch JSON reserves capacity based on its event count and escaped domain lengths. The HTTP client receives the existing payload buffer, avoiding an extra `String` copy. TLS operations are serialized, and diagnostic failures include free internal memory and the largest allocatable block.

The worker preserves device, boot, and sequence identity across retries. PostgreSQL uniqueness constraints deduplicate repeated batches and events. Event timestamps derive from capture age and synchronized network time. Telemetry waits for network time before certificate-verified HTTPS uploads.

The queue is volatile. Bursts or backend outages can drop records while DNS continues operating. Dropped-event and upload-failure counters are cumulative for a device boot and appear in subsequent batches.

## Database and metrics

`devices`, `telemetry_batches`, `dns_events`, and `client_counter_snapshots` are linked by declared foreign keys. `blocklist_update_status` uses a separate composite device/request key. Four views serve Grafana, including second-bucket event metrics and individual upstream latency measurements.

DNS decision and outcome are separate fields. A block match becomes a successful block only if the synthetic response is sent. An upstream reply may carry a non-success DNS response code. A resolved response requires `NOERROR` and at least one answer. Latency uses microseconds where available, with legacy millisecond values converted for old records.

Dashboard time-window counts come from recorded query events. Serial counters may cover another boot/window, include events lost from telemetry, or use different definitions of forwarding. See the denominator definitions in the backend guide.

## Automated review and blocklist OTA

The Mac refreshes the local HaGeZi Multi PRO++ reference and compares successful forwarded `NOERROR` responses from the last 48 hours. Parent-domain coverage excludes names covered by the installed source. Unmatchable DNS names are reported. The tool retains installed domains when merging candidates.

Before publishing, it validates ordering, collisions, CRC32, SHA-256, exact image length, and partition capacity. It compares the ESP32's current entry count and CRC with the Mac's active snapshot, then saves a rollback backup. With no candidates, it records a successful review and skips flashing.

The device fetches an authenticated manifest and immutable image over certificate-verified HTTPS. It validates the header and size, pauses DNS, writes the partition, validates the streamed hash/CRC/order, and reopens the flash reader to verify the resulting list. The Mac checks a previously allowed candidate and an existing blocked domain before promoting its active snapshot.

Failures publish the saved image as an OTA rollback and record the reason. There is one active list on the device. An interrupted write can leave it without a valid list, requiring Mac/network availability to restore the backup. Firmware passes DNS through when no valid list is available. This recovery design has a maintenance window.

The login agent checks hourly, runs when 48 hours have elapsed since the last successful review/update, and retries failures after six hours. It requires an awake, logged-in Mac, a reachable ESP32, and running PostgreSQL. The updater can start the API. A file lock prevents duplicate concurrent runs. Pending work resumes on a later invocation.

## Observed validation and remaining work

The home-network trial demonstrated blocking, forwarding, dashboard ingestion, firmware OTA, current-list reporting, and successful reference reviews with no new candidates. After the telemetry memory fix, a 40-second recovery check recorded 12 batches and 33 queries with zero reported drops or upload failures.

Candidate-changing blocklist deployment, interrupted-write recovery, and induced-failure rollback still require a controlled hardware trial. Sustained router-load validation and DNS-over-TCP fallback also remain open. Recorded home-network results should be read with their timestamps and telemetry coverage, rather than as production guarantees.

## Local data and trust

HTTPS telemetry uses a local CA and bearer token. Firmware Arduino OTA uses a separate password on the trusted LAN. Wi-Fi settings, tokens, private keys, raw review reports, backups, and runtime logs are ignored by Git. PostgreSQL stores queried names and client addresses, so retention and sharing need explicit attention. The database visuals are sanitized snapshots and can be regenerated from the exporter.
