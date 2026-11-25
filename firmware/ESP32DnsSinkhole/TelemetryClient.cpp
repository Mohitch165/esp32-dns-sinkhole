#include "TelemetryClient.h"

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <esp_system.h>
#include <time.h>

#include <cstdio>
#include <cstring>

#include "secrets.h"
#include "telemetry_ca.h"

#ifndef TELEMETRY_API_URL
#define TELEMETRY_API_URL ""
#endif
#ifndef TELEMETRY_API_TOKEN
#define TELEMETRY_API_TOKEN ""
#endif
#ifndef BLOCKLIST_VERSION
#define BLOCKLIST_VERSION "unknown"
#endif

namespace {
constexpr char kFirmwareVersion[] = "0.2.0";
constexpr time_t kValidClockEpoch = 1700000000;

const char* actionName(DnsTelemetryAction value) {
  switch (value) {
    case DnsTelemetryAction::Blocked: return "blocked";
    case DnsTelemetryAction::Forwarded: return "forwarded";
    case DnsTelemetryAction::Rejected: return "rejected";
  }
  return "rejected";
}

const char* outcomeName(DnsTelemetryOutcome value) {
  switch (value) {
    case DnsTelemetryOutcome::BlockedSent: return "blocked_sent";
    case DnsTelemetryOutcome::BlockedSendError: return "blocked_send_error";
    case DnsTelemetryOutcome::UpstreamResponse: return "upstream_response";
    case DnsTelemetryOutcome::UpstreamTimeout: return "upstream_timeout";
    case DnsTelemetryOutcome::UpstreamSendError: return "upstream_send_error";
    case DnsTelemetryOutcome::QueueFull: return "queue_full";
    case DnsTelemetryOutcome::ClientSendError: return "client_send_error";
    case DnsTelemetryOutcome::Malformed: return "malformed";
    case DnsTelemetryOutcome::UnsupportedQuery: return "unsupported_query";
  }
  return "malformed";
}

void appendJsonString(String& out, const char* value) {
  out += '"';
  if (value != nullptr) {
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value);
         *cursor != '\0'; ++cursor) {
      const unsigned char c = *cursor;
      if (c == '"' || c == '\\') {
        out += '\\';
        out += static_cast<char>(c);
      } else if (c < 0x20) {
        char escaped[7] = {};
        std::snprintf(escaped, sizeof(escaped), "\\u%04x", c);
        out += escaped;
      } else {
        out += static_cast<char>(c);
      }
    }
  }
  out += '"';
}

String formatUtc(time_t value) {
  struct tm brokenDown = {};
  if (gmtime_r(&value, &brokenDown) == nullptr) {
    return String("1970-01-01T00:00:00Z");
  }
  char formatted[24] = {};
  strftime(formatted, sizeof(formatted), "%Y-%m-%dT%H:%M:%SZ", &brokenDown);
  return String(formatted);
}

bool isFailure(DnsTelemetryOutcome outcome) {
  return outcome != DnsTelemetryOutcome::BlockedSent &&
         outcome != DnsTelemetryOutcome::UpstreamResponse;
}
}  // namespace

bool TelemetryClient::begin() {
  if (TELEMETRY_API_URL[0] == '\0' || TELEMETRY_API_TOKEN[0] == '\0' ||
      TELEMETRY_CA_CERT_PEM[0] == '\0') {
    Serial.println("Telemetry disabled; configure TELEMETRY_API_URL, TELEMETRY_API_TOKEN, and CA certificate");
    return false;
  }

  queue_ = xQueueCreate(kQueueCapacity, sizeof(DnsTelemetryEvent));
  if (queue_ == nullptr) {
    Serial.println("Telemetry disabled; could not allocate event queue");
    return false;
  }
  std::snprintf(bootId_, sizeof(bootId_), "%08lx%08lx",
                static_cast<unsigned long>(esp_random()),
                static_cast<unsigned long>(esp_random()));

  const BaseType_t created = xTaskCreatePinnedToCore(
      taskEntry, "dns-telemetry", 16384, this, 1, nullptr, 0);
  if (created != pdPASS) {
    vQueueDelete(queue_);
    queue_ = nullptr;
    Serial.println("Telemetry disabled; could not start worker task");
    return false;
  }
  Serial.printf("Telemetry worker started for %s\n", TELEMETRY_API_URL);
  return true;
}

bool TelemetryClient::enqueue(const IPAddress& clientIp, const char* domain,
                              uint16_t queryType, DnsTelemetryAction action,
                              DnsTelemetryOutcome outcome, int responseCode,
                              uint16_t answerCount, int32_t upstreamLatencyUs) {
  if (queue_ == nullptr) {
    return false;
  }
  DnsTelemetryEvent event;
  event.capturedAtMs = millis();
  event.clientIp = clientIp;
  std::snprintf(event.domain, sizeof(event.domain), "%s", domain == nullptr ? "" : domain);
  event.queryType = queryType == 0 ? 1 : queryType;
  event.action = action;
  event.outcome = outcome;
  event.responseCode = static_cast<int8_t>(responseCode);
  event.answerCount = answerCount;
  event.upstreamLatencyUs = upstreamLatencyUs;
  if (xQueueSend(queue_, &event, 0) == pdTRUE) {
    const uint32_t waiting = static_cast<uint32_t>(uxQueueMessagesWaiting(queue_));
    uint32_t peak = queueHighWater_.load(std::memory_order_relaxed);
    while (waiting > peak &&
           !queueHighWater_.compare_exchange_weak(
               peak, waiting, std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
    return true;
  }
  droppedEvents_.fetch_add(1, std::memory_order_relaxed);
  return false;
}

void TelemetryClient::printStats() const {
  Serial.printf("Telemetry: queued=%u/128 peak=%lu dropped=%lu upload_failures=%lu\n",
                queue_ == nullptr ? 0U : static_cast<unsigned>(uxQueueMessagesWaiting(queue_)),
                static_cast<unsigned long>(queueHighWater_.load(std::memory_order_relaxed)),
                static_cast<unsigned long>(droppedEvents_.load(std::memory_order_relaxed)),
                static_cast<unsigned long>(uploadFailures_.load(std::memory_order_relaxed)));
}

void TelemetryClient::taskEntry(void* argument) {
  static_cast<TelemetryClient*>(argument)->run();
}

void TelemetryClient::run() {
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  DnsTelemetryEvent events[kBatchCapacity];
  size_t count = 0;
  uint32_t batchStartedAtMs = 0;
  uint32_t lastClockWarningMs = 0;
  while (true) {
    if (count == 0) {
      if (xQueueReceive(queue_, &events[0], pdMS_TO_TICKS(10000)) != pdTRUE) {
        continue;
      }
      count = 1;
      batchStartedAtMs = millis();
    }

    while (count < kBatchCapacity) {
      const uint32_t elapsed = static_cast<uint32_t>(millis() - batchStartedAtMs);
      if (elapsed >= kBatchIntervalMs) {
        break;
      }
      const TickType_t waitTicks = pdMS_TO_TICKS(kBatchIntervalMs - elapsed);
      if (xQueueReceive(queue_, &events[count], waitTicks) != pdTRUE) {
        break;
      }
      ++count;
    }

    const time_t now = time(nullptr);
    if (now < kValidClockEpoch) {
      const uint32_t currentMs = millis();
      if (lastClockWarningMs == 0 ||
          static_cast<uint32_t>(currentMs - lastClockWarningMs) >= 5000U) {
        Serial.println("Telemetry waiting for network time before verified HTTPS upload");
        lastClockWarningMs = currentMs;
      }
      vTaskDelay(pdMS_TO_TICKS(250));
      continue;
    }
    String body = makeBatch(events, count, now, millis());
    if (body.length() == 0) {
      uploadFailures_.fetch_add(1, std::memory_order_relaxed);
      vTaskDelay(pdMS_TO_TICKS(kInitialRetryIntervalMs));
      continue;
    }

    uint32_t retryDelayMs = kInitialRetryIntervalMs;
    while (!postBatch(body)) {
      uploadFailures_.fetch_add(1, std::memory_order_relaxed);
      Serial.printf("Telemetry upload failed; retrying same batch (failures=%lu)\n",
                    static_cast<unsigned long>(uploadFailures_.load(std::memory_order_relaxed)));
      vTaskDelay(pdMS_TO_TICKS(retryDelayMs));
      if (retryDelayMs < kMaxRetryIntervalMs) {
        retryDelayMs = retryDelayMs > kMaxRetryIntervalMs / 2
                           ? kMaxRetryIntervalMs
                           : retryDelayMs * 2;
      }
    }
    Serial.printf("Telemetry batch accepted: sequence=%llu events=%u\n",
                  static_cast<unsigned long long>(nextSequence_),
                  static_cast<unsigned>(count));
    ++nextSequence_;
    count = 0;
  }
}

bool TelemetryClient::postBatch(const String& body) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("Telemetry POST unavailable: Wi-Fi status=%d\n",
                  static_cast<int>(WiFi.status()));
    return false;
  }
  WiFiClientSecure tlsClient;
  tlsClient.setCACert(TELEMETRY_CA_CERT_PEM);
  HTTPClient http;
  http.setConnectTimeout(4000);
  http.setTimeout(5000);
  if (!http.begin(tlsClient, TELEMETRY_API_URL)) {
    Serial.println("Telemetry HTTPS begin failed");
    return false;
  }
  http.addHeader("Authorization", String("Bearer ") + TELEMETRY_API_TOKEN);
  http.addHeader("Content-Type", "application/json");
  const int status = http.POST(body);
  if (status < 200 || status >= 300) {
    String detail = status < 0 ? HTTPClient::errorToString(status) : http.getString();
    if (detail.length() > 160) detail.remove(160);
    Serial.printf("Telemetry POST failed: status=%d detail=%s free_heap=%u min_free_heap=%u\n",
                  status, detail.c_str(), static_cast<unsigned>(ESP.getFreeHeap()),
                  static_cast<unsigned>(ESP.getMinFreeHeap()));
  }
  http.end();
  return status >= 200 && status < 300;
}

String TelemetryClient::makeBatch(const DnsTelemetryEvent* events, size_t count,
                                  time_t capturedAt, uint32_t capturedAtMs) {
  if (events == nullptr || count == 0 || count > kBatchCapacity) {
    return String();
  }

  struct ClientAggregate {
    IPAddress ip;
    uint16_t queries = 0;
    uint16_t blocked = 0;
    uint16_t forwarded = 0;
    uint16_t failures = 0;
  } clients[kBatchCapacity];
  size_t clientCount = 0;
  uint16_t received = 0;
  uint16_t blockedMatches = 0;
  uint16_t blockedResponses = 0;
  uint16_t forwarded = 0;
  uint16_t upstreamReplies = 0;
  uint16_t upstreamTimeouts = 0;
  uint16_t queueFull = 0;
  uint16_t malformed = 0;
  uint16_t sendErrors = 0;

  for (size_t i = 0; i < count; ++i) {
    const DnsTelemetryEvent& event = events[i];
    if (event.action != DnsTelemetryAction::Rejected) {
      ++received;
    }
    if (event.action == DnsTelemetryAction::Blocked) {
      ++blockedMatches;
    } else if (event.action == DnsTelemetryAction::Forwarded) {
      ++forwarded;
    }
    switch (event.outcome) {
      case DnsTelemetryOutcome::BlockedSent: ++blockedResponses; break;
      case DnsTelemetryOutcome::UpstreamResponse: ++upstreamReplies; break;
      case DnsTelemetryOutcome::UpstreamTimeout: ++upstreamTimeouts; break;
      case DnsTelemetryOutcome::QueueFull: ++queueFull; break;
      case DnsTelemetryOutcome::Malformed: ++malformed; break;
      case DnsTelemetryOutcome::BlockedSendError:
      case DnsTelemetryOutcome::UpstreamSendError:
      case DnsTelemetryOutcome::ClientSendError: ++sendErrors; break;
      case DnsTelemetryOutcome::UnsupportedQuery: break;
    }

    size_t clientIndex = 0;
    while (clientIndex < clientCount && clients[clientIndex].ip != event.clientIp) {
      ++clientIndex;
    }
    if (clientIndex == clientCount && clientCount < kBatchCapacity) {
      clients[clientCount].ip = event.clientIp;
      ++clientCount;
    }
    ClientAggregate& client = clients[clientIndex];
    if (event.action != DnsTelemetryAction::Rejected) {
      ++client.queries;
      if (event.action == DnsTelemetryAction::Blocked) ++client.blocked;
      if (event.action == DnsTelemetryAction::Forwarded) ++client.forwarded;
    }
    if (isFailure(event.outcome)) ++client.failures;
  }

  String body;
  body.reserve(16000);
  body += F("{\"device_id\":");
  appendJsonString(body, WiFi.macAddress().c_str());
  body += F(",\"boot_id\":");
  appendJsonString(body, bootId_);
  body += F(",\"sequence\":");
  body += String(static_cast<unsigned long>(nextSequence_));
  body += F(",\"captured_at\":");
  appendJsonString(body, formatUtc(capturedAt).c_str());
  body += F(",\"firmware_version\":");
  appendJsonString(body, kFirmwareVersion);
  body += F(",\"blocklist_version\":");
  appendJsonString(body, BLOCKLIST_VERSION);
  body += F(",\"counters\":{\"received\":");
  body += String(received);
  body += F(",\"blocked_matches\":");
  body += String(blockedMatches);
  body += F(",\"blocked_responses\":");
  body += String(blockedResponses);
  body += F(",\"forwarded\":");
  body += String(forwarded);
  body += F(",\"upstream_replies\":");
  body += String(upstreamReplies);
  body += F(",\"upstream_timeouts\":");
  body += String(upstreamTimeouts);
  body += F(",\"queue_full\":");
  body += String(queueFull);
  body += F(",\"malformed\":");
  body += String(malformed);
  body += F(",\"send_errors\":");
  body += String(sendErrors);
  body += F(",\"telemetry_dropped\":");
  body += String(static_cast<unsigned long>(
      droppedEvents_.load(std::memory_order_relaxed)));
  body += F(",\"telemetry_upload_failures\":");
  body += String(static_cast<unsigned long>(
      uploadFailures_.load(std::memory_order_relaxed)));
  body += F("},\"clients\":[");
  for (size_t i = 0; i < clientCount; ++i) {
    if (i != 0) body += ',';
    body += F("{\"client_ip\":");
    appendJsonString(body, clients[i].ip.toString().c_str());
    body += F(",\"queries\":");
    body += String(clients[i].queries);
    body += F(",\"blocked\":");
    body += String(clients[i].blocked);
    body += F(",\"forwarded\":");
    body += String(clients[i].forwarded);
    body += F(",\"failures\":");
    body += String(clients[i].failures);
    body += '}';
  }
  body += F("],\"events\":[");
  for (size_t i = 0; i < count; ++i) {
    const DnsTelemetryEvent& event = events[i];
    if (i != 0) body += ',';
    const uint32_t ageMs = static_cast<uint32_t>(capturedAtMs - event.capturedAtMs);
    body += F("{\"index\":");
    body += String(i);
    body += F(",\"occurred_at\":");
    const time_t occurredAt = capturedAt - static_cast<time_t>(ageMs / 1000U);
    appendJsonString(body, formatUtc(occurredAt).c_str());
    body += F(",\"client_ip\":");
    appendJsonString(body, event.clientIp.toString().c_str());
    body += F(",\"domain\":");
    appendJsonString(body, event.domain);
    body += F(",\"query_type\":");
    body += String(event.queryType);
    body += F(",\"action\":");
    appendJsonString(body, actionName(event.action));
    body += F(",\"outcome\":");
    appendJsonString(body, outcomeName(event.outcome));
    if (event.responseCode >= 0) {
      body += F(",\"response_code\":");
      body += String(event.responseCode);
    }
    body += F(",\"answer_count\":");
    body += String(event.answerCount);
    if (event.upstreamLatencyUs >= 0) {
      body += F(",\"upstream_latency_us\":");
      body += String(event.upstreamLatencyUs);
      body += F(",\"upstream_latency_ms\":");
      body += String((event.upstreamLatencyUs + 500) / 1000);
    }
    body += '}';
  }
  body += F("]}");
  return body;
}
