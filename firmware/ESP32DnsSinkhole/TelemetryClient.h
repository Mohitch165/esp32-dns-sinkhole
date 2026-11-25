#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <atomic>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>

enum class DnsTelemetryAction : uint8_t { Blocked, Forwarded, Rejected };
enum class DnsTelemetryOutcome : uint8_t {
  BlockedSent,
  BlockedSendError,
  UpstreamResponse,
  UpstreamTimeout,
  UpstreamSendError,
  QueueFull,
  ClientSendError,
  Malformed,
  UnsupportedQuery,
};

struct DnsTelemetryEvent {
  uint32_t capturedAtMs = 0;
  ip_addr_t clientIp{};
  char domain[254] = {};
  uint16_t queryType = 1;
  DnsTelemetryAction action = DnsTelemetryAction::Rejected;
  DnsTelemetryOutcome outcome = DnsTelemetryOutcome::Malformed;
  int8_t responseCode = -1;
  uint16_t answerCount = 0;
  int32_t upstreamLatencyUs = -1;
};

class TelemetryClient {
 public:
  bool begin(SemaphoreHandle_t httpsSessionMutex);
  bool enqueue(const IPAddress& clientIp, const char* domain, uint16_t queryType,
               DnsTelemetryAction action, DnsTelemetryOutcome outcome,
               int responseCode = -1, uint16_t answerCount = 0,
               int32_t upstreamLatencyUs = -1);
  void printStats() const;

 private:
  static constexpr size_t kQueueCapacity = 128;
  static constexpr size_t kBatchCapacity = 32;
  // Flush promptly so dashboard delay is bounded by this interval plus Grafana refresh.
  static constexpr uint32_t kBatchIntervalMs = 1000;
  static constexpr uint32_t kInitialRetryIntervalMs = 1000;
  static constexpr uint32_t kMaxRetryIntervalMs = 10000;

  static void taskEntry(void* argument);
  void run();
  bool receiveEvent(DnsTelemetryEvent& event, TickType_t timeout);
  bool postBatch(String& body);
  String makeBatch(const DnsTelemetryEvent* events, size_t count,
                   time_t capturedAt, uint32_t capturedAtMs);

  // Only slot numbers enter the FreeRTOS queues. Each slot has exactly one owner.
  uint32_t* slots_ = nullptr;
  QueueHandle_t freeSlots_ = nullptr;
  QueueHandle_t queue_ = nullptr;
  SemaphoreHandle_t httpsSessionMutex_ = nullptr;
  std::atomic<uint32_t> droppedEvents_{0};
  std::atomic<uint32_t> uploadFailures_{0};
  std::atomic<uint32_t> queueHighWater_{0};
  uint64_t nextSequence_ = 0;
  char bootId_[17] = {};
};
