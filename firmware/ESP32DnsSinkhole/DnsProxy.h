#pragma once

#include <Arduino.h>
#include <WiFiUdp.h>

#include "BlocklistStore.h"
#include "TelemetryClient.h"

struct DnsProxyStats {
  uint64_t received = 0;
  uint64_t blocked = 0;
  uint64_t forwarded = 0;
  uint64_t upstreamReplies = 0;
  uint64_t upstreamTimeouts = 0;
  uint64_t queueFull = 0;
  uint64_t malformed = 0;
  uint64_t sendErrors = 0;
};

class DnsProxy {
 public:
  bool begin(BlocklistStore& blocklist, IPAddress upstreamIp, uint16_t upstreamPort);
  void setTelemetry(TelemetryClient* telemetry) { telemetry_ = telemetry; }
  void stop();
  void setUpstream(IPAddress upstreamIp, uint16_t upstreamPort);
  void loop();
  void printStats() const;

 private:
  static constexpr size_t kMaxDnsPacketBytes = 4096;
  static constexpr size_t kMaxQuestionBytes = 272;
  static constexpr size_t kPendingCapacity = 32;
  static constexpr size_t kClientStatsCapacity = 16;
  static constexpr uint16_t kUpstreamLocalPort = 53053;
  static constexpr uint32_t kUpstreamTimeoutMs = 2500;

  struct PendingRequest {
    bool active = false;
    uint16_t upstreamId = 0;
    uint16_t originalId = 0;
    uint16_t clientPort = 0;
    IPAddress clientIp;
    uint32_t deadline = 0;
    uint32_t startedAtUs = 0;
    uint16_t questionLength = 0;
    uint16_t queryType = 1;
    char domain[254] = {};
    uint8_t question[kMaxQuestionBytes] = {};
  };

  struct ClientCounters {
    bool used = false;
    IPAddress ip;
    uint32_t lastSeen = 0;
    uint32_t queries = 0;
    uint32_t blocked = 0;
    uint32_t forwarded = 0;
    uint32_t failures = 0;
  };

  void processClientPackets(uint8_t budget);
  void processUpstreamPackets(uint8_t budget);
  void processTimeouts();
  bool parseQuestion(const uint8_t* packet, size_t length, char* name,
                     size_t nameCapacity, size_t& questionEnd) const;
  bool forwardQuery(const IPAddress& clientIp, uint16_t clientPort,
                    uint8_t* packet, size_t packetLength, size_t questionEnd,
                    const char* domain, uint16_t queryType);
  bool sendRcode(const IPAddress& clientIp, uint16_t clientPort,
                 const uint8_t* query, size_t queryLength,
                 size_t questionEnd, uint8_t rcode);
  bool sendPacket(const IPAddress& clientIp, uint16_t clientPort,
                  const uint8_t* data, size_t length);
  PendingRequest* allocatePending(uint16_t& upstreamId);
  PendingRequest* findPending(uint16_t upstreamId);
  ClientCounters& clientCounters(const IPAddress& clientIp);
  void printClient(const ClientCounters& counters) const;
  void record(const IPAddress& clientIp, const char* domain, uint16_t queryType,
              DnsTelemetryAction action, DnsTelemetryOutcome outcome,
              int responseCode = -1, uint16_t answerCount = 0,
              int32_t upstreamLatencyUs = -1);

  WiFiUDP clientSocket_;
  WiFiUDP upstreamSocket_;
  BlocklistStore* blocklist_ = nullptr;
  TelemetryClient* telemetry_ = nullptr;
  IPAddress upstreamIp_ = IPAddress(1, 1, 1, 1);
  uint16_t upstreamPort_ = 53;
  uint16_t nextUpstreamId_ = 1;
  bool started_ = false;
  uint32_t lastStatsPrint_ = 0;
  PendingRequest pending_[kPendingCapacity];
  ClientCounters clients_[kClientStatsCapacity];
  DnsProxyStats stats_;
  uint8_t packetBuffer_[kMaxDnsPacketBytes];
};
