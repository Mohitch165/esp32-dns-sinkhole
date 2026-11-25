#include "DnsProxy.h"

#include <cstdio>
#include <cstring>

namespace {
constexpr uint16_t kDnsPort = 53;
constexpr uint8_t kRcodeFormErr = 1;
constexpr uint8_t kRcodeServFail = 2;
constexpr uint8_t kRcodeNotImp = 4;

uint16_t readU16Be(const uint8_t* bytes) {
  return (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1];
}

void writeU16Be(uint8_t* bytes, uint16_t value) {
  bytes[0] = static_cast<uint8_t>(value >> 8);
  bytes[1] = static_cast<uint8_t>(value & 0xFFU);
}
}  // namespace

bool DnsProxy::begin(BlocklistStore& blocklist, IPAddress upstreamIp,
                     uint16_t upstreamPort) {
  stop();
  blocklist_ = &blocklist;
  setUpstream(upstreamIp, upstreamPort);
  if (!clientSocket_.begin(kDnsPort)) {
    return false;
  }
  if (!upstreamSocket_.begin(kUpstreamLocalPort)) {
    clientSocket_.stop();
    return false;
  }
  started_ = true;
  lastStatsPrint_ = millis();
  return true;
}

void DnsProxy::stop() {
  clientSocket_.stop();
  upstreamSocket_.stop();
  started_ = false;
  for (PendingRequest& request : pending_) {
    request.active = false;
  }
}

void DnsProxy::setUpstream(IPAddress upstreamIp, uint16_t upstreamPort) {
  if (upstreamPort == 0) {
    return;
  }
  if ((upstreamIp != upstreamIp_ || upstreamPort != upstreamPort_) && started_) {
    for (PendingRequest& request : pending_) {
      if (!request.active) {
        continue;
      }
      ++clientCounters(request.clientIp).failures;
      sendRcode(request.clientIp, request.clientPort, request.question,
                request.questionLength, request.questionLength, kRcodeServFail);
      request.active = false;
    }
  }
  upstreamIp_ = upstreamIp;
  upstreamPort_ = upstreamPort;
}

void DnsProxy::loop() {
  if (!started_) {
    return;
  }
  processClientPackets(8);
  processUpstreamPackets(8);
  processTimeouts();

  const uint32_t now = millis();
  if (static_cast<uint32_t>(now - lastStatsPrint_) >= 30000U) {
    printStats();
    lastStatsPrint_ = now;
  }
}

void DnsProxy::processClientPackets(uint8_t budget) {
  while (budget-- > 0) {
    const int packetSize = clientSocket_.parsePacket();
    if (packetSize <= 0) {
      return;
    }
    const IPAddress clientIp = clientSocket_.remoteIP();
    const uint16_t clientPort = clientSocket_.remotePort();
    const size_t readLimit = static_cast<size_t>(packetSize) < sizeof(packetBuffer_)
                                 ? static_cast<size_t>(packetSize)
                                 : sizeof(packetBuffer_);
    const int bytesRead = clientSocket_.read(packetBuffer_, readLimit);
    while (clientSocket_.available() > 0) {
      clientSocket_.read();
    }
    if (bytesRead < 2) {
      ++stats_.malformed;
      record(clientIp, "", 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::Malformed);
      continue;
    }
    if (static_cast<size_t>(packetSize) > sizeof(packetBuffer_) || bytesRead != packetSize) {
      ++stats_.malformed;
      ++clientCounters(clientIp).failures;
      record(clientIp, "", 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::Malformed);
      sendRcode(clientIp, clientPort, packetBuffer_, static_cast<size_t>(bytesRead), 0,
                kRcodeServFail);
      continue;
    }
    if (bytesRead < 12) {
      ++stats_.malformed;
      ++clientCounters(clientIp).failures;
      record(clientIp, "", 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::Malformed);
      sendRcode(clientIp, clientPort, packetBuffer_, static_cast<size_t>(bytesRead), 0,
                kRcodeFormErr);
      continue;
    }

    const uint16_t flags = readU16Be(packetBuffer_ + 2);
    if ((flags & 0x8000U) != 0) {
      // A DNS response sent to the listening port is not a client query.
      continue;
    }
    if ((flags & 0x7800U) != 0) {
      ++stats_.malformed;
      ++clientCounters(clientIp).failures;
      record(clientIp, "", 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::UnsupportedQuery);
      sendRcode(clientIp, clientPort, packetBuffer_, static_cast<size_t>(bytesRead), 0,
                kRcodeNotImp);
      continue;
    }
    if (readU16Be(packetBuffer_ + 4) != 1) {
      ++stats_.malformed;
      ++clientCounters(clientIp).failures;
      record(clientIp, "", 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::UnsupportedQuery);
      sendRcode(clientIp, clientPort, packetBuffer_, static_cast<size_t>(bytesRead), 0,
                kRcodeFormErr);
      continue;
    }

    char qname[254] = {};
    size_t questionEnd = 0;
    if (!parseQuestion(packetBuffer_, static_cast<size_t>(bytesRead), qname,
                       sizeof(qname), questionEnd)) {
      ++stats_.malformed;
      ++clientCounters(clientIp).failures;
      record(clientIp, "", 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::Malformed);
      sendRcode(clientIp, clientPort, packetBuffer_, static_cast<size_t>(bytesRead), 0,
                kRcodeFormErr);
      continue;
    }

    const uint16_t queryType = readU16Be(packetBuffer_ + questionEnd - 4);
    if (queryType == 0) {
      ++stats_.malformed;
      ++clientCounters(clientIp).failures;
      record(clientIp, qname, 1, DnsTelemetryAction::Rejected,
             DnsTelemetryOutcome::UnsupportedQuery);
      sendRcode(clientIp, clientPort, packetBuffer_, static_cast<size_t>(bytesRead),
                questionEnd, kRcodeNotImp);
      continue;
    }

    ++stats_.received;
    ClientCounters& perClient = clientCounters(clientIp);
    ++perClient.queries;
    if (blocklist_ != nullptr && blocklist_->containsDomainOrSubdomain(qname)) {
      ++stats_.blocked;
      ++perClient.blocked;
      const bool sent = sendRcode(clientIp, clientPort, packetBuffer_,
                                  static_cast<size_t>(bytesRead), questionEnd, 3);
      if (sent) {
        record(clientIp, qname, queryType, DnsTelemetryAction::Blocked,
               DnsTelemetryOutcome::BlockedSent, 3);
      } else {
        ++perClient.failures;
        record(clientIp, qname, queryType, DnsTelemetryAction::Blocked,
               DnsTelemetryOutcome::BlockedSendError);
      }
      Serial.printf("Blocked %s from %s\n", qname, clientIp.toString().c_str());
      continue;
    }

    if (forwardQuery(clientIp, clientPort, packetBuffer_,
                     static_cast<size_t>(bytesRead), questionEnd, qname, queryType)) {
      ++stats_.forwarded;
      ++perClient.forwarded;
      Serial.printf("Forwarded %s from %s\n", qname, clientIp.toString().c_str());
    }
  }
}

void DnsProxy::processUpstreamPackets(uint8_t budget) {
  while (budget-- > 0) {
    const int packetSize = upstreamSocket_.parsePacket();
    if (packetSize <= 0) {
      return;
    }
    const IPAddress sourceIp = upstreamSocket_.remoteIP();
    const uint16_t sourcePort = upstreamSocket_.remotePort();
    const size_t readLimit = static_cast<size_t>(packetSize) < sizeof(packetBuffer_)
                                 ? static_cast<size_t>(packetSize)
                                 : sizeof(packetBuffer_);
    const int bytesRead = upstreamSocket_.read(packetBuffer_, readLimit);
    while (upstreamSocket_.available() > 0) {
      upstreamSocket_.read();
    }
    if (static_cast<size_t>(packetSize) > sizeof(packetBuffer_) || bytesRead < 12 ||
        bytesRead != packetSize || sourceIp != upstreamIp_ || sourcePort != upstreamPort_) {
      ++stats_.sendErrors;
      continue;
    }
    if ((readU16Be(packetBuffer_ + 2) & 0x8000U) == 0) {
      ++stats_.sendErrors;
      continue;
    }

    PendingRequest* request = findPending(readU16Be(packetBuffer_));
    if (request == nullptr) {
      continue;
    }
    writeU16Be(packetBuffer_, request->originalId);
    const uint8_t responseCode = static_cast<uint8_t>(readU16Be(packetBuffer_ + 2) & 0x000FU);
    const uint16_t answerCount = readU16Be(packetBuffer_ + 6);
    const uint32_t latencyUs = static_cast<uint32_t>(micros() - request->startedAtUs);
    if (sendPacket(request->clientIp, request->clientPort, packetBuffer_,
                   static_cast<size_t>(bytesRead))) {
      ++stats_.upstreamReplies;
      record(request->clientIp, request->domain, request->queryType,
             DnsTelemetryAction::Forwarded, DnsTelemetryOutcome::UpstreamResponse,
             responseCode, answerCount, static_cast<int32_t>(latencyUs));
    } else {
      ++stats_.sendErrors;
      ++clientCounters(request->clientIp).failures;
      record(request->clientIp, request->domain, request->queryType,
             DnsTelemetryAction::Forwarded, DnsTelemetryOutcome::ClientSendError);
    }
    request->active = false;
  }
}

void DnsProxy::processTimeouts() {
  const uint32_t now = millis();
  for (PendingRequest& request : pending_) {
    if (!request.active || static_cast<int32_t>(now - request.deadline) < 0) {
      continue;
    }
    ++stats_.upstreamTimeouts;
    ++clientCounters(request.clientIp).failures;
    const bool sent = sendRcode(request.clientIp, request.clientPort, request.question,
                                request.questionLength, request.questionLength,
                                kRcodeServFail);
    const uint32_t latencyUs = static_cast<uint32_t>(micros() - request.startedAtUs);
    record(request.clientIp, request.domain, request.queryType,
           DnsTelemetryAction::Forwarded,
           sent ? DnsTelemetryOutcome::UpstreamTimeout
                : DnsTelemetryOutcome::ClientSendError,
           sent ? kRcodeServFail : -1, 0, static_cast<int32_t>(latencyUs));
    request.active = false;
  }
}

bool DnsProxy::parseQuestion(const uint8_t* packet, size_t length, char* name,
                             size_t nameCapacity, size_t& questionEnd) const {
  if (packet == nullptr || name == nullptr || nameCapacity == 0 || length < 12) {
    return false;
  }
  size_t cursor = 12;
  size_t nameLength = 0;
  bool firstLabel = true;
  while (cursor < length) {
    const uint8_t labelLength = packet[cursor++];
    if (labelLength == 0) {
      break;
    }
    if ((labelLength & 0xC0U) != 0 || labelLength > 63 || cursor + labelLength > length) {
      return false;
    }
    if (!firstLabel) {
      if (nameLength + 1 >= nameCapacity) {
        return false;
      }
      name[nameLength++] = '.';
    }
    firstLabel = false;
    if (nameLength + labelLength >= nameCapacity) {
      return false;
    }
    for (uint8_t i = 0; i < labelLength; ++i) {
      uint8_t value = packet[cursor++];
      if (value < 0x21U || value > 0x7EU) {
        return false;
      }
      if (value >= 'A' && value <= 'Z') {
        value = static_cast<uint8_t>(value + ('a' - 'A'));
      }
      name[nameLength++] = static_cast<char>(value);
    }
    if (nameLength > 253) {
      return false;
    }
  }
  if (cursor > length || cursor + 4 > length) {
    return false;
  }
  name[nameLength] = '\0';
  questionEnd = cursor + 4;  // QTYPE and QCLASS follow QNAME.
  return true;
}

bool DnsProxy::forwardQuery(const IPAddress& clientIp, uint16_t clientPort,
                            uint8_t* packet, size_t packetLength,
                            size_t questionEnd, const char* domain,
                            uint16_t queryType) {
  uint16_t upstreamId = 0;
  PendingRequest* request = allocatePending(upstreamId);
  if (request == nullptr) {
    ++stats_.queueFull;
    ++clientCounters(clientIp).failures;
    const bool responseSent = sendRcode(clientIp, clientPort, packet, packetLength,
                                        questionEnd, kRcodeServFail);
    record(clientIp, domain, queryType, DnsTelemetryAction::Forwarded,
           responseSent ? DnsTelemetryOutcome::QueueFull
                        : DnsTelemetryOutcome::ClientSendError,
           responseSent ? kRcodeServFail : -1);
    return false;
  }

  request->originalId = readU16Be(packet);
  request->clientIp = clientIp;
  request->clientPort = clientPort;
  request->questionLength = static_cast<uint16_t>(questionEnd);
  request->queryType = queryType;
  std::snprintf(request->domain, sizeof(request->domain), "%s", domain);
  std::memcpy(request->question, packet, questionEnd);
  writeU16Be(packet, upstreamId);

  request->startedAtUs = micros();
  const bool sent = upstreamSocket_.beginPacket(upstreamIp_, upstreamPort_) == 1 &&
                    upstreamSocket_.write(packet, packetLength) == packetLength &&
                    upstreamSocket_.endPacket() == 1;
  if (!sent) {
    request->active = false;
    ++stats_.sendErrors;
    ++clientCounters(clientIp).failures;
    const bool responseSent = sendRcode(clientIp, clientPort, request->question,
                                        request->questionLength, request->questionLength,
                                        kRcodeServFail);
    record(clientIp, request->domain, queryType, DnsTelemetryAction::Forwarded,
           responseSent ? DnsTelemetryOutcome::UpstreamSendError
                        : DnsTelemetryOutcome::ClientSendError,
           responseSent ? kRcodeServFail : -1);
    return false;
  }
  request->deadline = millis() + kUpstreamTimeoutMs;
  return true;
}

void DnsProxy::record(const IPAddress& clientIp, const char* domain,
                      uint16_t queryType, DnsTelemetryAction action,
                      DnsTelemetryOutcome outcome, int responseCode,
                      uint16_t answerCount, int32_t upstreamLatencyUs) {
  if (telemetry_ != nullptr) {
    telemetry_->enqueue(clientIp, domain, queryType, action, outcome,
                        responseCode, answerCount, upstreamLatencyUs);
  }
}

bool DnsProxy::sendRcode(const IPAddress& clientIp, uint16_t clientPort,
                         const uint8_t* query, size_t queryLength,
                         size_t questionEnd, uint8_t rcode) {
  uint8_t response[kMaxQuestionBytes] = {};
  size_t responseLength = 12;
  uint16_t queryFlags = 0;
  if (query != nullptr && queryLength >= 4) {
    queryFlags = readU16Be(query + 2);
  }
  if (query != nullptr && questionEnd > 12 && questionEnd <= queryLength &&
      questionEnd <= sizeof(response)) {
    std::memcpy(response, query, questionEnd);
    responseLength = questionEnd;
    writeU16Be(response + 4, 1);
  } else {
    if (query != nullptr && queryLength >= 2) {
      response[0] = query[0];
      response[1] = query[1];
    }
    writeU16Be(response + 4, 0);
  }
  const uint16_t responseFlags = static_cast<uint16_t>(
      0x8000U | (queryFlags & 0x7910U) | 0x0080U | (rcode & 0x0FU));
  writeU16Be(response + 2, responseFlags);
  writeU16Be(response + 6, 0);
  writeU16Be(response + 8, 0);
  writeU16Be(response + 10, 0);
  return sendPacket(clientIp, clientPort, response, responseLength);
}

bool DnsProxy::sendPacket(const IPAddress& clientIp, uint16_t clientPort,
                          const uint8_t* data, size_t length) {
  if (clientSocket_.beginPacket(clientIp, clientPort) != 1) {
    ++stats_.sendErrors;
    return false;
  }
  if (clientSocket_.write(data, length) != length || clientSocket_.endPacket() != 1) {
    ++stats_.sendErrors;
    return false;
  }
  return true;
}

DnsProxy::PendingRequest* DnsProxy::allocatePending(uint16_t& upstreamId) {
  PendingRequest* available = nullptr;
  for (PendingRequest& request : pending_) {
    if (!request.active) {
      available = &request;
      break;
    }
  }
  if (available == nullptr) {
    return nullptr;
  }

  for (uint32_t attempt = 0; attempt <= 0xFFFFU; ++attempt) {
    const uint16_t candidate = nextUpstreamId_++;
    if (findPending(candidate) == nullptr) {
      *available = PendingRequest{};
      available->active = true;
      available->upstreamId = candidate;
      upstreamId = candidate;
      return available;
    }
  }
  return nullptr;
}

DnsProxy::PendingRequest* DnsProxy::findPending(uint16_t upstreamId) {
  for (PendingRequest& request : pending_) {
    if (request.active && request.upstreamId == upstreamId) {
      return &request;
    }
  }
  return nullptr;
}

DnsProxy::ClientCounters& DnsProxy::clientCounters(const IPAddress& clientIp) {
  ClientCounters* oldest = &clients_[0];
  const uint32_t now = millis();
  for (ClientCounters& counters : clients_) {
    if (counters.used && counters.ip == clientIp) {
      counters.lastSeen = now;
      return counters;
    }
    if (!counters.used) {
      oldest = &counters;
      break;
    }
    if (static_cast<uint32_t>(now - counters.lastSeen) >
        static_cast<uint32_t>(now - oldest->lastSeen)) {
      oldest = &counters;
    }
  }
  *oldest = ClientCounters{};
  oldest->used = true;
  oldest->ip = clientIp;
  oldest->lastSeen = now;
  return *oldest;
}

void DnsProxy::printStats() const {
  Serial.println("--- DNS stats since boot ---");
  Serial.printf("Received: %llu\n", static_cast<unsigned long long>(stats_.received));
  Serial.printf("Blocked: %llu\n", static_cast<unsigned long long>(stats_.blocked));
  Serial.printf("Forwarded: %llu\n", static_cast<unsigned long long>(stats_.forwarded));
  Serial.printf("Upstream replies: %llu\n", static_cast<unsigned long long>(stats_.upstreamReplies));
  Serial.printf("Upstream timeouts: %llu\n", static_cast<unsigned long long>(stats_.upstreamTimeouts));
  Serial.printf("Queue full: %llu\n", static_cast<unsigned long long>(stats_.queueFull));
  Serial.printf("Malformed: %llu\n", static_cast<unsigned long long>(stats_.malformed));
  Serial.printf("Send errors: %llu\n", static_cast<unsigned long long>(stats_.sendErrors));
  for (const ClientCounters& counters : clients_) {
    if (counters.used) {
      printClient(counters);
    }
  }
}

void DnsProxy::printClient(const ClientCounters& counters) const {
  Serial.printf("Client %s: queries=%lu blocked=%lu forwarded=%lu failures=%lu\n",
                counters.ip.toString().c_str(),
                static_cast<unsigned long>(counters.queries),
                static_cast<unsigned long>(counters.blocked),
                static_cast<unsigned long>(counters.forwarded),
                static_cast<unsigned long>(counters.failures));
}
