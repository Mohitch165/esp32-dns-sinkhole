#include "BlocklistOta.h"

#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <esp_partition.h>
#include <psa/crypto.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "secrets.h"
#include "telemetry_ca.h"

#ifndef TELEMETRY_API_URL
#define TELEMETRY_API_URL ""
#endif
#ifndef TELEMETRY_API_TOKEN
#define TELEMETRY_API_TOKEN ""
#endif

namespace {
constexpr char kDeviceId[] = "esp32-dns-sinkhole";
constexpr char kTelemetryPath[] = "/api/v1/telemetry/batches";
constexpr size_t kNblHeaderBytes = 16;
constexpr size_t kNblHashBytes = 5;
constexpr size_t kTransferChunkBytes = 1024;
constexpr uint32_t kPollIntervalMs = 10000;
constexpr uint32_t kReadTimeoutMs = 30000;

uint32_t readU32Be(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) | data[3];
}

uint32_t crc32Update(uint32_t crc, const uint8_t* data, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      const uint32_t mask = 0U - (crc & 1U);
      crc = (crc >> 1) ^ (0xEDB88320U & mask);
    }
  }
  return crc;
}

bool jsonStringField(const String& json, const char* key, String& value) {
  const String name = String("\"") + key + "\"";
  int position = json.indexOf(name);
  if (position < 0) return false;
  position = json.indexOf(':', position + name.length());
  if (position < 0) return false;
  position = json.indexOf('"', position + 1);
  if (position < 0) return false;
  const int end = json.indexOf('"', position + 1);
  if (end < 0) return false;
  value = json.substring(position + 1, end);
  return true;
}

bool jsonUintField(const String& json, const char* key, uint32_t& value) {
  const String name = String("\"") + key + "\"";
  int position = json.indexOf(name);
  if (position < 0) return false;
  position = json.indexOf(':', position + name.length());
  if (position < 0) return false;
  ++position;
  while (position < static_cast<int>(json.length()) &&
         (json[position] == ' ' || json[position] == '\t')) ++position;
  if (position >= static_cast<int>(json.length()) || json[position] < '0' || json[position] > '9') return false;
  const char* start = json.c_str() + position;
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(start, &end, 10);
  if (end == start || parsed > UINT32_MAX) return false;
  value = static_cast<uint32_t>(parsed);
  return true;
}

bool jsonAvailable(const String& json, bool& available) {
  const int position = json.indexOf("\"available\"");
  if (position < 0) return false;
  const int colon = json.indexOf(':', position);
  if (colon < 0) return false;
	int value = colon + 1;
	while (value < static_cast<int>(json.length()) &&
	       (json[value] == ' ' || json[value] == '\t' || json[value] == '\r' || json[value] == '\n')) ++value;
	if (json.substring(value).startsWith("true")) {
    available = true;
    return true;
  }
	if (json.substring(value).startsWith("false")) {
    available = false;
    return true;
  }
  return false;
}

bool readExact(Stream& stream, uint8_t* destination, size_t length) {
  size_t received = 0;
  uint32_t lastProgress = millis();
  while (received < length) {
    const int available = stream.available();
    if (available > 0) {
      const size_t amount = static_cast<size_t>(available) < length - received
                                ? static_cast<size_t>(available)
                                : length - received;
      const size_t count = stream.readBytes(reinterpret_cast<char*>(destination + received), amount);
      if (count > 0) {
        received += count;
        lastProgress = millis();
      }
    } else {
      if (static_cast<uint32_t>(millis() - lastProgress) > kReadTimeoutMs) return false;
      vTaskDelay(pdMS_TO_TICKS(2));
    }
  }
  return true;
}

bool validHex(const String& value, size_t length) {
  if (value.length() != length) return false;
  for (size_t i = 0; i < length; ++i) {
    const char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

bool parseManifest(const String& body, BlocklistOta::Manifest& manifest, bool& available) {
  if (!jsonAvailable(body, available)) return false;
  if (!available) return true;
  return jsonStringField(body, "request_id", manifest.requestId) &&
         jsonStringField(body, "version", manifest.version) &&
         jsonStringField(body, "image_sha256", manifest.imageSha256) &&
         jsonStringField(body, "payload_crc32", manifest.payloadCrc32) &&
         jsonUintField(body, "image_bytes", manifest.imageBytes) &&
         jsonUintField(body, "entry_count", manifest.entryCount) &&
         manifest.requestId.length() > 0 && manifest.requestId.length() <= 64 &&
         manifest.version.length() > 0 && manifest.version.length() <= 96 &&
         validHex(manifest.imageSha256, 64) && validHex(manifest.payloadCrc32, 8) &&
         manifest.entryCount > 0 && manifest.imageBytes >= kNblHeaderBytes;
}

bool makeAuthenticatedClient(WiFiClientSecure& client, HTTPClient& http,
                             const String& url) {
  if (TELEMETRY_API_TOKEN[0] == '\0' || TELEMETRY_CA_CERT_PEM[0] == '\0') return false;
  client.setCACert(TELEMETRY_CA_CERT_PEM);
  client.setTimeout(35000);
  if (!http.begin(client, url)) return false;
  http.setTimeout(35000);
  http.addHeader("Authorization", String("Bearer ") + TELEMETRY_API_TOKEN);
  return true;
}

String hex32(uint32_t value) {
  char text[9] = {};
  std::snprintf(text, sizeof(text), "%08lx", static_cast<unsigned long>(value));
  return String(text);
}

String hexDigest(const uint8_t* value, size_t length) {
	static constexpr char digits[] = "0123456789abcdef";
	String result;
	result.reserve(length * 2);
	for (size_t i = 0; i < length; ++i) {
		result += digits[value[i] >> 4];
		result += digits[value[i] & 0x0F];
	}
	return result;
}
}  // namespace

bool BlocklistOta::begin(BlocklistStore& store, PauseDnsForBlocklistUpdate pauseDns,
                         ResumeDnsAfterBlocklistUpdate resumeDns) {
  store_ = &store;
  pauseDns_ = pauseDns;
  resumeDns_ = resumeDns;
  if (!buildApiUrls()) {
    Serial.println("Blocklist OTA disabled; telemetry API URL or credentials are incomplete");
    return false;
  }
  const BaseType_t created = xTaskCreatePinnedToCore(
      taskEntry, "blocklist-ota", 12288, this, 1, nullptr, 0);
  if (created != pdPASS) {
    Serial.println("Blocklist OTA disabled; could not start update worker");
    return false;
  }
  Serial.printf("Blocklist OTA worker started: %s\n", manifestUrl_.c_str());
  return true;
}

bool BlocklistOta::buildApiUrls() {
  String base = TELEMETRY_API_URL;
  if (base.length() <= sizeof(kTelemetryPath) - 1 || !base.endsWith(kTelemetryPath)) return false;
  base.remove(base.length() - (sizeof(kTelemetryPath) - 1));
  manifestUrl_ = base + "/api/v1/blocklist/manifest";
  imageUrlBase_ = base + "/api/v1/blocklist/images/";
  statusUrl_ = base + "/api/v1/blocklist/status";
  return true;
}

void BlocklistOta::taskEntry(void* argument) {
  static_cast<BlocklistOta*>(argument)->run();
}

void BlocklistOta::run() {
	while (WiFi.status() == WL_CONNECTED && std::time(nullptr) < 1700000000) {
		Serial.println("Blocklist OTA waiting for network time before verified HTTPS");
		vTaskDelay(pdMS_TO_TICKS(10000));
	}
	bool currentStatusReported = false;
	uint32_t nextCurrentReport = 0;
  if (store_ != nullptr && store_->isReady()) {
		currentStatusReported = postStatus("current", "", hex32(store_->payloadCrc32()).c_str(), "ready",
		                                   store_->entryCount(), "installed blocklist is valid");
  } else {
		currentStatusReported = postStatus("current", "", "", "failed", 0,
		                                   "no valid installed blocklist");
  }

  while (true) {
	if (WiFi.status() == WL_CONNECTED && std::time(nullptr) >= 1700000000) {
			if (!currentStatusReported && static_cast<int32_t>(millis() - nextCurrentReport) >= 0) {
				if (store_ != nullptr && store_->isReady()) {
					currentStatusReported = postStatus("current", "", hex32(store_->payloadCrc32()).c_str(),
					                                   "ready", store_->entryCount(),
					                                   "installed blocklist is valid");
				} else {
					currentStatusReported = postStatus("current", "", "", "failed", 0,
					                                   "no valid installed blocklist");
				}
				nextCurrentReport = millis() + 30000U;
			}
      Manifest manifest;
      bool available = false;
      if (fetchManifest(manifest, available) && available &&
          manifest.requestId != lastHandledRequestId_) {
        applyManifest(manifest);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(kPollIntervalMs));
  }
}

bool BlocklistOta::fetchManifest(Manifest& manifest, bool& available) {
  WiFiClientSecure client;
  HTTPClient http;
  if (!makeAuthenticatedClient(client, http, manifestUrl_)) return false;
  const int result = http.GET();
  if (result != HTTP_CODE_OK) {
    http.end();
    return false;
  }
  const String body = http.getString();
  http.end();
  return body.length() <= 2048 && parseManifest(body, manifest, available);
}

bool BlocklistOta::applyManifest(const Manifest& manifest) {
  const uint32_t currentCount = store_->entryCount();
  const uint32_t currentCrc = store_->payloadCrc32();
  if (store_->isReady() && manifest.entryCount == currentCount &&
      manifest.payloadCrc32 == hex32(currentCrc)) {
    lastHandledRequestId_ = manifest.requestId;
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "unchanged", currentCount,
               "device already has this blocklist payload");
    postStatus("current", manifest.imageSha256.c_str(), manifest.payloadCrc32.c_str(),
               "ready", currentCount, "installed blocklist is valid");
    return true;
  }

  postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
             manifest.payloadCrc32.c_str(), "downloading", manifest.entryCount,
             "downloading blocklist image over verified HTTPS");

  WiFiClientSecure client;
  HTTPClient http;
  if (!makeAuthenticatedClient(client, http, imageUrlBase_ + manifest.imageSha256)) {
    lastHandledRequestId_ = manifest.requestId;
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "failed", 0,
               "could not initialize authenticated image transfer");
    return false;
  }
  const int response = http.GET();
  const int contentLength = http.getSize();
  if (response != HTTP_CODE_OK || contentLength < 0 ||
      static_cast<uint32_t>(contentLength) != manifest.imageBytes) {
    http.end();
    lastHandledRequestId_ = manifest.requestId;
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "failed", 0,
               "image HTTP status or content length did not match the manifest");
    return false;
  }

  WiFiClient* stream = http.getStreamPtr();
  uint8_t header[kNblHeaderBytes] = {};
  if (stream == nullptr || !readExact(*stream, header, sizeof(header))) {
    http.end();
    lastHandledRequestId_ = manifest.requestId;
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "failed", 0,
               "image header transfer timed out");
    return false;
  }
  const uint32_t count = readU32Be(header + 8);
  const uint32_t expectedCrc = readU32Be(header + 12);
  const uint64_t expectedBytes = kNblHeaderBytes + static_cast<uint64_t>(count) * kNblHashBytes;
  const esp_partition_t* partition = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "blocklist");
  if (std::memcmp(header, "NBL1", 4) != 0 || header[4] != 1 || header[5] != 1 ||
      header[6] != 5 || header[7] != 0 || count != manifest.entryCount ||
      expectedCrc != std::strtoul(manifest.payloadCrc32.c_str(), nullptr, 16) ||
      expectedBytes != manifest.imageBytes || partition == nullptr ||
      manifest.imageBytes > partition->size || partition->size % 0x1000 != 0) {
    http.end();
    lastHandledRequestId_ = manifest.requestId;
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "failed", 0,
               "image header, count, CRC, or partition-size check failed");
    return false;
  }

  postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
             manifest.payloadCrc32.c_str(), "writing", count,
             "pausing DNS and replacing the blocklist data partition");
  if (pauseDns_ == nullptr || !pauseDns_()) {
    http.end();
    lastHandledRequestId_ = manifest.requestId;
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "failed", 0,
               "could not pause DNS safely before flash write");
    return false;
  }

	psa_hash_operation_t sha = PSA_HASH_OPERATION_INIT;
	bool success = psa_crypto_init() == PSA_SUCCESS &&
	               psa_hash_setup(&sha, PSA_ALG_SHA_256) == PSA_SUCCESS;
	if (success) success = esp_partition_erase_range(partition, 0, partition->size) == ESP_OK;
  uint32_t flashOffset = 0;
  uint32_t crc = 0xFFFFFFFFU;
  uint64_t previousHash = 0;
  bool hasPreviousHash = false;
  uint8_t hashBytes[kNblHashBytes] = {};
  size_t hashByteCount = 0;
  uint8_t transferBuffer[kTransferChunkBytes] = {};
  if (success) {
		success = psa_hash_update(&sha, header, sizeof(header)) == PSA_SUCCESS;
	}
	if (success) {
    success = esp_partition_write(partition, flashOffset, header, sizeof(header)) == ESP_OK;
    flashOffset += sizeof(header);
  }

  uint32_t payloadRemaining = count * static_cast<uint32_t>(kNblHashBytes);
  while (success && payloadRemaining > 0) {
    const size_t chunkLength = payloadRemaining < sizeof(transferBuffer)
                                   ? payloadRemaining : sizeof(transferBuffer);
    if (!readExact(*stream, transferBuffer, chunkLength)) {
      success = false;
      break;
    }
		if (psa_hash_update(&sha, transferBuffer, chunkLength) != PSA_SUCCESS) {
			success = false;
			break;
		}
    crc = crc32Update(crc, transferBuffer, chunkLength);
    for (size_t i = 0; i < chunkLength; ++i) {
      hashBytes[hashByteCount++] = transferBuffer[i];
      if (hashByteCount == kNblHashBytes) {
        uint64_t currentHash = 0;
        for (uint8_t byte : hashBytes) currentHash = (currentHash << 8) | byte;
        if (hasPreviousHash && currentHash <= previousHash) {
          success = false;
          break;
        }
        previousHash = currentHash;
        hasPreviousHash = true;
        hashByteCount = 0;
      }
    }
    if (!success) break;
    const size_t paddedLength = (chunkLength + 3U) & ~static_cast<size_t>(3U);
    if (paddedLength > chunkLength) {
      std::memset(transferBuffer + chunkLength, 0xFF, paddedLength - chunkLength);
    }
    if (esp_partition_write(partition, flashOffset, transferBuffer, paddedLength) != ESP_OK) {
      success = false;
      break;
    }
    flashOffset += chunkLength;
    payloadRemaining -= static_cast<uint32_t>(chunkLength);
    vTaskDelay(1);
  }
  crc ^= 0xFFFFFFFFU;
  success = success && hashByteCount == 0 && crc == expectedCrc &&
	          flashOffset == manifest.imageBytes;
	uint8_t imageDigest[32] = {};
	size_t digestLength = 0;
	if (success) {
		success = psa_hash_finish(&sha, imageDigest, sizeof(imageDigest), &digestLength) == PSA_SUCCESS &&
		          digestLength == sizeof(imageDigest) &&
		          hexDigest(imageDigest, sizeof(imageDigest)) == manifest.imageSha256;
	}
	psa_hash_abort(&sha);
  http.end();

  if (success) {
    success = store_->begin() && store_->entryCount() == count &&
              store_->payloadCrc32() == expectedCrc;
  }
  if (!success) {
    store_->begin();
    lastHandledRequestId_ = manifest.requestId;
		Serial.println("Blocklist OTA failed; check API log/status for transfer and validation details");
    postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
               manifest.payloadCrc32.c_str(), "failed", 0,
               "flash transfer or on-device blocklist validation failed; Mac rollback required");
		if (store_->isReady()) {
			postStatus("current", "", hex32(store_->payloadCrc32()).c_str(), "ready",
			           store_->entryCount(), "existing blocklist remains valid after failed update");
		} else {
			postStatus("current", "", "", "failed", 0,
			           "blocklist partition requires Mac rollback");
		}
    if (resumeDns_ != nullptr) resumeDns_();
    return false;
  }

  lastHandledRequestId_ = manifest.requestId;
  postStatus(manifest.requestId.c_str(), manifest.imageSha256.c_str(),
             manifest.payloadCrc32.c_str(), "installed", count,
             "blocklist image passed CRC, ordering, and flash readback validation");
  postStatus("current", manifest.imageSha256.c_str(), manifest.payloadCrc32.c_str(),
             "ready", count, "new blocklist is active");
  if (resumeDns_ != nullptr) resumeDns_();
  Serial.printf("Blocklist OTA installed: version=%s hashes=%lu CRC32=%s\n",
                manifest.version.c_str(), static_cast<unsigned long>(count),
                manifest.payloadCrc32.c_str());
  return true;
}

bool BlocklistOta::postStatus(const char* requestId, const char* imageSha256,
                              const char* payloadCrc32, const char* stage,
                              uint32_t entryCount, const char* message) {
  if (WiFi.status() != WL_CONNECTED) return false;
  WiFiClientSecure client;
  HTTPClient http;
  if (!makeAuthenticatedClient(client, http, statusUrl_)) return false;
  http.addHeader("Content-Type", "application/json");
  String body = "{\"device_id\":\"";
  body += kDeviceId;
  body += "\",\"request_id\":\"";
  body += requestId;
  body += "\",\"image_sha256\":\"";
  body += imageSha256;
  body += "\",\"payload_crc32\":\"";
  body += payloadCrc32;
  body += "\",\"stage\":\"";
  body += stage;
  body += "\",\"entry_count\":";
  body += String(entryCount);
  body += ",\"message\":\"";
  body += message;
  body += "\"}";
  const int result = http.POST(body);
  http.end();
  return result == HTTP_CODE_ACCEPTED || result == HTTP_CODE_OK;
}
