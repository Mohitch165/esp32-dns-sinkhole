#include "BlocklistStore.h"

#include <cstring>

#include "esp_partition.h"

namespace {
constexpr uint8_t kHeaderBytes = 16;
constexpr uint8_t kHashBytes = 5;
constexpr uint8_t kFormatVersion = 1;
constexpr uint8_t kHashAlgorithmFnv1a40 = 1;
constexpr uint8_t kMagic[4] = {'N', 'B', 'L', '1'};
constexpr uint64_t kHashMask = (1ULL << 40) - 1ULL;
constexpr uint64_t kFnvOffsetBasis64 = 14695981039346656037ULL;
constexpr uint64_t kFnvPrime64 = 1099511628211ULL;
constexpr size_t kValidationChunkBytes = 1000;  // divisible by five-byte entry size

uint32_t readU32Be(const uint8_t* bytes) {
  return (static_cast<uint32_t>(bytes[0]) << 24) |
         (static_cast<uint32_t>(bytes[1]) << 16) |
         (static_cast<uint32_t>(bytes[2]) << 8) |
         static_cast<uint32_t>(bytes[3]);
}

uint64_t readHash40Be(const uint8_t* bytes) {
  uint64_t value = 0;
  for (size_t i = 0; i < kHashBytes; ++i) {
    value = (value << 8) | bytes[i];
  }
  return value;
}

uint32_t crc32Update(uint32_t crc, const uint8_t* bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    crc ^= bytes[i];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      const uint32_t mask = 0U - (crc & 1U);
      crc = (crc >> 1) ^ (0xEDB88320U & mask);
    }
  }
  return crc;
}
}  // namespace

bool BlocklistStore::fail(const char* reason) {
  partition_ = nullptr;
  entryCount_ = 0;
  ready_ = false;
  status_ = reason;
  return false;
}

bool BlocklistStore::begin() {
  ready_ = false;
  entryCount_ = 0;
  partition_ = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                        ESP_PARTITION_SUBTYPE_ANY,
                                        "blocklist");
  if (partition_ == nullptr) {
    return fail("blocklist partition not found");
  }
  if (partition_->size < kHeaderBytes) {
    return fail("blocklist partition is too small");
  }

  uint8_t header[kHeaderBytes] = {};
  if (esp_partition_read(partition_, 0, header, sizeof(header)) != ESP_OK) {
    return fail("could not read blocklist header");
  }
  if (std::memcmp(header, kMagic, sizeof(kMagic)) != 0) {
    return fail("blocklist magic mismatch");
  }
  if (header[4] != kFormatVersion || header[5] != kHashAlgorithmFnv1a40 ||
      header[6] != kHashBytes || header[7] != 0) {
    return fail("unsupported blocklist format");
  }

  const uint32_t count = readU32Be(header + 8);
  const uint32_t expectedCrc = readU32Be(header + 12);
  const uint64_t payloadBytes = static_cast<uint64_t>(count) * kHashBytes;
  const uint64_t totalBytes = kHeaderBytes + payloadBytes;
  if (count == 0 || totalBytes > partition_->size) {
    return fail("blocklist entry count exceeds partition");
  }
  if (!validatePayload(count, expectedCrc)) {
    return fail("blocklist CRC or ordering check failed");
  }

  entryCount_ = count;
  ready_ = true;
  status_ = "ready";
  return true;
}

bool BlocklistStore::validatePayload(uint32_t count, uint32_t expectedCrc) const {
  uint8_t chunk[kValidationChunkBytes];
  const uint64_t totalPayloadBytes = static_cast<uint64_t>(count) * kHashBytes;

  uint32_t crc = 0xFFFFFFFFU;
  uint64_t offset = 0;
  uint64_t previous = 0;
  bool hasPrevious = false;
  while (offset < totalPayloadBytes) {
    const size_t remaining = static_cast<size_t>(totalPayloadBytes - offset);
    const size_t chunkLength = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
    if (esp_partition_read(partition_, kHeaderBytes + offset, chunk, chunkLength) != ESP_OK) {
      return false;
    }
    crc = crc32Update(crc, chunk, chunkLength);
    for (size_t index = 0; index < chunkLength; index += kHashBytes) {
      const uint64_t current = readHash40Be(chunk + index);
      if (hasPrevious && current <= previous) {
        return false;
      }
      previous = current;
      hasPrevious = true;
    }
    offset += chunkLength;
  }
  crc ^= 0xFFFFFFFFU;
  return crc == expectedCrc;
}

uint64_t BlocklistStore::hashDomain40(const char* domain) {
  uint64_t hash = kFnvOffsetBasis64;
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(domain);
       *cursor != '\0'; ++cursor) {
    uint8_t value = *cursor;
    if (value >= 'A' && value <= 'Z') {
      value = static_cast<uint8_t>(value + ('a' - 'A'));
    }
    hash ^= value;
    hash *= kFnvPrime64;
  }
  return hash & kHashMask;
}

bool BlocklistStore::containsHash(uint64_t hash) const {
  if (!ready_ || partition_ == nullptr) {
    return false;
  }
  uint8_t target[kHashBytes];
  for (int i = kHashBytes - 1; i >= 0; --i) {
    target[i] = static_cast<uint8_t>(hash & 0xFFU);
    hash >>= 8;
  }

  uint32_t low = 0;
  uint32_t high = entryCount_;
  uint8_t candidate[kHashBytes];
  while (low < high) {
    const uint32_t middle = low + ((high - low) / 2);
    const size_t offset = kHeaderBytes + static_cast<size_t>(middle) * kHashBytes;
    if (esp_partition_read(partition_, offset, candidate, sizeof(candidate)) != ESP_OK) {
      return false;
    }
    const int comparison = std::memcmp(candidate, target, sizeof(candidate));
    if (comparison == 0) {
      return true;
    }
    if (comparison < 0) {
      low = middle + 1;
    } else {
      high = middle;
    }
  }
  return false;
}

bool BlocklistStore::containsDomainOrSubdomain(const char* domain) const {
  if (!ready_ || domain == nullptr || domain[0] == '\0') {
    return false;
  }
  size_t length = std::strlen(domain);
  if (length > 253) {
    return false;
  }
  if (containsHash(hashDomain40(domain))) {
    return true;
  }

  // Check each parent domain, but never hash a one-label TLD such as "com".
  for (const char* dot = std::strchr(domain, '.'); dot != nullptr;
       dot = std::strchr(dot + 1, '.')) {
    const char* suffix = dot + 1;
    if (std::strchr(suffix, '.') == nullptr) {
      break;
    }
    if (containsHash(hashDomain40(suffix))) {
      return true;
    }
  }
  return false;
}
