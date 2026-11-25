#pragma once

#include <cstddef>
#include <cstdint>

#include "esp_partition.h"

class BlocklistStore {
 public:
  bool begin();
  bool isReady() const { return ready_; }
  uint32_t entryCount() const { return entryCount_; }
  uint32_t payloadCrc32() const { return payloadCrc32_; }
  const char* status() const { return status_; }
  bool containsDomainOrSubdomain(const char* domain) const;

 private:
  bool fail(const char* reason);
  bool validatePayload(uint32_t count, uint32_t expectedCrc) const;
  bool containsHash(uint64_t hash) const;
  static uint64_t hashDomain40(const char* domain);

  const esp_partition_t* partition_ = nullptr;
  uint32_t entryCount_ = 0;
  uint32_t payloadCrc32_ = 0;
  bool ready_ = false;
  const char* status_ = "not initialized";
};
