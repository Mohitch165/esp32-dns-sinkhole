#pragma once

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "BlocklistStore.h"

using PauseDnsForBlocklistUpdate = bool (*)();
using ResumeDnsAfterBlocklistUpdate = void (*)();

class BlocklistOta {
 public:
  struct Manifest {
    String requestId;
    String version;
    String imageSha256;
    String payloadCrc32;
    uint32_t imageBytes = 0;
    uint32_t entryCount = 0;
  };

  bool begin(BlocklistStore& store, PauseDnsForBlocklistUpdate pauseDns,
             ResumeDnsAfterBlocklistUpdate resumeDns,
             SemaphoreHandle_t httpsSessionMutex);

 private:
  static void taskEntry(void* argument);
  void run();
  bool buildApiUrls();
  bool fetchManifest(Manifest& manifest, bool& available);
  bool applyManifest(const Manifest& manifest);
  bool postStatus(const char* requestId, const char* imageSha256,
                  const char* payloadCrc32, const char* stage,
                  uint32_t entryCount, const char* message);

  BlocklistStore* store_ = nullptr;
  PauseDnsForBlocklistUpdate pauseDns_ = nullptr;
  ResumeDnsAfterBlocklistUpdate resumeDns_ = nullptr;
  SemaphoreHandle_t httpsSessionMutex_ = nullptr;
  String manifestUrl_;
  String imageUrlBase_;
  String statusUrl_;
  String lastHandledRequestId_;
};
