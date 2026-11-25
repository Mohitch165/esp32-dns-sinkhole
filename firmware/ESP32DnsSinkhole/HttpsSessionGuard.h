#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

class HttpsSessionGuard {
 public:
  explicit HttpsSessionGuard(SemaphoreHandle_t mutex)
      : mutex_(mutex), acquired_(mutex_ != nullptr &&
                                xSemaphoreTakeRecursive(mutex_, portMAX_DELAY) == pdTRUE) {}

  ~HttpsSessionGuard() {
    if (acquired_) xSemaphoreGiveRecursive(mutex_);
  }

  bool acquired() const { return acquired_; }

 private:
  SemaphoreHandle_t mutex_;
  bool acquired_;
};
