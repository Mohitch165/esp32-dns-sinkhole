#include <Arduino.h>
#include <ArduinoOTA.h>
#include <Preferences.h>
#include <WiFi.h>

#include <cstdio>
#include <cstring>

#include "BlocklistStore.h"
#include "DnsProxy.h"
#include "TelemetryClient.h"
#include "secrets.h"

#ifndef OTA_UPDATE_PASSWORD
#define OTA_UPDATE_PASSWORD ""
#endif

namespace {
constexpr char kDefaultUpstream[] = "1.1.1.1";
constexpr char kOtaHostname[] = "esp32-dns-sinkhole";
constexpr char kOtaPassword[] = OTA_UPDATE_PASSWORD;
constexpr uint16_t kDefaultUpstreamPort = 53;
constexpr uint32_t kWifiRetryMs = 10000;

BlocklistStore blocklist;
DnsProxy dnsProxy;
TelemetryClient telemetryClient;
IPAddress upstreamIp(1, 1, 1, 1);
uint16_t upstreamPort = kDefaultUpstreamPort;
bool dnsStarted = false;
bool otaStarted = false;
bool otaInProgress = false;
bool otaPasswordWarningPrinted = false;
uint8_t lastOtaProgressPercent = 0;
uint32_t nextWifiAttempt = 0;
uint32_t nextDnsAttempt = 0;

void loadResolverSettings() {
  Preferences preferences;
  // First boot has no namespace yet, so open read/write to let NVS create it.
  if (!preferences.begin("dns-proxy", false)) {
    Serial.println("NVS unavailable; using default resolver");
    return;
  }
  const String savedIp = preferences.getString("upstream", kDefaultUpstream);
  const uint16_t savedPort = preferences.getUShort("port", kDefaultUpstreamPort);
  preferences.end();

  IPAddress parsed;
  if (parsed.fromString(savedIp) && savedPort != 0) {
    upstreamIp = parsed;
    upstreamPort = savedPort;
  } else {
    Serial.println("Invalid saved resolver; using default resolver");
  }
}

void startWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.setHostname("esp32-dns-sinkhole");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to Wi-Fi");
  const uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 10000U) {
    delay(250);
    Serial.print('.');
  }
  Serial.println();
}

bool persistResolver(const IPAddress& ip, uint16_t port) {
  Preferences preferences;
  if (!preferences.begin("dns-proxy", false)) {
    Serial.println("Could not open NVS; resolver was not saved");
    return false;
  }
  const size_t ipBytes = preferences.putString("upstream", ip.toString());
  const size_t portBytes = preferences.putUShort("port", port);
  preferences.end();
  if (ipBytes == 0 || portBytes == 0) {
    Serial.println("NVS write failed; resolver was not changed");
    return false;
  }
  upstreamIp = ip;
  upstreamPort = port;
  dnsProxy.setUpstream(upstreamIp, upstreamPort);
  Serial.printf("Upstream resolver saved: %s:%u\n", upstreamIp.toString().c_str(),
                static_cast<unsigned>(upstreamPort));
  return true;
}

void processSerialLine(const char* line) {
  if (line[0] == '\0') {
    return;
  }
  if (std::strcmp(line, "stats") == 0) {
    dnsProxy.printStats();
    return;
  }
  if (std::strcmp(line, "telemetry") == 0) {
    telemetryClient.printStats();
    return;
  }
  if (std::strcmp(line, "resolver") == 0) {
    Serial.printf("Upstream resolver: %s:%u\n", upstreamIp.toString().c_str(),
                  static_cast<unsigned>(upstreamPort));
    return;
  }
  if (std::strcmp(line, "help") == 0) {
    Serial.println("Commands: stats | telemetry | resolver | resolver <IPv4> <port> | help");
    return;
  }

  char addressText[16] = {};
  unsigned portValue = 0;
  char extra[2] = {};
  if (std::sscanf(line, "resolver %15s %u %1s", addressText, &portValue, extra) == 2 &&
      portValue > 0 && portValue <= 65535U) {
    IPAddress parsed;
    if (parsed.fromString(addressText)) {
      persistResolver(parsed, static_cast<uint16_t>(portValue));
      return;
    }
  }
  Serial.println("Unknown command. Enter 'help' for available commands.");
}

void handleSerialCommand() {
  static char line[64] = {};
  static size_t length = 0;
  static bool discarding = false;
  while (Serial.available() > 0) {
    const char value = static_cast<char>(Serial.read());
    if (value == '\r') {
      continue;
    }
    if (value == '\n') {
      if (!discarding) {
        line[length] = '\0';
        processSerialLine(line);
      } else {
        Serial.println("Command too long");
      }
      length = 0;
      discarding = false;
      continue;
    }
    if (!discarding && length + 1 < sizeof(line)) {
      line[length++] = value;
    } else {
      discarding = true;
    }
  }
}

void ensureOtaStarted() {
  if (WiFi.status() != WL_CONNECTED) {
    if (otaStarted) {
      ArduinoOTA.end();
      otaStarted = false;
    }
    if (otaInProgress) {
      otaInProgress = false;
      nextDnsAttempt = 0;
      Serial.println("Wi-Fi lost during OTA; the transfer was interrupted");
    }
    return;
  }

  if (!otaStarted) {
    if (kOtaPassword[0] == '\0') {
      if (!otaPasswordWarningPrinted) {
        Serial.println("OTA disabled; set OTA_UPDATE_PASSWORD in secrets.h before enabling it");
        otaPasswordWarningPrinted = true;
      }
      return;
    }

    ArduinoOTA.setHostname(kOtaHostname);
    ArduinoOTA.setPassword(kOtaPassword);
    ArduinoOTA.setRebootOnSuccess(true);
    ArduinoOTA.onStart([]() {
      otaInProgress = true;
      lastOtaProgressPercent = 0;
      if (dnsStarted) {
        dnsProxy.stop();
        dnsStarted = false;
      }
      Serial.println("OTA update starting; DNS paused until reboot");
    });
    ArduinoOTA.onEnd([]() {
      Serial.println("OTA update complete; rebooting into the new firmware");
    });
    ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
      if (total == 0) {
        return;
      }
      unsigned int percent = (progress * 100U) / total;
      if (percent > 100U) {
        percent = 100U;
      }
      if (percent > lastOtaProgressPercent &&
          (percent >= static_cast<unsigned int>(lastOtaProgressPercent) + 10U ||
           percent == 100U)) {
        lastOtaProgressPercent = static_cast<uint8_t>(percent);
        Serial.printf("OTA progress: %u%%\n", percent);
      }
    });
    ArduinoOTA.onError([](ota_error_t error) {
      otaInProgress = false;
      nextDnsAttempt = 0;
      Serial.printf("OTA update failed (error %u); DNS will resume\n",
                    static_cast<unsigned>(error));
    });
    ArduinoOTA.begin();
    otaStarted = true;
    Serial.printf("Arduino OTA service started: %s at %s\n", kOtaHostname,
                  WiFi.localIP().toString().c_str());
  }

  ArduinoOTA.handle();
}

void ensureDnsStarted() {
  if (otaInProgress) {
    return;
  }
  if (WiFi.status() != WL_CONNECTED) {
    if (dnsStarted) {
      dnsProxy.stop();
      dnsStarted = false;
      nextDnsAttempt = 0;
    }
    const uint32_t now = millis();
    if (nextWifiAttempt == 0 || static_cast<int32_t>(now - nextWifiAttempt) >= 0) {
      Serial.println("Wi-Fi disconnected; reconnecting");
      WiFi.disconnect();
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
      nextWifiAttempt = now + kWifiRetryMs;
    }
    return;
  }

  nextWifiAttempt = 0;
  if (dnsStarted) {
    return;
  }
  const uint32_t now = millis();
  if (nextDnsAttempt != 0 && static_cast<int32_t>(now - nextDnsAttempt) < 0) {
    return;
  }
  Serial.printf("Connected. ESP32 IP: %s\n", WiFi.localIP().toString().c_str());
  if (dnsProxy.begin(blocklist, upstreamIp, upstreamPort)) {
    dnsStarted = true;
    Serial.printf("DNS sinkhole listening on UDP/53; upstream %s:%u\n",
                  upstreamIp.toString().c_str(), static_cast<unsigned>(upstreamPort));
    if (!blocklist.isReady()) {
      Serial.printf("Blocklist unavailable (%s); operating in DNS pass-through mode\n",
                    blocklist.status());
    }
  } else {
    Serial.println("Could not bind DNS UDP sockets; retrying");
    nextDnsAttempt = millis() + 2000U;
  }
}
}  // namespace

void setup() {
  Serial.begin(115200);
  delay(100);

  Serial.println();
  Serial.println("ESP32 DNS sinkhole starting");
  if (std::strcmp(WIFI_SSID, "YOUR_WIFI_SSID") == 0 ||
      std::strcmp(WIFI_PASSWORD, "YOUR_WIFI_PASSWORD") == 0) {
    Serial.println("Edit firmware/ESP32DnsSinkhole/secrets.h with your test Wi-Fi credentials");
  }

  loadResolverSettings();
  dnsProxy.setUpstream(upstreamIp, upstreamPort);
  Serial.printf("Configured upstream: %s:%u\n", upstreamIp.toString().c_str(),
                static_cast<unsigned>(upstreamPort));

  if (blocklist.begin()) {
    Serial.printf("Blocklist ready: %lu sorted hashes\n",
                  static_cast<unsigned long>(blocklist.entryCount()));
  } else {
    Serial.printf("Blocklist not ready: %s\n", blocklist.status());
    Serial.println("DNS will pass through until a valid blocklist partition is installed");
  }

  startWifi();
  dnsProxy.setTelemetry(&telemetryClient);
  telemetryClient.begin();
  ensureDnsStarted();
  ensureOtaStarted();
  Serial.println("Serial commands: stats | telemetry | resolver | resolver <IPv4> <port> | help");
}

void loop() {
  handleSerialCommand();
  ensureDnsStarted();
  ensureOtaStarted();
  dnsProxy.loop();
  delay(1);
}
