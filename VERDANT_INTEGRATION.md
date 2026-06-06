# Verdant Integration Package (Spider Farmer GGS)

## 1) Source components inventoried for migration
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/SpiderFarmer_GGS_BLE_MQTT_Bridge.ino`  
  Device runtime adapter (ESP32 BLE → MQTT).
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/ggs_ble.py`  
  BLE command/status utility.
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/ggs_console.py`  
  Interactive BLE console tool.
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/ggs_ff00_sniffer.py`  
  BLE notification/sniffer utility.
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/README.md`  
  Protocol findings, setup guide, topic structure.

## 2) Verdant integration boundary
- Treat GGS as an **optional hardware connector module** (feature-flagged).
- Runtime model is **device-side bridge + app-side ingestion**:
  - ESP32 bridge publishes MQTT telemetry from BLE.
  - Verdant consumes canonical MQTT topics and maps to domain entities.
- Canonical topic contract remains `grow/GGS/*` by default, with configurable prefix.

## 3) Split deliverables
- Device deliverable:
  - ESP32 firmware remains the adapter.
  - Includes reconnect logic and bridge lifecycle status topic.
- Verdant deliverable:
  - Python module in `verdant_integration/` provides config validation, topic mapping, and parser utilities suitable for ingestion pipelines.

## 4) Configuration normalization
Environment-based app config implemented in:
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/verdant_integration/config.py`

Primary keys:
- `VERDANT_GGS_ENABLED`
- `VERDANT_GGS_MQTT_HOST`
- `VERDANT_GGS_MQTT_PORT`
- `VERDANT_GGS_MQTT_USERNAME`
- `VERDANT_GGS_MQTT_PASSWORD`
- `VERDANT_GGS_MQTT_TLS_ENABLED`
- `VERDANT_GGS_MQTT_TLS_CA_CERT_PATH`
- `VERDANT_GGS_TOPIC_PREFIX`
- `VERDANT_GGS_BLE_ADDRESS`
- `VERDANT_GGS_TELEMETRY_STALE_SECONDS`
- `VERDANT_GGS_COMMAND_RETRIES`

Validation rules fail fast on startup for missing/invalid combinations.

Firmware config was normalized to compile-time definitions instead of hardcoded credentials:
- `WIFI_SSID`, `WIFI_PASSWORD`
- `MQTT_SERVER`, `MQTT_PORT`
- `MQTT_USER`, `MQTT_PASS`
- `MQTT_TOPIC_PREFIX`
- `GGS_BLE_ADDRESS`

## 5) Data contract standardization
Implemented in:
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/verdant_integration/contract.py`

Mapped telemetry:
- `sensor/temp`, `sensor/humi`, `sensor/vpd`
- `fan/on`, `fan/level`
- `light/on`, `light/level`
- `blower/level`
- `status` (bridge online/offline)

## 6) Reliability behavior
- Firmware keeps BLE reconnect + MQTT reconnect behavior.
- MQTT lifecycle signaling now includes retained online/offline state via Last Will on `<prefix>/status`.
- Parser resilience is implemented for fragmented/noisy BLE JSON streams in:
  - `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/verdant_integration/ble_stream.py`

## 7) Security and operations hardening
- Removed source-level credential placeholders in firmware constants by switching to compile-time config definitions.
- Added TLS config expectations for app-side ingestion through environment validation.
- Recommended least-privilege MQTT ACL:
  - Bridge publish: `<prefix>/status`, `<prefix>/sensor/#`, `<prefix>/fan/#`, `<prefix>/light/#`, `<prefix>/blower/#`
  - Verdant consumer subscribe: same read paths
  - Command publisher restricted to explicit command topics only (if enabled in target app).

## 8) Capability mapping
Supported telemetry:
- temp, humidity, vpd, fan, light, blower, bridge status.

Supported controls (protocol-level):
- light/fan/blower methods (`setLight`, `setFan`, `setBlower`).

Not covered by this package:
- Features outside observed BLE protocol surface.

## 9) Integration boundary tests
Added tests:
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/tests/test_contract.py`
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/tests/test_config.py`
- `/tmp/workspace/cheekhimself/Spider-Farmer-GGS-Controller-MQTT/tests/test_ble_stream.py`

These cover topic contract mapping, startup validation, and parser resilience.

## 10) Maintainer documentation
This file acts as the migration/operations guide with:
- Imported component inventory
- Config reference
- Data contract summary
- Reliability/security notes
- Compatibility caveat: vendor firmware changes can alter BLE payloads.

## 11) Rollout approach
- Keep behind feature flag (`VERDANT_GGS_ENABLED`).
- Validate against one known controller before broad enablement.
- Promote only after CI + hardware verification in target repository.
