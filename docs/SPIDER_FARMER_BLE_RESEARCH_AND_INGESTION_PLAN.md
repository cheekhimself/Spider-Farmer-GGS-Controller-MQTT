# Spider Farmer GGS BLE Research and Verdant Ingestion Plan

Status: research plan; no production decoder or Verdant sink is implemented here.

Research snapshot: 2026-08-28.

## 1. Scope and decision

This plan covers receive-only ingestion of observed Spider Farmer GGS controller
telemetry into Verdant. It does not enable equipment commands, subscribe to
command topics, or write the GGS BLE command characteristic.

The safest implementation is not to extend the current brace-matching parser.
Public evidence shows incompatible payload profiles across product families and
firmware versions. Verdant should use a strict transport decoder with an
explicit, pinned profile for each validated hardware and firmware combination.

The initial production boundary is:

```text
GGS controller FF01 notifications
  -> receive-only Pi process
  -> strict frame, CRC, decrypt, and JSON validation
  -> one atomic, source-labeled observation
  -> restricted local MQTT telemetry topic
  -> Verdant staging ingestion
```

FF02 writes remain prohibited through the one-tent canary. Any future command
work is a separate safety review and must remain grower-approved.

## 2. Search coverage and limits

The survey used public GitHub repository, code, commit, fork, issue, and pull
request searches for Spider Farmer, GGS, the observed UUIDs, frame magic, BLE,
MQTT, Home Assistant, and ESPHome. It also followed repositories linked from
issues and READMEs.

This is a comprehensive public sweep as of the research date, not a guarantee
that every private, deleted, newly created, or unindexed repository was found.
One issue references a private implementation that could not be reviewed and is
therefore not evidence for this plan.

## 3. Public repository evidence ledger

### Primary BLE evidence

| Repository | Evidence contributed | Use in Verdant |
| --- | --- | --- |
| [cr0ssn0tice/Spider-Farmer-GGS-Controller-MQTT](https://github.com/cr0ssn0tice/Spider-Farmer-GGS-Controller-MQTT/tree/e4e4c71b492582943892c513e6c03f909fad2507) | Original plaintext BLE/MQTT bridge, UUIDs, early fields, and firmware-v2 issue reports | Historical baseline; parser is insufficient for encrypted firmware |
| [cheekhimself/Spider-Farmer-GGS-Controller-MQTT](https://github.com/cheekhimself/Spider-Farmer-GGS-Controller-MQTT) | Verdant helper prototype and current working repository | Planning and future clean-room implementation target |
| [MarcHard-tech/spider-farmer-ggs-ble](https://github.com/MarcHard-tech/spider-farmer-ggs-ble/tree/62c3842f7c058e07ff22847bb547541ad952e416) | Current Home Assistant decoder; v2 framing, whole-message CRC evidence, AES-CBC profile, broad telemetry | Strong FW 3.20 evidence; reimplement facts independently because no recognized license was found |
| [smurfy/esphome-spiderfarmer_ble](https://github.com/smurfy/esphome-spiderfarmer_ble/tree/709c7d296881f2216e37766117688e8aa1dfd818) | ESPHome decoder for CB, PS5, and PS10; plaintext/encrypted framing and product variants | Independent confirmation; GPL code must not be copied here |
| [noheton/Obscurity-Is-Dead](https://github.com/noheton/Obscurity-Is-Dead/tree/3c218e5ff2c29b88b5db932b81e18e3686f3bfe3) | APK analysis and implementation notes; product-selected crypto material and a dynamic receive-IV theory | Candidate-profile evidence only; do not vendor APKs, keys, or code |
| [mullervg/ggs-esp32-mqtt-bridge](https://github.com/mullervg/ggs-esp32-mqtt-bridge/tree/e56f1967fa5c05d048fd35c3758fc9c4a4e37de5) | Framing/CRC documentation, raw/framed JSON support, and runtime-versus-config distinctions | Secondary confirmation and state-semantics input |
| [ilguerro/Spider-Farmer-Home-Assistant](https://github.com/ilguerro/Spider-Farmer-Home-Assistant/tree/9967162503e992faa7183d5cf138d9c0e2f68515) | Read-only integration, MTU behavior, one-central limit, unsolicited cadence, redacted capture tooling | Operational guidance for older plaintext firmware |
| [astrixtech/SpiderFarmerBridge](https://github.com/astrixtech/SpiderFarmerBridge/tree/145ad708e9d8eb303dca5c387bec21be2a9da871) | Read-only ESPHome YAML and plaintext observations | Historical corroboration; substring parsing is too permissive |
| [ascodev/spiderfarmer-ggs-hacs-](https://github.com/ascodev/spiderfarmer-ggs-hacs-) | Small Home Assistant plaintext parser | Historical corroboration; capability claims conflict with newer captures |

### Forks checked for independent protocol evidence

The upstream forks by
[boltandbyte6620](https://github.com/boltandbyte6620/Spider-Farmer-GGS-Controller-MQTT),
[jplatte](https://github.com/jplatte/Spider-Farmer-GGS-Controller-MQTT),
[monotron303](https://github.com/monotron303/Spider-Farmer-GGS-Controller-MQTT), and
[haddock-development](https://github.com/haddock-development/Spider-Farmer-GGS-Controller-MQTT)
did not add a material protocol delta at review time.
[gdtrfb58-hash/Spider-Farmer-GGS-Controller-MQTT](https://github.com/gdtrfb58-hash/Spider-Farmer-GGS-Controller-MQTT)
adds ESP32-S3/logging work but no independently verified payload profile.

### Adjacent non-BLE evidence

| Repository | Relevance | Boundary |
| --- | --- | --- |
| [iceboerg00/spiderfarmer-bridge](https://github.com/iceboerg00/spiderfarmer-bridge/tree/8675ac0898a2b567d154ff125d61ddb89753beab) | Wi-Fi/MQTT proxy with broad CB/PS5/PS10/LC field inventory | Schema evidence only; do not adopt TLS interception |
| [cobragt2000/spider_farmer_bridge](https://github.com/cobragt2000/spider_farmer_bridge/tree/ed2b736f84be53a5b34014041b3b04ac776901c8) | Live-tested heater, humidifier, and dehumidifier state semantics | State-semantics evidence only; not BLE transport evidence |
| [Trixx34/spider_farmer_bridge](https://github.com/Trixx34/spider_farmer_bridge) | Fork of the Wi-Fi proxy | No independent BLE protocol delta found |
| [EddiePiazza/schedule-4-real](https://github.com/EddiePiazza/schedule-4-real) | Product capability inventory and MQTT ingestion patterns | Do not adopt its proxy binary or identical-value disconnection heuristic |
| [kalisalpetermix/schedule-4-real](https://github.com/kalisalpetermix/schedule-4-real) | Fork of schedule-4-real | No independent BLE protocol delta found |
| [1am/spiderfarmer-ha](https://github.com/1am/spiderfarmer-ha) | USB/RS485 Home Assistant path | Hardware fallback only, outside the BLE MVP |
| [1am/spiderwire](https://github.com/1am/spiderwire) | USB/RS485 protocol work | Hardware fallback only, outside the BLE MVP |
| [Weedalf/GrowFan](https://github.com/Weedalf/GrowFan) | Generic fan project returned by broad search | Excluded; not GGS BLE evidence |

Key protocol pointers are the upstream
[encrypted-firmware discussion](https://github.com/cr0ssn0tice/Spider-Farmer-GGS-Controller-MQTT/issues/4),
[v2 firmware report](https://github.com/cr0ssn0tice/Spider-Farmer-GGS-Controller-MQTT/issues/7),
[FW 3.20 protocol module](https://github.com/MarcHard-tech/spider-farmer-ggs-ble/blob/62c3842f7c058e07ff22847bb547541ad952e416/protocol.py),
[ESPHome decoder](https://github.com/smurfy/esphome-spiderfarmer_ble/blob/709c7d296881f2216e37766117688e8aa1dfd818/components/spiderfarmer_ble/spiderfarmer_ble.cpp),
and the independent
[APK BLE analysis](https://github.com/noheton/Obscurity-Is-Dead/blob/3c218e5ff2c29b88b5db932b81e18e3686f3bfe3/experiments/spider-farmer/original/doc/apk_analysis/ble_analysis.md).

## 4. Facts supported by multiple implementations

- The service is `000000ff-0000-1000-8000-00805f9b34fb` (0x00FF).
- Notifications arrive on `0000ff01-0000-1000-8000-00805f9b34fb`.
- App-to-controller writes use `0000ff02-0000-1000-8000-00805f9b34fb`.
- Controllers can emit unsolicited `getDevSta` and `getSysSta` messages, so
  live observation does not require command polling.
- Many framed messages start with `AA AA 00 03` and use a 20-byte inner header.
- Message type 1 has been observed as plaintext; type 2 as encrypted.
- Frames carry chunk offset/length, total payload length, whole-payload checksum,
  and packet checksum.
- GGS controllers generally permit one BLE central at a time.
- Product families include at least CB, PS5, PS10, and LC; payload shapes differ.
- Runtime output and configured target are different facts and must be stored
  separately.

Observed frame interpretation to validate for every profile:

| Bytes | Meaning |
| --- | --- |
| 0-3 | Magic/version marker `AA AA 00 03` |
| 4-5 | Packet/body length field |
| 6-7 | Message type, observed as 1 plaintext or 2 encrypted |
| 8-9 | Whole reassembled payload/ciphertext CRC16 |
| 10-13 | Total payload/ciphertext length |
| 14-17 | Current chunk offset |
| 18-19 | Current chunk length |
| 20..n-3 | Chunk bytes |
| n-2..n-1 | Per-packet CRC16 |

CRC byte order, exact length scope, and message-size bounds belong to a pinned
profile and must be proven by fixtures. Production must not try alternate CRC
interpretations after validation fails.

## 5. Unresolved protocol conflicts

- AES-CBC padding is reported as zero padding in some firmware and PKCS7 in a
  current implementation.
- The receive IV is reported as fixed by one implementation and derived from
  first-fragment header bytes by another analysis.
- Crypto material may be firmware-wide, product-specific, or both.
- Some LC devices reportedly emit direct JSON without the AA/AA frame.
- Older messages can exceed a small default MTU and may truncate.
- Fields vary, including `fan` versus `blower` and climate-device
  enabled-versus-running distinctions.

Auto-detection is therefore unsafe for production. It may run only in explicit
local capture mode. A profile is promotable after at least 10 consecutive
complete messages pass packet CRC, whole-message CRC, decrypt/unpad, strict
UTF-8, JSON schema, and plausibility checks. Production then pins that profile
and fails closed on mismatch.

Candidate receive profiles:

1. Strict direct UTF-8 JSON.
2. Framed type-1 plaintext.
3. Framed type-2 AES-CBC with configured fixed IV and zero padding.
4. Framed type-2 AES-CBC with configured fixed IV and PKCS7 padding.
5. Framed type-2 AES-CBC with capture-supported dynamic receive IV and zero
   padding.

Do not add fallbacks without a redacted hardware capture. Keys and IVs belong in
a local secret store, never in Git, logs, telemetry, fixtures, or documentation.

## 6. Capture runbook

Use only controllers and accounts the operator is authorized to inspect. Review
applicable vendor terms before app analysis.

1. Record advertising-name prefix, controller family, hardware/firmware version,
   pcode, Pi model/OS, Bluetooth adapter, and requested MTU.
2. Stop the official app and other clients; confirm the Pi is the only central.
3. Subscribe to FF01 only. Any attempt to write FF02 must terminate capture.
4. Capture at least 10 unsolicited `getDevSta` and three `getSysSta` messages.
5. Save bounded encrypted bytes locally only when explicitly enabled. Default
   output is length, offset, CRC result, timestamp, method, schema fingerprint,
   and SHA-256 digest.
6. Redact BLE addresses, pid, uid, account IDs, Wi-Fi data, crypto material, and
   full decrypted payloads before committing a fixture.
7. Repeat after reconnect and process restart to prove deterministic profile
   selection, reassembly, and deduplication.
8. If passive notifications are insufficient, capture official-app BLE traffic
   with Android HCI snoop in a lab session. Do not replay command writes.

Never downgrade firmware for capture. Keep raw captures local and follow an
explicit retention policy after the redacted fixture is reviewed.

## 7. Decoder design

Implement small pure modules before service wiring:

```text
advertisement.py       candidate family without exposing MACs
profile_registry.py    explicit product/firmware profiles
frame_codec.py         length, bounds, CRC, and chunk validation
reassembler.py         bounded, timed, non-overlapping assembly
crypto_profile.py      secret-injected decrypt and strict unpadding
message_schema.py      strict UTF-8, JSON, envelope, and field validation
normalizer.py          atomic Verdant observation construction
capture_cli.py         local redacted evidence collection
```

Required properties:

- Reject unknown magic/type, bad length/CRC/offset, overlap, incomplete coverage,
  invalid padding/UTF-8/JSON, unknown envelope, and implausible typed fields.
- Bound packet length, total length, active assemblies, and assembly age.
- Accept duplicate chunks only when bytes are identical; otherwise reject.
- Reassemble ciphertext completely before decrypting once.
- Parse JSON structurally. Never recover data merely by finding braces.
- Keep capture-mode probing out of the production service path.
- Emit no observation until one whole message is validated.

## 8. Verdant observation contract

Publish one atomic observation per validated message. Do not rebuild a snapshot
from independently timed scalar MQTT topics.

```json
{
  "schema_version": 1,
  "provider": "spider_farmer_ggs",
  "controller_id": "sha256:pseudonymous-stable-id",
  "source": "live",
  "captured_at": "2026-08-28T12:00:00Z",
  "device_timestamp": null,
  "tent_id": "required-mapped-tent-id",
  "plant_id": null,
  "confidence": 0.99,
  "quality": { "status": "ok", "reasons": [] },
  "controller": {
    "family": "CB",
    "hardware_version": "redacted-example",
    "firmware_version": "redacted-example",
    "pcode": "redacted-example",
    "protocol_profile": "cb-fw3x-v2-example"
  },
  "metrics": {},
  "equipment_observed": {},
  "configuration_target": null,
  "raw_payload": {
    "storage": "redacted",
    "sha256": "digest-only",
    "method": "getDevSta",
    "schema_fingerprint": "sorted-field-path-digest"
  }
}
```

Contract rules:

- `captured_at` is Pi receive time in UTC; preserve a valid device timestamp
  separately.
- Require explicit controller-to-`tent_id` mapping. `plant_id` is optional.
- Use `source: live` only after transport, schema, plausibility, freshness, and
  mapping checks pass.
- Emit `source: invalid` reason codes for rejected current messages. Mark the
  last accepted observation `stale` when cadence, connection, or timestamps fail.
- Store units with typed metrics and validate temperature, humidity, VPD, CO2,
  PPFD, soil moisture, soil EC, and equipment levels before health evaluation.
- Keep `equipment_observed` separate from `configuration_target`.
- Do not classify repeated identical values as disconnected by themselves.
- `raw_payload` defaults to a sanitized summary and digest, not full decrypted
  vendor data.

## 9. Pi bridge operating boundary

- Request only BLE scan/connect/subscribe permissions.
- Hold a per-adapter/controller lock to prevent duplicate connections.
- Reconnect with capped exponential backoff and jitter.
- Prefer unsolicited notifications; do not poll FF02.
- Publish only to a per-controller telemetry namespace with an MQTT credential
  that cannot publish or subscribe to command topics.
- Use TLS and certificate validation outside an isolated lab.
- Persist only state needed for deduplication and stale recovery.
- Expose payload-free counters for packets, completes, rejects, stale changes,
  reconnects, and dropped observations.
- Stop publishing `live` immediately when the pinned profile stops validating.

## 10. Tests and evidence

Pure tests must cover:

- Known-good direct JSON, framed plaintext, and every capture-proven encrypted
  profile.
- Boundary/invalid lengths and CRCs, gaps, duplicates, conflicts, overlap,
  out-of-order chunks, timeouts, and memory limits.
- Wrong key/IV/profile and invalid padding.
- UTF-8 failures, braces inside strings, escapes, multiple messages, trailing
  bytes, nulls, and deterministic repeats.
- CB/PS5/PS10/LC variants; fan/blower; light/light2; outlets; climate devices;
  air, soil, CO2, and PPFD.
- Runtime/config separation, plausibility, freshness, stale transitions, and
  old/missing fields.
- A hard assertion that the BLE adapter never writes or calls FF02.

Hardware evidence matrix:

| Family | Firmware class | Expected profile | Status |
| --- | --- | --- | --- |
| CB | older plaintext | direct or framed type 1 | Owned-hardware evidence needed |
| CB | around 3.14 | encrypted type 2 | Padding/IV unresolved |
| CB | around 3.20 | encrypted type 2 | Strong public evidence; local capture required |
| PS5 | current owned version | capture-selected | Not validated |
| PS10 | current owned version | capture-selected | Not validated |
| LC | current owned version | direct JSON or variant | Not validated |

Acceptance gates:

- All committed golden packets pass their pinned profile.
- All corrupted/truncated adversarial fixtures fail closed.
- No test, trace, or hardware session writes FF02.
- No secret, MAC, pid, uid, or full decrypted payload appears in Git or logs.
- Restart/reconnect does not duplicate accepted observations.
- Invalid or stale data is never surfaced as healthy/current.

## 11. Delivery phases

### Phase 0: evidence and fixtures

- Capture the user's exact controller and select one profile from evidence.
- Commit only sanitized fixtures and digests.

Exit: 10 consecutive status messages validate without fallback or FF02 writes.

### Phase 1: receive-only codec

- Implement pure frame, reassembly, crypto-profile, schema, and normalizer code.
- Remove command-oriented settings from the Verdant ingestion process.
- Add adversarial and no-write tests.

Exit: focused tests pass with exact counts and review finds no permissive fallback
or secret logging.

### Phase 2: Pi shadow bridge

- Publish one controller to a local debug-only telemetry topic.
- Do not connect shadow data to production decisions, alerts, AI, or Action Queue.
- Compare with the official app for at least 24 hours.

Exit: no invalid-live classifications, no writes, bounded resources, and proven
restart/disconnect behavior.

### Phase 3: Verdant staging ingestion

- Implement the actual sink in the accessible Verdant repository through its
  existing server/admin ingestion boundary.
- Enforce owner/controller/tent mapping and atomic observations.
- Verify database policy behavior with a runtime harness.

Exit: authenticated staging proves users cannot spoof source, ownership,
confidence, or another tent's readings.

### Phase 4: one-tent canary

- Enable one mapped controller for seven days with all control disabled.
- Review source, freshness, units, reconnects, rejects, and an independent sensor.

Exit: signed report with exact observation/reject/stale counts and no safety-rule
violations.

### Phase 5: profile expansion

- Repeat Phases 0-4 for each product family and firmware class.
- Never infer compatibility from an advertising name alone.

## 12. Blockers and next action

The production Verdant app repository was not accessible during this pass, so
the database/API sink, policy checks, and website integration could not be
reviewed or implemented here.

The next action is a receive-only capture from the user's exact controller with
family, hardware version, firmware version, and 10 unsolicited status messages.
That evidence selects the first decoder profile without guessing.

Device commands, app-server command replay, firmware downgrades, automatic
Action Queue creation, and autonomous control are explicitly deferred.
