# Phase 2 — framed payload inspect (crypto research)

Status: research + scaffolding. **No decrypt success is claimed.**
Pin: Cheek live FF01 on SF-GGS-CB, Windows G7, 2026-09-16 (Phase 0/1), plus
size-class 390 observed on the same unit.

This slice does **not** implement MQTT, FF02 writes, ESP32 crypto, or live
sensor mapping.

## 1. What is already proven (do not re-litigate)

From Phase 1 `frame_codec` and Cheek capture:

| Fact | Evidence |
| --- | --- |
| Every observed FF01 buffer starts `AA AA 00 03` | 32/32 `FRAMED_CANDIDATE` |
| Bytes 4–5 are big-endian declared length | `01 9e` / `00 ee` / `00 de` (and 390-class `01 7e`) |
| `total_size = declared_length + 8` | 422, 246, 230, 390 |
| Live sizes | **422** (len 414), **390** (len 382), **230** (len 222); earlier also **246** (len 238) |
| Plaintext `getDevSta` | **0** on this unit |
| Stock JSON / ESP32 brace parser | remains blocked; do not teach it binary |

Header through offset 5 is the only **codec-owned** layout. Everything after
the 6-byte header is opaque until proven.

## 2. Candidate bytes after the 6-byte header

Public third-party notes (PR #2 ledger; treat as **unverified** until fixtures
prove them) describe a 20-byte inner header from the start of the packet:

| Offset | Size | Candidate (hypothesis only) | Proven on Cheek fixtures? |
| --- | --- | --- | --- |
| 0–3 | 4 | magic `AA AA 00 03` | **yes** |
| 4–5 | 2 | declared length (BE) | **yes** |
| 6–7 | 2 | type / protocol version; `00 02` = encrypted profile in public notes | **consistent** (`00 02` on 422/246/230 prefixes); not proven to mean AES |
| 8–9 | 2 | public notes: CRC16/MODBUS of **whole assembled ciphertext** (not a session counter, not an IV) | **not proven** (no full live ciphertext) |
| 10–13 | 4 | total ciphertext length (BE) | **structurally consistent** on 422+246 (`400+224=624`) |
| 14–17 | 4 | chunk offset (BE) | **structurally consistent** (0 then 400) |
| 18–19 | 2 | chunk length (BE) | **yes as arithmetic**: `20 + chunk + 2 == total` on 422/246/230 |
| 20 … 20+N−1 | N | opaque chunk / ciphertext candidate | **not proven ciphertext** — committed bodies are mostly `00` pads |
| last 2 | 2 | public notes: per-packet CRC16/MODBUS over header+chunk | **not proven** — padded fixtures end `00 00` |

IV candidate: public AES-CBC write-ups place a **fixed 16-byte IV outside the
frame** (vendor APK literal), while a separate APK note theorizes a
header-derived receive IV. **Neither IV layout is identifiable in these
fixtures.** There is no 16-byte high-entropy field after the 6-byte header.

Counter candidate: none of the inner fields monotonically increment across the
three prefixes in a way we can pin. Bytes 8–9 are shared by the 422 and 246
prefixes (`f19f`) which matches “whole-message checksum,” not a packet counter.

## 3. What the committed hex fixtures are

| File | Total | Declared | Provenance |
| --- | --- | --- | --- |
| `tests/fixtures/frame_422.hex` | 422 | 414 | Phase 1 redacted Cheek prefix, **zero-padded** body |
| `tests/fixtures/frame_246.hex` | 246 | 238 | Same; earlier size class |
| `tests/fixtures/frame_230.hex` | 230 | 222 | Same |
| `tests/fixtures/frame_390.hex` | 390 | 382 | Phase 2 **synthetic size-class** envelope (`01 7e`); live 390 was observed but **no redacted body prefix was retained** — inner CRC/chunk bytes are structural placeholders, not a live capture |

No MACs, BLE addresses, APK keys, IVs, or plaintext telemetry are stored.

Shannon entropy of the padded bodies is ~0.3–0.5 bits/byte (almost all zeros).
That is **incompatible** with live AES ciphertext. Do not treat these files as
crypto known-answer tests.

## 4. Crypto profile — research notes, not a working decrypt

A public Home Assistant decoder describes **AES-128-CBC + PKCS7** over the
**reassembled** ciphertext, with key/IV as **fixed APK literals**, and
CRC16/MODBUS on the trailer. PR #2 already flagged padding and IV conflicts.
**This repository does not copy keys, IVs, or that decoder.**

Key material that would be required **if** that profile is later proven on
Cheek hardware (do not invent, do not commit):

1. **AES-128 key** — public notes say a static vendor-app literal, possibly
   product-selected. Could also be firmware-wide. **Not** observed as pairing
   output on FF01 in our captures (pairing was not exercised).
2. **IV** — either a second static APK literal (CBC, never rotating) or derived
   from first-fragment header bytes. Fixtures cannot distinguish these.
3. **Known-good plaintext** — a `getDevSta` JSON document matching a full
   reassembled ciphertext. **None exists in this repo.**

Until (a) unpadded live frames pass trailer CRC, (b) a complete reassembly
exists, and (c) decrypt output matches a committed known-good plaintext
fixture, any decrypt API **must refuse** and must set `claimed_success=false`.

`payload_inspect.attempt_framed_decrypt` is that fail-closed stub. It does not
accept key bytes.

## 5. Inspector contract (implemented)

`verdant_integration/payload_inspect.py`:

- Reuses `FrameCodec.parse` (no second length parser).
- Splits 6-byte header vs opaque body.
- Reports body length, Shannon entropy, unique-byte count, zero fraction,
  optional 16-byte hex prefix/suffix.
- Emits inner-header field **guesses** only under `hypotheses` with
  `label=hypothesis_only`.
- Decrypt stub always refuses without a known-good plaintext proof.

## 6. Non-goals (this PR)

- No FF02 / `ggs_console` / `setLight`
- No MQTT / ESP32 firmware crypto port
- No claim of LIVE sensors
- No merge of PR #4
- No AES keys in git

## 7. Next gate (Phase 3 MQTT only if decode succeeds)

Capture **unpadded** full FF01 frames for 422/390/230 (redact MACs). Prove
trailer CRC on live bytes. Reassemble chunks until `offset+chunk == total`.
Only then introduce a decrypt path gated on a known-good plaintext fixture.
MQTT / Verdant live mapping stays blocked until that plaintext is `getDevSta`
with finite `temp/humi/vpd`.
