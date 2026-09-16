# Phase 3 — complete unpadded FF01 frame dumps

Status: capture tooling only. **No decrypt, no MQTT, no ESP32 flash, no live
sensor claims.** Stacks on Phase 1 `frame_codec` and Phase 2 `payload_inspect`.

Cheek live pin (do not invent otherwise): SF-GGS-CB, FF01 notifications only,
header `aa aa 00 03`, size classes ~422 / 246 / 230 (and 390). Plaintext
`getDevSta` is dead on this unit. Prior committed fixtures were often
**zero-padded** and must not be used as crypto known-answer tests.

## What COMPLETE means (Phase 4 gate)

`COMPLETE` = one FF01 notification whose **observed byte length** equals
`declared_length + 8` (Phase 1 envelope) with **no leftover bytes**.

| Flag | Meaning | Dumped? |
| --- | --- | --- |
| `COMPLETE` | Length matches declared size exactly | yes, full hex, if `--dump-frames DIR` |
| `TRUNCATED` | Header/length parse, buffer shorter than declared size | **never** (do not pad) |
| `OVERSIZED` | Buffer longer than declared size | **never** (do not guess a slice as the live frame) |
| `PLAINTEXT` | Buffer looks like JSON | **never** |
| `UNKNOWN` | Not framed, too short for a header, or invalid length field | **never** |

`COMPLETE` is **not** CRC-proven, **not** a reassembled ciphertext, and **not**
plaintext. Phase 4 still has to prove trailer CRC, chunk reassembly, and a
known-good plaintext fixture from **live** COMPLETE dumps.

Each BLE notification is classified independently. Notifications are **not**
concatenated. If the stack delivers a 422-byte envelope as two ATT callbacks,
both will be `TRUNCATED`/`UNKNOWN` — raise MTU / adapter limits rather than
guessing missing bytes.

## Windows (receive-only listen)

From the repo root, Python 3.11+ with `bleak`:

```bat
python3 ggs_ff00_sniffer.py --listen-seconds 60 --dump-frames dumps\ff01
```

Optional scan knobs: `--scan-attempts 3 --scan-seconds 3`.

Behavior:

- Scans for exact BLE name `SF-GGS-CB`.
- Subscribes **FF01 only**. Never writes FF02. Never prints or stores BLE MACs.
- Prints completeness + header/length per notification (not truncated body prefixes).
- Writes `NNNN_<bytes>b_len<declared>.hex` **only** for `COMPLETE` frames.
- Stop line: `COMPLETE / TRUNCATED / PLAINTEXT / UNKNOWN` (plus `OVERSIZED`).

Offline classify of one hex blob (no BLE):

```bat
python3 -m verdant_integration.frame_dump --hex-file tests\fixtures\frame_422.hex --dump-frames dumps\check
```

`--hex` / `--hex-file` / stdin is the buffer. Exit `0` only when completeness is `COMPLETE`. The committed size-class fixtures can be `COMPLETE` by **length** while still being zero-padded research files. Live COMPLETE dumps used for Phase 4 CRC/reassembly are in `tests/fixtures/live_phase3/` (`docs/PHASE4_CRC_REASSEMBLY.md`).

## Non-goals

- No AES keys, IV, or claimed decrypt
- No MQTT publish / Home Assistant YAML
- No ESP32 firmware changes
- No FF02 / `setLight` writes
