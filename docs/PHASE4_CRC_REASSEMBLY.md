# Phase 4 — CRC and chunk reassembly (live COMPLETE dumps)

Status: analysis + fail-closed helpers. **No decrypt success, no AES keys, no
MQTT, no ESP32, no live sensor claims.** Stacks on Phase 3 COMPLETE dumps.

Primary evidence: `tests/fixtures/live_phase3/` — 45 live COMPLETE FF01 hex
dumps from Cheek’s SF-GGS-CB (G7, ~2026-09-16). Counts: **28×422**, **11×54**,
**6×230**. Bodies are high-entropy (nonzero ≈ 413/422, 46/54, 220/230), unlike
the older zero-padded `tests/fixtures/frame_*.hex` research files.

## What is proven

| Claim | Evidence |
| --- | --- |
| Envelope `total = declared_length + 8` | Phase 1; all 45 live files parse COMPLETE |
| Declared length = bytes after the 6-byte header **excluding** the 2-byte trailer | 414+8=422, 222+8=230, 46+8=54; inner `20 + chunk + 2 = total` on 45/45 |
| Inner layout `20-byte header + chunk + 2-byte trailer` | Arithmetic on every live frame |
| Fields: type u16be @6, message CRC @8–9, total u32be @10, offset u32be @14, chunk len u16be @18 | Consistent across 45 frames; type observed `00 02` |
| **Per-frame trailer = CRC-16/MODBUS (BE) over `frame[:-2]`** | **45/45 PASS**; padded fixtures FAIL (do not treat them as CRC truth) |
| **Bytes 8–9 = CRC-16/MODBUS (BE) of assembled ciphertext chunks** | **17/17 messages PASS** |
| Capture groups tile without gaps | 11 messages of 832 bytes as `400+400+32`; 6 messages of 608 bytes as `400+208` |

Operator classify (proven trailer rule only):

```bash
python3 -m verdant_integration.frame_crc --dir tests/fixtures/live_phase3
python3 -m verdant_integration.reassembly --dir tests/fixtures/live_phase3
```

Exit `0` from `frame_crc --dir` only when every `*.hex` is COMPLETE and the
MODBUS trailer matches. A mismatch is `crc_mismatch` — never repaired by padding.

## What remains hypothesis

| Item | Status |
| --- | --- |
| Type `00 02` means “AES-encrypted profile” | Observed value only; **not** a decrypt proof |
| Chunk bytes are AES-CBC ciphertext | Entropy is compatible with ciphertext (~7.4 bits/byte on a 422-class dump) but **no key/IV/plaintext fixture** |
| IV / key location | Still not in-frame as a 16-byte field; do not invent APK literals |
| Other CRC polynomials (XMODEM, CCITT-FALSE, CRC-32 last-4, XOR) | **FAIL** on live trailers; rejected |
| Grouping by bytes 8–9 | Unique on this capture (17 groups). A CRC-16 collision would fail closed on overlapping byte conflicts |
| 390 / 246 size classes | **Not present** in this live zip; do not infer CRC from padded placeholders |

## Reassembly contract (fail-closed)

`verdant_integration.reassembly.reassemble_group`:

1. Every input buffer must be COMPLETE (Phase 3) and pass the proven trailer CRC.
2. Inner `20 + chunk_len + 2` must equal the frame length; offsets must fit `total`.
3. Chunks must tile `0 .. total-1`. Gaps → no candidate. Overlap with different bytes → fail.
4. CRC-16/MODBUS of the tiled body must equal bytes 8–9.
5. On success, emit **opaque assembled bytes** with `claimed_plaintext=false` and
   `claimed_decrypt=false`. Incomplete groups emit nothing.

This is a ciphertext candidate only.

## What would unlock plaintext / decrypt (still not done)

All of the following, and none of them are satisfied here:

1. A capture-proven crypto profile (algorithm, key, IV) demonstrated on **these**
   live bytes — not copied from unverified notes and **not invented**.
2. A known-good plaintext fixture that matches decrypt output of a full
   reassembled candidate (for example a `getDevSta` JSON document).
3. `attempt_framed_decrypt` remaining fail-closed until (1) and (2) are true.

MQTT / Verdant live mapping stays blocked until plaintext is actually `getDevSta`
with finite `temp` / `humi` / `vpd` from a proven decrypt — which this phase
does not perform.
