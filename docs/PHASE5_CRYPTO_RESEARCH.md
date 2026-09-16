# Phase 5 — honest crypto research on reassembled opaque candidates

Status: research + fail-closed trial harness. **No live decrypt success.
No vendor keys or IVs in git. No MQTT. No ESP32. No FF02 writes.**

Stacks on Phase 4: 45 COMPLETE live FF01 dumps, trailer CRC-16/MODBUS,
message CRC of tiled chunks, 17 opaque assemblies (11×832, 6×608).

Operator commands (receive-only analysis):

```bash
python3 -m verdant_integration.reassembly --dir tests/fixtures/live_phase3
python3 -m verdant_integration.crypto_research --dir tests/fixtures/live_phase3
```

`claimed_success` stays false unless `trial_decrypt` is given both operator
key/IV bytes **and** a known-plaintext fixture that equals the recovered
output. Environment variables `SF_GGS_AES_KEY_HEX` / `SF_GGS_AES_IV_HEX` are
the only key path; they are unset in this repo.

## Proven (do not regress)

| Claim | Evidence | Label |
| --- | --- | --- |
| Trailer CRC-16/MODBUS BE over `frame[:-2]` | Phase 4, 45/45 | **PROVEN** |
| Bytes 8–9 = CRC-16/MODBUS of tiled chunks | Phase 4, 17/17 | **PROVEN** |
| Reassembly 11×832 (`400+400+32`), 6×608 (`400+208`) | Phase 4 | **PROVEN** |
| Type field `00 02` on every live frame | Phase 4 | **PROVEN** (value only) |
| Assembly lengths are AES-block aligned (`len % 16 == 0`) | 17/17 | **PROVEN** |
| Shannon entropy of assemblies ≈ 7.65–7.79 bits/byte | 17/17 | **PROVEN** (ciphertext-compatible) |
| Within each size class, the first **80** bytes are identical (5 AES blocks), then later blocks avalanche | 11/11 of 832; 6/6 of 608 | **PROVEN** |
| First AES block is constant per size class and **differs** between 832 and 608 | 2 distinct prefixes | **PROVEN** |
| Issue #4 public 21-byte sample `8faabc89…fc8243` is the prefix of every **832** assembly | 11/11; not the 608 class | **PROVEN** |
| `claimed_decrypt` / `claimed_plaintext` remain false on reassembly | Phase 4 tests | **PROVEN** |

One 832 pair differs **only** in the last 16-byte block (816/832 equal). That
is what CBC (or ECB) looks like when 51 plaintext blocks match and the last
block changes. It is not a decrypt.

## Hypotheses tested

| Hypothesis | What we did | Label |
| --- | --- | --- |
| Type `00 02` means “AES-encrypted profile” | Public notes (Phase 2, GitHub issue #4 on the upstream MQTT repo). Consistent with opaque high-entropy bodies; **not** a decrypt proof | **BLOCKED** as a semantic claim; structurally compatible |
| Static repeating XOR (issue #4 sniffer) | Crib `{"method":"getDevSta"` against assembly[0] recovers that crib by construction; applying the 21-byte stream as a repeating key produces non-JSON immediately after 21 bytes (`jt\\x10…`). Same failure with period 16. 1am already reported `{"method":"getDe%rg` | **FAIL** |
| “Different XOR key per method” | 832 vs 608 prefixes differ, so a crib-derived stream differs — expected if **plaintext prefixes** differ (`getDevSta` vs `getSysSta`) under one AES key. Does not prove two XOR keys | **FAIL** as a crypto profile |
| AES-CTR / static keystream | After the 80-byte shared prefix, pairwise XOR of same-size assemblies is high-entropy (~7.2–7.4 bits/byte) with only accidental equal bytes. Similar JSON under a reused keystream would leak structure | **FAIL** for a static keystream |
| AES-ECB with repeated plaintext blocks | No duplicate 16-byte ciphertext blocks inside any assembly (0/17). Does not rule out ECB if JSON never repeats a 16-byte block | **FAIL** as an ECB detection; ECB still **BLOCKED** without a key |
| AES-CBC with a **fixed** IV (public APK/HA notes) | Shared 5-block prefix then avalanche; last-block-only twin; lengths multiple of 16. Matches CBC with a constant IV and a stable JSON header. Public write-ups name AES-128-CBC + PKCS7 over **reassembled** chunks with APK literals — **those literals are not in this repo and were not recovered** | Compatible structure **PROVEN**; algorithm+key **BLOCKED** |
| AES-CBC/ECB/CTR with trivial keys (`00…` / `ff…`) | Stdlib `cryptography` decrypt; PKCS7 invalid; output not JSON | **FAIL** |
| AES with invented or guessed APK ASCII keys | Hard stop: not tested, not committed | refused |
| Header-derived receive IV (16 bytes after offset 6) | Inner header is 20 bytes of layout fields (type, CRCs, lengths). No extra 16-byte IV field. First 16 bytes of the **chunk** are ciphertext, constant per class | **FAIL** as in-header IV |
| First 16 assembly bytes are a per-message IV | They are identical for all messages of a class, so they cannot be a unique per-packet IV. Treating them as a static in-band IV is equivalent to an APK literal and still needs the key | **BLOCKED** |
| PKCS7 padding on live ciphertext | Cannot check without a correct AES key. Last-block-only twin is compatible with padding or a last JSON field changing | **BLOCKED** |
| RSA (`sha256WithRSAEncryption` note on issue #4) | 608/832-byte payloads are not RSA-sized ciphertext blobs in the usual 256-byte module sense; issue discussion already discarded RSA because the prefix is static | **FAIL** on these assemblies |
| Pairing-derived session keys | This capture is FF01 listen-only; no pairing transcript | **BLOCKED** |
| Public Spider Farmer APK dump in-tree | Not present. Play-store / Flutter apps are not vendored. Certificates used by cloud MQTT MITM projects are a different channel (TLS to `sf.mqtt.spider-farmer.com`), not this BLE frame | **BLOCKED** |

Public sources consulted (no keys copied):

- This repo’s Phase 2 notes: AES-128-CBC + PKCS7 over reassembled ciphertext, key/IV as vendor-app literals, CRC-16/MODBUS trailer (unverified until now for CRC; still unverified for AES key).
- [cr0ssn0tice issue #4](https://github.com/cr0ssn0tice/Spider-Farmer-GGS-Controller-MQTT/issues/4) — firmware ~3.14 obfuscation, XOR experiment, `getDevSta` / `getSysSta` cribs, incomplete recovery.
- Upstream README (older firmware): plaintext JSON `getDevSta` on FF01 — **not** what Cheek’s live COMPLETE dumps contain.
- Community TLS MITM bridges (SpiderBridge / Trixx34) decode **cloud MQTT**, not these BLE assemblies.

## Harness contract

`verdant_integration.crypto_research.trial_decrypt`:

1. Default: no key, no IV → `claimed_success=false`, reason includes
   `unproven_crypto_profile`.
2. Key/IV accepted only as arguments or `SF_GGS_AES_KEY_HEX` /
   `SF_GGS_AES_IV_HEX` (operator machine, never git).
3. `claimed_success=true` **only** when `known_good_plaintext` is provided and
   equals the PKCS7-unpadded recovery. “Looks like JSON” is not enough.
4. Unit tests prove the true path with an isolated AES test vector
   (`bytes(range(16))`, not a vendor secret) and prove live dumps stay false.

`payload_inspect.attempt_framed_decrypt` still refuses a **single** frame
(incomplete candidate).

## What would unlock a real decrypt (none satisfied)

1. **APK dump** of the current Spider Farmer app: strings / `SecretKeySpec` /
   Dart `encrypt` literals for BLE (not cloud TLS certs). Trial those bytes
   via env vars against these 17 assemblies.
2. **Pairing or write-path capture** (FF02) that shows key agreement. This
   zip is FF01 notifications only.
3. **Older-firmware plaintext** `getDevSta` from the **same** controller
   generation as a known-answer document, **or** an app-side decode log that
   matches one of these message-CRC groups.
4. A passing `trial_decrypt(..., known_good_plaintext=fixture)` on a live
   832- or 608-byte body. Then commit a **sanitized** plaintext fixture
   (no MACs, no operator PII) and set `claimed_decrypt` only behind that test.

Until then MQTT / Verdant live `temp` / `humi` / `vpd` mapping stays blocked.

## Non-goals (this PR)

- No invented keys or IVs
- No fake LIVE MQTT
- No FF02 / `setLight` / ESP32 crypto port
- No merge to `main`
