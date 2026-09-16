# Live Phase 3 COMPLETE FF01 dumps

Provenance: Cheek, Windows G7, Spider Farmer **SF-GGS-CB**, receive-only FF01
listen on **2026-09-16**. Dumped by Phase 3 `ggs_ff00_sniffer.py --dump-frames`
as COMPLETE frames only (observed length == `declared_length + 8`, no leftover,
never padded).

Source archive: `phase3_live_complete_ff01.zip` (45 `NNNN_<bytes>b_len<declared>.hex`
files). Full hex is opaque protocol bytes. **No BLE MACs** are stored.

| Size class | Count | Declared length | Typical nonzero bytes |
| --- | ---: | ---: | --- |
| 422 | 28 | 414 | ~413 / 422 |
| 230 | 6 | 222 | ~220 / 230 |
| 54 | 11 | 46 | ~46 / 54 |

These are **not** the older committed `tests/fixtures/frame_*.hex` files, which
are zero-padded research envelopes and must not be used as CRC / crypto
known-answer truth.

`COMPLETE` still does not mean plaintext, MQTT sensors, or decrypt success.
Phase 4 CRC/reassembly tools consume this directory.
