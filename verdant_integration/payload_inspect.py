"""Fail-closed inspect of AA AA 00 03 bodies (no decrypt success).

Inner-header field names are hypotheses. See docs/PHASE2_FRAMED_PAYLOAD_INSPECT.md.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from verdant_integration.crc16 import crc16_modbus
from verdant_integration.frame_codec import FrameCodec, FrameParseResult

# Public notes describe a 20-byte packet header from offset 0. Unproven as spec.
HYPOTHESIZED_INNER_HEADER_SIZE = 20
HYPOTHESIZED_TRAILER_SIZE = 2
PREVIEW_BYTES = 16

DECRYPT_REFUSED = "unproven_crypto_profile"
DECRYPT_NO_PLAINTEXT_FIXTURE = "no_known_good_plaintext_fixture"


@dataclass(frozen=True)
class BodyStats:
    length: int
    shannon_entropy_bits: float
    unique_bytes: int
    zero_fraction: float
    prefix_hex: str
    suffix_hex: str


@dataclass(frozen=True)
class DecryptAttempt:
    ok: bool
    claimed_success: bool
    reason: str
    known_good_plaintext_provided: bool
    profile_note: str

    def as_summary(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "claimed_success": self.claimed_success,
            "reason": self.reason,
            "known_good_plaintext_provided": self.known_good_plaintext_provided,
            "profile_note": self.profile_note,
        }


def shannon_entropy_bits(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def body_stats(body: bytes) -> BodyStats:
    preview = min(PREVIEW_BYTES, len(body))
    zeros = body.count(0)
    fraction = (zeros / len(body)) if body else 0.0
    return BodyStats(
        length=len(body),
        shannon_entropy_bits=round(shannon_entropy_bits(body), 4),
        unique_bytes=len(set(body)),
        zero_fraction=round(fraction, 4),
        prefix_hex=body[:preview].hex(),
        suffix_hex=body[-preview:].hex() if preview else "",
    )


def hypothesized_inner_fields(buffer: bytes) -> dict[str, object] | None:
    """Guess 20-byte inner header fields. Never treat output as proven layout."""
    if len(buffer) < HYPOTHESIZED_INNER_HEADER_SIZE + HYPOTHESIZED_TRAILER_SIZE:
        return None

    chunk_length = int.from_bytes(buffer[18:20], "big")
    total = len(buffer)
    layout_consistent = (
        HYPOTHESIZED_INNER_HEADER_SIZE + chunk_length + HYPOTHESIZED_TRAILER_SIZE
        == total
    )
    covered = HYPOTHESIZED_INNER_HEADER_SIZE + chunk_length
    trailer = buffer[covered : covered + HYPOTHESIZED_TRAILER_SIZE] if layout_consistent else b""
    trailer_crc_matches = False
    if layout_consistent and len(trailer) == HYPOTHESIZED_TRAILER_SIZE:
        expected = crc16_modbus(buffer[:covered])
        trailer_crc_matches = expected == int.from_bytes(trailer, "big")

    chunk = (
        buffer[HYPOTHESIZED_INNER_HEADER_SIZE:covered] if layout_consistent else b""
    )
    return {
        "label": "hypothesis_only",
        "inner_header_size": HYPOTHESIZED_INNER_HEADER_SIZE,
        "message_type_u16be": int.from_bytes(buffer[6:8], "big"),
        "bytes_8_9_hex": buffer[8:10].hex(),
        "total_ciphertext_u32be": int.from_bytes(buffer[10:14], "big"),
        "chunk_offset_u32be": int.from_bytes(buffer[14:18], "big"),
        "chunk_length_u16be": chunk_length,
        "layout_consistent": layout_consistent,
        "chunk_length_mod_16": (chunk_length % 16) if layout_consistent else None,
        "trailing_u16_hex": trailer.hex() if trailer else None,
        "trailer_crc16_modbus_matches": trailer_crc_matches,
        "chunk_prefix_hex": chunk[:PREVIEW_BYTES].hex() if chunk else "",
        "notes": [
            "type 2 is encrypted in public notes; not proven AES on these fixtures",
            "bytes 8-9 are CRC-16/MODBUS of assembled chunks on live dumps",
            "IV is not present as a 16-byte field in this hypothesized header",
            "live COMPLETE dumps pass trailer CRC-16/MODBUS; padded fixtures must fail",
        ],
    }


def inspect_frame(data: bytes | bytearray | memoryview | str) -> dict[str, object]:
    parsed: FrameParseResult = FrameCodec.parse(data)
    if isinstance(data, str):
        buffer = data.encode("utf-8", errors="surrogateescape")
    else:
        buffer = bytes(data)

    if not parsed.ok:
        stats = body_stats(b"")
        return {
            "ok": False,
            "error": parsed.error,
            "header": parsed.header.hex(),
            "body_bytes": 0,
            "leftover_bytes": 0,
            "declared_length": parsed.length,
            "stats": {
                "length": stats.length,
                "shannon_entropy_bits": stats.shannon_entropy_bits,
                "unique_bytes": stats.unique_bytes,
                "zero_fraction": stats.zero_fraction,
                "prefix_hex": stats.prefix_hex,
                "suffix_hex": stats.suffix_hex,
            },
            "hypotheses": None,
        }

    total = (parsed.length or 0) + 8
    frame = buffer[:total]
    stats = body_stats(parsed.payload)
    return {
        "ok": True,
        "error": None,
        "header": parsed.header.hex(),
        "body_bytes": len(parsed.payload),
        "leftover_bytes": len(parsed.leftover),
        "declared_length": parsed.length,
        "stats": {
            "length": stats.length,
            "shannon_entropy_bits": stats.shannon_entropy_bits,
            "unique_bytes": stats.unique_bytes,
            "zero_fraction": stats.zero_fraction,
            "prefix_hex": stats.prefix_hex,
            "suffix_hex": stats.suffix_hex,
        },
        "hypotheses": hypothesized_inner_fields(frame),
    }


def attempt_framed_decrypt(
    data: bytes | bytearray | memoryview | str,
    known_good_plaintext: bytes | None = None,
) -> DecryptAttempt:
    """Refuse AES/CBC decrypt. Keys are not accepted and success is never claimed.

    A later Phase may decrypt only when a capture-proven profile exists and
    ``known_good_plaintext`` matches the output. This stub stops before that.
    """
    parsed = FrameCodec.parse(data)
    if not parsed.ok:
        return DecryptAttempt(
            ok=False,
            claimed_success=False,
            reason=parsed.error or DECRYPT_REFUSED,
            known_good_plaintext_provided=known_good_plaintext is not None,
            profile_note="aes-128-cbc-pkcs7 remains an unverified research note",
        )
    if known_good_plaintext is None:
        reason = f"{DECRYPT_REFUSED}:{DECRYPT_NO_PLAINTEXT_FIXTURE}"
    else:
        reason = f"{DECRYPT_REFUSED}:plaintext_fixture_not_sufficient_without_proven_key_iv"
    return DecryptAttempt(
        ok=False,
        claimed_success=False,
        reason=reason,
        known_good_plaintext_provided=known_good_plaintext is not None,
        profile_note=(
            "Candidate profile from public notes: AES-128-CBC / PKCS7 over "
            "reassembled ciphertext, key+IV as vendor-app literals (not in this "
            "repo; do not commit). IV layout is not visible in Cheek fixtures. "
            "Pairing-derived session keys were not observed."
        ),
    )


def _load_hex(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit("hex input is not valid.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect AA AA 00 03 body stats (hypotheses only; no decrypt)."
    )
    parser.add_argument(
        "--hex",
        help="Hex bytes of one buffer. Reads stdin when omitted.",
    )
    parser.add_argument(
        "--attempt-decrypt",
        action="store_true",
        help="Also print the fail-closed decrypt stub result (always refuses).",
    )
    args = parser.parse_args(argv)
    source = args.hex if args.hex is not None else sys.stdin.read()
    buffer = _load_hex(source)
    report = inspect_frame(buffer)
    if args.attempt_decrypt:
        report = {
            **report,
            "decrypt": attempt_framed_decrypt(buffer).as_summary(),
        }
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
