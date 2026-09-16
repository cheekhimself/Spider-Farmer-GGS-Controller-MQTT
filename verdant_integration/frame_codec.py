"""Fail-closed AA AA 00 03 frame detector (receive-only; no decrypt).

Header layout hypothesis (Cheek, Windows G7, 2026-09-16; 32/32 FRAMED_CANDIDATE):

    offset  size  field
    0-3     4     magic / version-ish  ``AA AA 00 03``
    4-5     2     declared length, big-endian uint16
    6-end         opaque body (not interpreted)

Observed complete sizes were 422, 246, and 230. After the 6-byte header the
declared length was 414, 238, and 222 respectively, which matches:

    total_size = declared_length + 8

The extra two bytes after the 6-byte header are left inside ``payload`` and
are not named (CRC/auth remains unproven). Trailing byte families are not
parsed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass

MAGIC = b"\xaa\xaa\x00\x03"
HEADER_SIZE = 6
# Cheek pin: 0x019E (414) + 8 = 422; 0x00EE (238) + 8 = 246; 0x00DE (222) + 8 = 230.
LENGTH_ENVELOPE = 8
MAX_DECLARED_LENGTH = 2048

ERROR_TOO_SHORT = "too_short"
ERROR_PLAINTEXT_JSON = "plaintext_json"
ERROR_NOT_FRAMED = "not_framed"
ERROR_INVALID_LENGTH = "invalid_length"
ERROR_TRUNCATED = "truncated"


@dataclass(frozen=True)
class FrameParseResult:
    ok: bool
    error: str | None
    length: int | None
    header: bytes
    payload: bytes
    leftover: bytes

    def as_summary(self) -> dict[str, object]:
        """Header/length-only view; payload is never included."""
        return {
            "ok": self.ok,
            "error": self.error,
            "length": self.length,
            "header": self.header.hex(),
            "payload_bytes": len(self.payload),
            "leftover_bytes": len(self.leftover),
        }


class FrameCodec:
    """Detect and slice ``AA AA 00 03`` frames without interpreting crypto."""

    @staticmethod
    def looks_framed(data: bytes | bytearray | memoryview) -> bool:
        buffer = bytes(data)
        return len(buffer) >= len(MAGIC) and buffer[: len(MAGIC)] == MAGIC

    @staticmethod
    def looks_plaintext_json(data: bytes | bytearray | memoryview) -> bool:
        buffer = bytes(data).lstrip()
        return bool(buffer) and buffer[:1] in (b"{", b"[")

    @staticmethod
    def parse(data: bytes | bytearray | memoryview | str) -> FrameParseResult:
        if isinstance(data, str):
            buffer = data.encode("utf-8", errors="surrogateescape")
        else:
            buffer = bytes(data)

        if FrameCodec.looks_plaintext_json(buffer):
            return FrameParseResult(
                ok=False,
                error=ERROR_PLAINTEXT_JSON,
                length=None,
                header=b"",
                payload=b"",
                leftover=b"",
            )

        if len(buffer) < HEADER_SIZE:
            return FrameParseResult(
                ok=False,
                error=ERROR_TOO_SHORT,
                length=None,
                header=buffer,
                payload=b"",
                leftover=b"",
            )

        if not FrameCodec.looks_framed(buffer):
            return FrameParseResult(
                ok=False,
                error=ERROR_NOT_FRAMED,
                length=None,
                header=b"",
                payload=b"",
                leftover=b"",
            )

        declared = int.from_bytes(buffer[4:HEADER_SIZE], "big")
        header = buffer[:HEADER_SIZE]
        if declared < 1 or declared > MAX_DECLARED_LENGTH:
            return FrameParseResult(
                ok=False,
                error=ERROR_INVALID_LENGTH,
                length=declared,
                header=header,
                payload=b"",
                leftover=b"",
            )

        total = declared + LENGTH_ENVELOPE
        if len(buffer) < total:
            return FrameParseResult(
                ok=False,
                error=ERROR_TRUNCATED,
                length=declared,
                header=header,
                payload=b"",
                leftover=b"",
            )

        return FrameParseResult(
            ok=True,
            error=None,
            length=declared,
            header=header,
            payload=buffer[HEADER_SIZE:total],
            leftover=buffer[total:],
        )


def _load_hex(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit("hex input is not valid.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse AA AA 00 03 frame header/length only (no decrypt)."
    )
    parser.add_argument(
        "--hex",
        help="Hex bytes of one buffer. Reads stdin when omitted.",
    )
    args = parser.parse_args(argv)
    source = args.hex if args.hex is not None else sys.stdin.read()
    result = FrameCodec.parse(_load_hex(source))
    print(json.dumps(result.as_summary(), separators=(",", ":"), sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
