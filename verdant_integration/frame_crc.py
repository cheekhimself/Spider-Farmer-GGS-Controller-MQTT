"""Fail-closed CRC classification for COMPLETE AA AA 00 03 frames.

Proven on Cheek live COMPLETE dumps (2026-09-16, 45 frames / 3 size classes):

* Per-frame trailer: CRC-16/MODBUS, big-endian, over ``frame[:-2]``,
  equals the last two bytes.
* Message field at bytes 8–9: CRC-16/MODBUS, big-endian, over the
  concatenated ciphertext chunks (see ``reassembly``).

Mismatched CRC is always a failure. Truncated buffers are never padded.
This module does not decrypt and does not claim plaintext or MQTT sensors.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from verdant_integration.crc16 import crc16_modbus, crc16_modbus_be_bytes
from verdant_integration.frame_dump import (
    COMPLETENESS_COMPLETE,
    inspect_notification,
)

TRAILER_SIZE = 2
MESSAGE_CRC_OFFSET = 8
MESSAGE_CRC_SIZE = 2

HYPOTHESIS_PER_FRAME_MODBUS = "crc16_modbus_be_over_frame_excluding_last_2"
HYPOTHESIS_XMODEM_TRAILER = "crc16_xmodem_be_over_frame_excluding_last_2"
HYPOTHESIS_CCITT_TRAILER = "crc16_ccitt_false_be_over_frame_excluding_last_2"
HYPOTHESIS_CRC32_LAST4 = "crc32_iso_hdlc_be_over_frame_excluding_last_4"
HYPOTHESIS_XOR_LAST_BYTE = "xor_all_but_last_equals_last_byte"

PROVEN_HYPOTHESES = frozenset({HYPOTHESIS_PER_FRAME_MODBUS})


@dataclass(frozen=True)
class HypothesisResult:
    name: str
    status: str
    proven: bool
    detail: str

    def as_summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "proven": self.proven,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class FrameCrcResult:
    ok: bool
    error: str | None
    completeness: str
    observed_bytes: int
    expected_crc_hex: str | None
    actual_trailer_hex: str | None
    hypotheses: tuple[HypothesisResult, ...]

    def as_summary(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "error": self.error,
            "completeness": self.completeness,
            "observed_bytes": self.observed_bytes,
            "expected_crc_hex": self.expected_crc_hex,
            "actual_trailer_hex": self.actual_trailer_hex,
            "proven_rule": HYPOTHESIS_PER_FRAME_MODBUS,
            "hypotheses": [item.as_summary() for item in self.hypotheses],
        }


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def _crc16_xmodem(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _crc32_iso_hdlc(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF


def evaluate_trailer_hypotheses(frame: bytes) -> tuple[HypothesisResult, ...]:
    """PASS/FAIL each trailer hypothesis. Only MODBUS-over-[:-2] is proven."""
    if len(frame) < TRAILER_SIZE:
        empty = HypothesisResult(
            name=HYPOTHESIS_PER_FRAME_MODBUS,
            status="FAIL",
            proven=True,
            detail="frame shorter than a 2-byte trailer",
        )
        return (empty,)

    covered = frame[:-TRAILER_SIZE]
    trailer = frame[-TRAILER_SIZE:]
    trailer_int = int.from_bytes(trailer, "big")
    modbus = crc16_modbus(covered)
    xmodem = _crc16_xmodem(covered)
    ccitt = _crc16_ccitt_false(covered)
    xor_last = 0
    for byte in covered:
        xor_last ^= byte
    xor_ok = len(frame) >= 1 and (xor_last & 0xFF) == frame[-1]

    crc32_ok = False
    crc32_detail = "need at least 4-byte trailer candidate"
    if len(frame) >= 4:
        body = frame[:-4]
        digest = _crc32_iso_hdlc(body)
        last4 = int.from_bytes(frame[-4:], "big")
        crc32_ok = digest == last4
        crc32_detail = f"computed={digest:08x} last4={last4:08x}"

    return (
        HypothesisResult(
            name=HYPOTHESIS_PER_FRAME_MODBUS,
            status=_status(modbus == trailer_int),
            proven=True,
            detail=f"computed={modbus:04x} trailer={trailer.hex()}",
        ),
        HypothesisResult(
            name=HYPOTHESIS_XMODEM_TRAILER,
            status=_status(xmodem == trailer_int),
            proven=False,
            detail=f"computed={xmodem:04x} trailer={trailer.hex()}",
        ),
        HypothesisResult(
            name=HYPOTHESIS_CCITT_TRAILER,
            status=_status(ccitt == trailer_int),
            proven=False,
            detail=f"computed={ccitt:04x} trailer={trailer.hex()}",
        ),
        HypothesisResult(
            name=HYPOTHESIS_CRC32_LAST4,
            status=_status(crc32_ok),
            proven=False,
            detail=crc32_detail,
        ),
        HypothesisResult(
            name=HYPOTHESIS_XOR_LAST_BYTE,
            status=_status(xor_ok),
            proven=False,
            detail=f"xor={xor_last & 0xFF:02x} last={frame[-1]:02x}",
        ),
    )


def check_complete_frame_crc(
    data: bytes | bytearray | memoryview | str,
) -> FrameCrcResult:
    """Classify completeness then apply the proven trailer CRC rule.

    Never pads. ``ok`` is true only for COMPLETE frames whose trailer matches
    CRC-16/MODBUS over ``frame[:-2]``.
    """
    inspect = inspect_notification(data)
    if inspect.completeness != COMPLETENESS_COMPLETE or inspect.frame_bytes is None:
        return FrameCrcResult(
            ok=False,
            error=inspect.parsed.error or inspect.completeness.lower(),
            completeness=inspect.completeness,
            observed_bytes=inspect.observed_bytes,
            expected_crc_hex=None,
            actual_trailer_hex=None,
            hypotheses=(),
        )

    frame = inspect.frame_bytes
    hypotheses = evaluate_trailer_hypotheses(frame)
    expected = crc16_modbus_be_bytes(frame[:-TRAILER_SIZE])
    actual = frame[-TRAILER_SIZE:]
    matched = expected == actual
    return FrameCrcResult(
        ok=matched,
        error=None if matched else "crc_mismatch",
        completeness=inspect.completeness,
        observed_bytes=inspect.observed_bytes,
        expected_crc_hex=expected.hex(),
        actual_trailer_hex=actual.hex(),
        hypotheses=hypotheses,
    )


def classify_dump_dir(dump_dir: Path) -> dict[str, object]:
    """Classify every ``*.hex`` dump in a directory against the proven CRC rule."""
    paths = sorted(dump_dir.glob("*.hex"))
    rows: list[dict[str, object]] = []
    passed = 0
    failed = 0
    for path in paths:
        buffer = bytes.fromhex("".join(path.read_text(encoding="ascii").split()))
        result = check_complete_frame_crc(buffer)
        if result.ok:
            passed += 1
        else:
            failed += 1
        rows.append({"path": path.name, **result.as_summary()})
    return {
        "dir": str(dump_dir),
        "files": len(paths),
        "crc_pass": passed,
        "crc_fail": failed,
        "proven_rule": HYPOTHESIS_PER_FRAME_MODBUS,
        "results": rows,
    }


def _load_hex(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit("hex input is not valid.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed CRC-16/MODBUS trailer check for COMPLETE FF01 frames "
            "(no decrypt)."
        )
    )
    parser.add_argument("--hex", help="Hex bytes of one buffer.")
    parser.add_argument("--hex-file", metavar="PATH", help="Read ASCII hex from PATH.")
    parser.add_argument(
        "--dir",
        metavar="DIR",
        help="Classify every *.hex file in DIR against the proven trailer rule.",
    )
    args = parser.parse_args(argv)
    specified = [item for item in (args.hex, args.hex_file, args.dir) if item is not None]
    if len(specified) > 1:
        raise SystemExit("use only one of --hex, --hex-file, or --dir.")

    if args.dir is not None:
        report = classify_dump_dir(Path(args.dir))
        print(json.dumps(report, separators=(",", ":"), sort_keys=True))
        return 0 if report["crc_fail"] == 0 and report["files"] else 1

    if args.hex_file is not None:
        source = Path(args.hex_file).read_text(encoding="ascii")
    elif args.hex is not None:
        source = args.hex
    else:
        source = sys.stdin.read()
    result = check_complete_frame_crc(_load_hex(source))
    print(json.dumps(result.as_summary(), separators=(",", ":"), sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
