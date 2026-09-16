"""Fail-closed chunk reassembly for COMPLETE CRC-checked FF01 frames.

Inner layout proven as arithmetic + CRC on live 2026-09-16 dumps:

    offset  size  field
    0-3     4     magic ``AA AA 00 03``
    4-5     2     declared length (BE) = bytes after header excluding trailer
    6-7     2     type (observed ``00 02``)
    8-9     2     CRC-16/MODBUS (BE) of assembled ciphertext chunks
    10-13   4     total ciphertext length (BE)
    14-17   4     chunk offset (BE)
    18-19   2     chunk length (BE)
    20..    N     opaque chunk (not proven plaintext)
    last 2  2     CRC-16/MODBUS (BE) of the whole frame excluding these two bytes

A candidate is emitted only when every contributing frame is COMPLETE, passes
the proven trailer CRC, tiles ``0 .. total-1`` without byte conflicts, and the
assembled body matches bytes 8–9. Incomplete groups do not emit. This is not
decrypt and not MQTT.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from verdant_integration.crc16 import crc16_modbus_be_bytes
from verdant_integration.frame_codec import MAGIC
from verdant_integration.frame_crc import (
    MESSAGE_CRC_OFFSET,
    MESSAGE_CRC_SIZE,
    TRAILER_SIZE,
    check_complete_frame_crc,
)
from verdant_integration.frame_dump import COMPLETENESS_COMPLETE

INNER_HEADER_SIZE = 20


@dataclass(frozen=True)
class ChunkView:
    message_crc_hex: str
    type_u16be: int
    total_ciphertext: int
    offset: int
    chunk_length: int
    chunk: bytes
    frame_bytes: bytes

    def as_summary(self) -> dict[str, object]:
        return {
            "message_crc_hex": self.message_crc_hex,
            "type_u16be": self.type_u16be,
            "total_ciphertext": self.total_ciphertext,
            "offset": self.offset,
            "chunk_length": self.chunk_length,
            "chunk_bytes": len(self.chunk),
        }


@dataclass(frozen=True)
class ReassemblyResult:
    ok: bool
    error: str | None
    message_crc_hex: str | None
    total_ciphertext: int | None
    chunk_count: int
    assembled_bytes: int
    assembled: bytes | None
    claimed_plaintext: bool
    claimed_decrypt: bool

    def as_summary(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "error": self.error,
            "message_crc_hex": self.message_crc_hex,
            "total_ciphertext": self.total_ciphertext,
            "chunk_count": self.chunk_count,
            "assembled_bytes": self.assembled_bytes,
            "claimed_plaintext": self.claimed_plaintext,
            "claimed_decrypt": self.claimed_decrypt,
        }


def parse_chunk_view(frame: bytes) -> ChunkView | None:
    """Slice inner fields from a COMPLETE frame. None if layout does not fit."""
    if len(frame) < INNER_HEADER_SIZE + TRAILER_SIZE:
        return None
    if frame[:4] != MAGIC:
        return None
    chunk_length = int.from_bytes(frame[18:20], "big")
    if INNER_HEADER_SIZE + chunk_length + TRAILER_SIZE != len(frame):
        return None
    type_u16be = int.from_bytes(frame[6:8], "big")
    message_crc = frame[MESSAGE_CRC_OFFSET : MESSAGE_CRC_OFFSET + MESSAGE_CRC_SIZE]
    total = int.from_bytes(frame[10:14], "big")
    offset = int.from_bytes(frame[14:18], "big")
    if total < 1 or offset < 0 or chunk_length < 1:
        return None
    if offset + chunk_length > total:
        return None
    chunk = frame[INNER_HEADER_SIZE : INNER_HEADER_SIZE + chunk_length]
    return ChunkView(
        message_crc_hex=message_crc.hex(),
        type_u16be=type_u16be,
        total_ciphertext=total,
        offset=offset,
        chunk_length=chunk_length,
        chunk=chunk,
        frame_bytes=frame,
    )


def _reject(
    error: str,
    *,
    message_crc_hex: str | None = None,
    total: int | None = None,
    chunk_count: int = 0,
    assembled_bytes: int = 0,
) -> ReassemblyResult:
    return ReassemblyResult(
        ok=False,
        error=error,
        message_crc_hex=message_crc_hex,
        total_ciphertext=total,
        chunk_count=chunk_count,
        assembled_bytes=assembled_bytes,
        assembled=None,
        claimed_plaintext=False,
        claimed_decrypt=False,
    )


def reassemble_group(frames: Sequence[bytes]) -> ReassemblyResult:
    """Reassemble one message from COMPLETE CRC-checked frames.

    Fail-closed: any completeness/CRC/layout/overlap/gap/message-CRC mismatch
    returns ``ok=False`` and no assembled candidate.
    """
    views: list[ChunkView] = []
    for buffer in frames:
        crc = check_complete_frame_crc(buffer)
        if not crc.ok or crc.completeness != COMPLETENESS_COMPLETE:
            return _reject(crc.error or "frame_crc_failed", chunk_count=len(frames))
        raw = bytes(buffer)
        view = parse_chunk_view(raw)
        if view is None:
            return _reject("inner_layout_inconsistent", chunk_count=len(frames))
        views.append(view)

    if not views:
        return _reject("empty_group")

    message_crc_hex = views[0].message_crc_hex
    total = views[0].total_ciphertext
    for view in views:
        if view.message_crc_hex != message_crc_hex or view.total_ciphertext != total:
            return _reject(
                "group_header_mismatch",
                message_crc_hex=message_crc_hex,
                total=total,
                chunk_count=len(views),
            )

    assembled = bytearray(total)
    filled = bytearray(total)  # 0 empty, 1 filled
    for view in views:
        for index, byte in enumerate(view.chunk):
            position = view.offset + index
            if filled[position]:
                if assembled[position] != byte:
                    return _reject(
                        "chunk_overlap_conflict",
                        message_crc_hex=message_crc_hex,
                        total=total,
                        chunk_count=len(views),
                    )
                continue
            assembled[position] = byte
            filled[position] = 1

    if any(flag == 0 for flag in filled):
        covered = sum(filled)
        return _reject(
            "incomplete_coverage",
            message_crc_hex=message_crc_hex,
            total=total,
            chunk_count=len(views),
            assembled_bytes=covered,
        )

    body = bytes(assembled)
    expected = crc16_modbus_be_bytes(body)
    actual = bytes.fromhex(message_crc_hex)
    if expected != actual:
        return _reject(
            "message_crc_mismatch",
            message_crc_hex=message_crc_hex,
            total=total,
            chunk_count=len(views),
            assembled_bytes=len(body),
        )

    return ReassemblyResult(
        ok=True,
        error=None,
        message_crc_hex=message_crc_hex,
        total_ciphertext=total,
        chunk_count=len(views),
        assembled_bytes=len(body),
        assembled=body,
        claimed_plaintext=False,
        claimed_decrypt=False,
    )


def reassemble_dump_frames(frames: Sequence[bytes]) -> list[ReassemblyResult]:
    """Group CRC-checked frames by (message CRC, total) and reassemble each."""
    buckets: dict[tuple[str, int], list[bytes]] = defaultdict(list)
    rejected: list[ReassemblyResult] = []
    for buffer in frames:
        crc = check_complete_frame_crc(buffer)
        if not crc.ok:
            rejected.append(
                _reject(crc.error or "frame_crc_failed", chunk_count=1)
            )
            continue
        raw = bytes(buffer) if not isinstance(buffer, bytes) else buffer
        view = parse_chunk_view(raw)
        if view is None:
            rejected.append(_reject("inner_layout_inconsistent", chunk_count=1))
            continue
        buckets[(view.message_crc_hex, view.total_ciphertext)].append(raw)

    results = [reassemble_group(group) for group in buckets.values()]
    results.extend(rejected)
    return results


def load_hex_dir(dump_dir: Path) -> list[bytes]:
    frames: list[bytes] = []
    for path in sorted(dump_dir.glob("*.hex")):
        frames.append(bytes.fromhex("".join(path.read_text(encoding="ascii").split())))
    return frames


def _load_hex(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit("hex input is not valid.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed reassembly of COMPLETE CRC-checked FF01 chunks "
            "(opaque ciphertext only; no decrypt)."
        )
    )
    parser.add_argument(
        "--dir",
        metavar="DIR",
        help="Directory of COMPLETE *.hex dumps (live_phase3 style).",
    )
    parser.add_argument(
        "--include-hex",
        action="store_true",
        help="Include assembled ciphertext hex (still not plaintext).",
    )
    args = parser.parse_args(argv)
    if args.dir is None:
        raise SystemExit("--dir is required.")
    frames = load_hex_dir(Path(args.dir))
    results = reassemble_dump_frames(frames)
    summaries: list[dict[str, object]] = []
    emitted = 0
    for result in results:
        row = result.as_summary()
        if args.include_hex and result.assembled is not None:
            row["assembled_hex"] = result.assembled.hex()
        summaries.append(row)
        if result.ok:
            emitted += 1
    report = {
        "input_frames": len(frames),
        "groups": len(summaries),
        "emitted_candidates": emitted,
        "claimed_decrypt": False,
        "claimed_plaintext": False,
        "message_crc_rule": "crc16_modbus_be_over_assembled_chunks",
        "results": summaries,
    }
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if emitted else 1


if __name__ == "__main__":
    raise SystemExit(main())
