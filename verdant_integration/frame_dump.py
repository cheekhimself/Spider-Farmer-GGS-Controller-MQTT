"""Fail-closed completeness classify + dump for FF01 framed notifications.

COMPLETE means the observed buffer length equals ``declared_length + 8`` with
no leftover bytes. It does **not** mean CRC, reassembly, or decrypt succeeded.
Truncated or oversized buffers are never padded and are never written as
COMPLETE dumps.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from verdant_integration.frame_codec import (
    ERROR_INVALID_LENGTH,
    ERROR_NOT_FRAMED,
    ERROR_PLAINTEXT_JSON,
    ERROR_TOO_SHORT,
    ERROR_TRUNCATED,
    LENGTH_ENVELOPE,
    FrameCodec,
    FrameParseResult,
)

COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_TRUNCATED = "TRUNCATED"
COMPLETENESS_OVERSIZED = "OVERSIZED"
COMPLETENESS_PLAINTEXT = "PLAINTEXT"
COMPLETENESS_UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class NotificationInspect:
    completeness: str
    observed_bytes: int
    expected_bytes: int | None
    parsed: FrameParseResult
    frame_bytes: bytes | None

    def as_summary(self) -> dict[str, object]:
        """Classification + header/length only; no body hex."""
        return {
            "completeness": self.completeness,
            "observed_bytes": self.observed_bytes,
            "expected_bytes": self.expected_bytes,
            "ok": self.parsed.ok,
            "error": self.parsed.error,
            "length": self.parsed.length,
            "header": self.parsed.header.hex() if self.parsed.header else "",
            "leftover_bytes": len(self.parsed.leftover),
            "dumpable": self.frame_bytes is not None,
        }


@dataclass
class CaptureStats:
    notifications: int = 0
    complete: int = 0
    truncated: int = 0
    plaintext: int = 0
    unknown: int = 0
    oversized: int = 0
    dumped: int = 0
    paths: list[str] = field(default_factory=list)

    def record(self, inspect: NotificationInspect) -> None:
        self.notifications += 1
        if inspect.completeness == COMPLETENESS_COMPLETE:
            self.complete += 1
        elif inspect.completeness == COMPLETENESS_TRUNCATED:
            self.truncated += 1
        elif inspect.completeness == COMPLETENESS_PLAINTEXT:
            self.plaintext += 1
        elif inspect.completeness == COMPLETENESS_OVERSIZED:
            self.oversized += 1
        else:
            self.unknown += 1

    def as_summary(self) -> dict[str, object]:
        return {
            "notifications": self.notifications,
            "COMPLETE": self.complete,
            "TRUNCATED": self.truncated,
            "PLAINTEXT": self.plaintext,
            "UNKNOWN": self.unknown,
            "OVERSIZED": self.oversized,
            "dumped": self.dumped,
        }


def inspect_notification(data: bytes | bytearray | memoryview | str) -> NotificationInspect:
    """Classify one FF01 notification. Never pads or invents missing bytes."""
    if isinstance(data, str):
        buffer = data.encode("utf-8", errors="surrogateescape")
    else:
        buffer = bytes(data)

    parsed = FrameCodec.parse(buffer)
    observed = len(buffer)

    if parsed.error == ERROR_PLAINTEXT_JSON:
        return NotificationInspect(
            completeness=COMPLETENESS_PLAINTEXT,
            observed_bytes=observed,
            expected_bytes=None,
            parsed=parsed,
            frame_bytes=None,
        )

    if parsed.error in (ERROR_TOO_SHORT, ERROR_NOT_FRAMED, ERROR_INVALID_LENGTH):
        expected = (
            parsed.length + LENGTH_ENVELOPE
            if parsed.length is not None and parsed.error == ERROR_INVALID_LENGTH
            else None
        )
        return NotificationInspect(
            completeness=COMPLETENESS_UNKNOWN,
            observed_bytes=observed,
            expected_bytes=expected,
            parsed=parsed,
            frame_bytes=None,
        )

    if parsed.error == ERROR_TRUNCATED:
        expected = (
            parsed.length + LENGTH_ENVELOPE if parsed.length is not None else None
        )
        return NotificationInspect(
            completeness=COMPLETENESS_TRUNCATED,
            observed_bytes=observed,
            expected_bytes=expected,
            parsed=parsed,
            frame_bytes=None,
        )

    if not parsed.ok or parsed.length is None:
        return NotificationInspect(
            completeness=COMPLETENESS_UNKNOWN,
            observed_bytes=observed,
            expected_bytes=None,
            parsed=parsed,
            frame_bytes=None,
        )

    expected = parsed.length + LENGTH_ENVELOPE
    if parsed.leftover or observed != expected:
        return NotificationInspect(
            completeness=COMPLETENESS_OVERSIZED,
            observed_bytes=observed,
            expected_bytes=expected,
            parsed=parsed,
            frame_bytes=None,
        )

    return NotificationInspect(
        completeness=COMPLETENESS_COMPLETE,
        observed_bytes=observed,
        expected_bytes=expected,
        parsed=parsed,
        frame_bytes=buffer,
    )


def write_complete_frame(
    dump_dir: Path,
    inspect: NotificationInspect,
    index: int,
) -> Path | None:
    """Write one ``.hex`` file only for COMPLETE frames. Returns path or None."""
    if inspect.completeness != COMPLETENESS_COMPLETE or inspect.frame_bytes is None:
        return None
    dump_dir.mkdir(parents=True, exist_ok=True)
    declared = inspect.parsed.length if inspect.parsed.length is not None else 0
    name = f"{index:04d}_{inspect.observed_bytes}b_len{declared}.hex"
    path = dump_dir / name
    path.write_text(inspect.frame_bytes.hex() + "\n", encoding="ascii")
    return path


def apply_dump(
    stats: CaptureStats,
    inspect: NotificationInspect,
    dump_dir: Path | None,
) -> Path | None:
    stats.record(inspect)
    if dump_dir is None:
        return None
    path = write_complete_frame(dump_dir, inspect, stats.complete)
    if path is not None:
        stats.dumped += 1
        stats.paths.append(str(path))
    return path


def _load_hex(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit("hex input is not valid.") from None


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Classify one FF01 buffer for COMPLETE vs TRUNCATED (no decrypt, no BLE)."
        )
    )
    parser.add_argument(
        "--hex",
        help="Hex bytes of one notification. Reads stdin when omitted and --hex-file is omitted.",
    )
    parser.add_argument(
        "--hex-file",
        metavar="PATH",
        help="Read hex bytes from PATH (ASCII hex; whitespace ignored).",
    )
    parser.add_argument(
        "--dump-frames",
        metavar="DIR",
        help="If COMPLETE, write the full frame hex into DIR.",
    )
    args = parser.parse_args(argv)
    if args.hex is not None and args.hex_file is not None:
        raise SystemExit("use only one of --hex or --hex-file.")
    if args.hex_file is not None:
        source = Path(args.hex_file).read_text(encoding="ascii")
    elif args.hex is not None:
        source = args.hex
    else:
        source = sys.stdin.read()
    inspect = inspect_notification(_load_hex(source))
    stats = CaptureStats()
    dump_dir = Path(args.dump_frames) if args.dump_frames else None
    dumped = apply_dump(stats, inspect, dump_dir)
    report = inspect.as_summary()
    if dumped is not None:
        report["dumped_path"] = str(dumped)
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if inspect.completeness == COMPLETENESS_COMPLETE else 1


if __name__ == "__main__":
    raise SystemExit(main())
