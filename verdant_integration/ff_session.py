"""Offline FF01/FF02 hex-dir classify + gated write policy (Phase 6)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from verdant_integration.frame_crc import check_complete_frame_crc
from verdant_integration.frame_dump import (
    COMPLETENESS_COMPLETE,
    CaptureStats,
    apply_dump,
    inspect_notification,
)

WRITE_ENV = "SF_GGS_I_UNDERSTAND_FF02_WRITE"
WRITE_REFUSED = (
    "FF02 write refused: not required for Phase 6; pass "
    "--i-understand-this-writes-ff02 and set SF_GGS_I_UNDERSTAND_FF02_WRITE=yes."
)
MAC_REDACT = "xx-xx-xx-xx-xx-xx"
# Colon, hyphen, or underscore separated IEEE-looking 6-octet addresses.
_MAC_SEP = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:\-_]){5}[0-9a-f]{2}(?![0-9a-f])"
)


def redact_macs(text: str) -> str:
    """Replace MAC-like tokens in operator filenames / dump paths."""
    return _MAC_SEP.sub(MAC_REDACT, text)


def load_hex(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit("hex input is not valid.") from None


def channel_hint(name: str) -> str:
    lowered = name.lower()
    if "ff02" in lowered:
        return "ff02"
    if "ff01" in lowered:
        return "ff01"
    return "unknown"


def classify_hex_file(path: Path) -> dict[str, object]:
    """Phase 3 completeness + Phase 4 CRC on one operator hex dump."""
    buffer = load_hex(path.read_text(encoding="ascii"))
    inspect = inspect_notification(buffer)
    row: dict[str, object] = {
        "path": redact_macs(path.name),
        "channel_hint": channel_hint(path.name),
        "observed_bytes": inspect.observed_bytes,
        "completeness": inspect.completeness,
        "header": inspect.parsed.header.hex() if inspect.parsed.header else "",
        "length": inspect.parsed.length,
        "crc_ok": None,
        "crc_error": None,
    }
    if inspect.completeness == COMPLETENESS_COMPLETE:
        crc = check_complete_frame_crc(buffer)
        row["crc_ok"] = crc.ok
        row["crc_error"] = crc.error
        row["expected_crc_hex"] = crc.expected_crc_hex
        row["actual_trailer_hex"] = crc.actual_trailer_hex
    return row


def classify_hex_dir(dump_dir: Path, dump_frames: Path | None) -> dict[str, object]:
    stats = CaptureStats()
    rows: list[dict[str, object]] = []
    crc_pass = 0
    crc_fail = 0
    for path in sorted(dump_dir.glob("*.hex")):
        inspect = inspect_notification(load_hex(path.read_text(encoding="ascii")))
        dumped = apply_dump(stats, inspect, dump_frames)
        row = classify_hex_file(path)
        row["dumped"] = redact_macs(str(dumped)) if dumped is not None else None
        if row["crc_ok"] is True:
            crc_pass += 1
        elif row["crc_ok"] is False:
            crc_fail += 1
        rows.append(row)
    return {
        "mode": "from_hex_dir",
        "files": len(rows),
        "completeness": stats.as_summary(),
        "crc_pass": crc_pass,
        "crc_fail": crc_fail,
        "claimed_decrypt": False,
        "claimed_mqtt_live": False,
        "ble_macs": "suppressed",
        "results": rows,
    }


def write_ff02_allowed(*, write_hex: str, understand_flag: bool) -> bool:
    if not write_hex:
        return False
    env_ok = os.environ.get(WRITE_ENV, "") == "yes"
    if not understand_flag or not env_ok:
        raise SystemExit(WRITE_REFUSED)
    return True
