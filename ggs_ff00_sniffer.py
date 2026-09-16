"""Bounded receive-only capture for Spider Farmer GGS FF01 notifications."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    raise SystemExit("bleak is required for receive-only FF01 capture.") from None

from verdant_integration.ble_stream import (
    FragmentedJsonStreamParser,
    extract_safe_get_dev_status,
)
from verdant_integration.frame_codec import FrameCodec
from verdant_integration.frame_dump import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PLAINTEXT,
    CaptureStats,
    apply_dump,
    inspect_notification,
)

DEVICE_NAME = "SF-GGS-CB"
FF01_NOTIFY_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Receive-only Spider Farmer GGS FF01 capture")
    parser.add_argument("--scan-attempts", type=int, default=3)
    parser.add_argument("--scan-seconds", type=float, default=3.0)
    parser.add_argument("--listen-seconds", type=float, default=30.0)
    parser.add_argument(
        "--dump-frames",
        metavar="DIR",
        help=(
            "Write one .hex file per COMPLETE framed notification into DIR. "
            "TRUNCATED/OVERSIZED/UNKNOWN are never padded or written."
        ),
    )
    return parser


def _positive(value: int | float, label: str) -> None:
    if value <= 0:
        raise SystemExit(f"{label} must be greater than zero.")


async def capture(
    scan_attempts: int,
    scan_seconds: float,
    listen_seconds: float,
    dump_frames: str | None = None,
) -> int:
    _positive(scan_attempts, "--scan-attempts")
    _positive(scan_seconds, "--scan-seconds")
    _positive(listen_seconds, "--listen-seconds")

    dump_dir = Path(dump_frames) if dump_frames else None
    if dump_dir is not None:
        dump_dir.mkdir(parents=True, exist_ok=True)

    print(f"[SCAN] Looking for exact BLE name {DEVICE_NAME}; BLE addresses are suppressed.")
    device = None
    for _ in range(scan_attempts):
        discovered = await BleakScanner.discover(timeout=scan_seconds)
        device = next(
            (candidate for candidate in discovered if (candidate.name or "").strip() == DEVICE_NAME),
            None,
        )
        if device is not None:
            break

    if device is None:
        print(f"[STOP] {DEVICE_NAME} was not found; capture NOT_MEASURED.")
        return 2

    print(f"[CONNECT] Matched {DEVICE_NAME}; BLE address suppressed.")
    parser = FragmentedJsonStreamParser()
    stats = CaptureStats()
    telemetry_count = 0

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("[STOP] BLE connection failed; details suppressed.")
            return 3

        def handle_notification(_: object, data: bytearray) -> None:
            nonlocal telemetry_count
            inspect = inspect_notification(data)
            dumped = apply_dump(stats, inspect, dump_dir)
            summary = inspect.as_summary()
            dumped_note = str(dumped) if dumped is not None else "no"

            if inspect.completeness != COMPLETENESS_PLAINTEXT:
                classification = (
                    "FRAMED_CANDIDATE"
                    if inspect.parsed.ok and inspect.completeness == COMPLETENESS_COMPLETE
                    else f"FRAMED_{inspect.completeness}"
                    if FrameCodec.looks_framed(data)
                    else inspect.completeness
                )
                print(
                    f"[FF01] notification={stats.notifications} bytes={inspect.observed_bytes} "
                    f"completeness={inspect.completeness} classification={classification} "
                    f"length={summary['length']} header={summary['header']} "
                    f"expected={inspect.expected_bytes} dumped={dumped_note}"
                )
                return

            messages = parser.feed(data)
            if not messages:
                print(
                    f"[FF01] notification={stats.notifications} bytes={inspect.observed_bytes} "
                    f"completeness={COMPLETENESS_PLAINTEXT} classification=NOT_LIVE dumped=no"
                )
                return

            for message in messages:
                safe_status = extract_safe_get_dev_status(message)
                if safe_status is None:
                    print(
                        f"[FF01] notification={stats.notifications} "
                        f"completeness={COMPLETENESS_PLAINTEXT} "
                        "classification=PLAINTEXT_JSON_NOT_LIVE dumped=no"
                    )
                    continue
                telemetry_count += 1
                print(
                    f"[FF01] completeness={COMPLETENESS_PLAINTEXT} "
                    "classification=PLAINTEXT_GETDEVSTA "
                    + json.dumps(safe_status, separators=(",", ":"), sort_keys=True)
                )

        print(f"[LISTEN] Subscribing to FF01 only for {listen_seconds:g} seconds.")
        await client.start_notify(FF01_NOTIFY_UUID, handle_notification)
        try:
            await asyncio.sleep(listen_seconds)
        finally:
            await client.stop_notify(FF01_NOTIFY_UUID)

    counts = stats.as_summary()
    dump_note = (
        f" dumped_complete={counts['dumped']} dir={dump_dir}"
        if dump_dir is not None
        else " no frame files written"
    )
    print(
        f"[STOP] notifications={counts['notifications']} "
        f"COMPLETE={counts['COMPLETE']} TRUNCATED={counts['TRUNCATED']} "
        f"PLAINTEXT={counts['PLAINTEXT']} UNKNOWN={counts['UNKNOWN']} "
        f"OVERSIZED={counts['OVERSIZED']} plaintext_getDevSta={telemetry_count};"
        f"{dump_note}; BLE addresses suppressed."
    )
    return 0


async def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return await capture(
        args.scan_attempts,
        args.scan_seconds,
        args.listen_seconds,
        args.dump_frames,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("[STOP] Interrupted; no additional capture files were written.")
    except Exception as exc:
        print(f"[STOP] BLE capture failed ({type(exc).__name__}); details suppressed.")
        raise SystemExit(1) from None
