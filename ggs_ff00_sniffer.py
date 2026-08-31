"""Bounded receive-only capture for Spider Farmer GGS FF01 notifications."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    raise SystemExit("bleak is required for receive-only FF01 capture.") from None

from verdant_integration.ble_stream import (
    FragmentedJsonStreamParser,
    extract_safe_get_dev_status,
)

DEVICE_NAME = "SF-GGS-CB"
FF01_NOTIFY_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Receive-only Spider Farmer GGS FF01 capture")
    parser.add_argument("--scan-attempts", type=int, default=3)
    parser.add_argument("--scan-seconds", type=float, default=3.0)
    parser.add_argument("--listen-seconds", type=float, default=30.0)
    return parser


def _positive(value: int | float, label: str) -> None:
    if value <= 0:
        raise SystemExit(f"{label} must be greater than zero.")


async def capture(scan_attempts: int, scan_seconds: float, listen_seconds: float) -> int:
    _positive(scan_attempts, "--scan-attempts")
    _positive(scan_seconds, "--scan-seconds")
    _positive(listen_seconds, "--listen-seconds")

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
    notification_count = 0
    telemetry_count = 0

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("[STOP] BLE connection failed; details suppressed.")
            return 3

        def handle_notification(_: object, data: bytearray) -> None:
            nonlocal notification_count, telemetry_count
            notification_count += 1
            messages = parser.feed(data)
            if not messages:
                print(
                    f"[FF01] notification={notification_count} bytes={len(data)} "
                    "classification=NOT_LIVE"
                )
                return

            for message in messages:
                safe_status = extract_safe_get_dev_status(message)
                if safe_status is None:
                    print(
                        f"[FF01] notification={notification_count} "
                        "classification=PLAINTEXT_JSON_NOT_LIVE"
                    )
                    continue
                telemetry_count += 1
                print(
                    "[FF01] classification=PLAINTEXT_GETDEVSTA "
                    + json.dumps(safe_status, separators=(",", ":"), sort_keys=True)
                )

        print(f"[LISTEN] Subscribing to FF01 only for {listen_seconds:g} seconds.")
        await client.start_notify(FF01_NOTIFY_UUID, handle_notification)
        try:
            await asyncio.sleep(listen_seconds)
        finally:
            await client.stop_notify(FF01_NOTIFY_UUID)

    print(
        f"[STOP] notifications={notification_count} plaintext_getDevSta={telemetry_count}; "
        "no raw bytes or BLE addresses retained."
    )
    return 0


async def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return await capture(args.scan_attempts, args.scan_seconds, args.listen_seconds)


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("[STOP] Interrupted; no capture file was written.")
    except Exception as exc:
        print(f"[STOP] BLE capture failed ({type(exc).__name__}); details suppressed.")
        raise SystemExit(1) from None
