"""Receive-first FF01/FF02 capture for pairing evidence (Phase 6).

Default path is listen-only: subscribe FF01 notifications and, when the
GATT properties allow, also subscribe FF02 *notifications/indications*.
That does **not** see writes the official Android app sends on another
connection. For those writes, use Android HCI snoop (documented) and
``--from-hex-dir``.

An FF02 write helper exists only behind two explicit opt-in switches and
is **not** required for Phase 6. BLE MACs are never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from verdant_integration.frame_codec import FrameCodec
from verdant_integration.frame_crc import check_complete_frame_crc
from verdant_integration.frame_dump import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PLAINTEXT,
    CaptureStats,
    apply_dump,
    inspect_notification,
)
from verdant_integration.ff_session import (
    classify_hex_dir,
    load_hex,
    write_ff02_allowed,
)

DEVICE_NAME = "SF-GGS-CB"
FF01_NOTIFY_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
FF02_WRITE_UUID = "0000ff02-0000-1000-8000-00805f9b34fb"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Receive-first Spider Farmer GGS capture: FF01 notify, optional "
            "FF02 indicate, or offline hex-dir import. HCI snoop is preferred "
            "for official-app FF02 writes."
        )
    )
    parser.add_argument("--scan-attempts", type=int, default=3)
    parser.add_argument("--scan-seconds", type=float, default=3.0)
    parser.add_argument("--listen-seconds", type=float, default=30.0)
    parser.add_argument(
        "--dump-frames",
        metavar="DIR",
        help="Write COMPLETE framed buffers (FF01 and FF02) into DIR.",
    )
    parser.add_argument(
        "--from-hex-dir",
        metavar="DIR",
        help=(
            "Offline: classify *.hex dumps (operator HCI/Wireshark exports). "
            "Skips live BLE. Completeness + trailer CRC when COMPLETE."
        ),
    )
    parser.add_argument(
        "--no-ff02-notify",
        action="store_true",
        help="Do not attempt start_notify on FF02 even if properties allow.",
    )
    parser.add_argument(
        "--dangerous-write-ff02-hex",
        default="",
        help="DANGEROUS/opt-in: hex payload to write to FF02. Not required.",
    )
    parser.add_argument(
        "--i-understand-this-writes-ff02",
        action="store_true",
        help="Required together with env SF_GGS_I_UNDERSTAND_FF02_WRITE=yes.",
    )
    return parser


def _positive(value: int | float, label: str) -> None:
    if value <= 0:
        raise SystemExit(f"{label} must be greater than zero.")


async def capture_live(
    scan_attempts: int,
    scan_seconds: float,
    listen_seconds: float,
    dump_frames: str | None,
    *,
    ff02_notify: bool,
    write_hex: str,
) -> int:
    try:
        from bleak import BleakClient, BleakScanner
    except ImportError:
        raise SystemExit("bleak is required for live BLE capture.") from None

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
    stats = CaptureStats()

    def handle(channel: str):
        def _inner(_: object, data: bytearray) -> None:
            inspect = inspect_notification(data)
            dumped = apply_dump(stats, inspect, dump_dir)
            crc_note = "n/a"
            if inspect.completeness == COMPLETENESS_COMPLETE:
                crc = check_complete_frame_crc(bytes(data))
                crc_note = "pass" if crc.ok else f"fail:{crc.error}"
            dumped_note = str(dumped) if dumped is not None else "no"
            classification = (
                "FRAMED_CANDIDATE"
                if inspect.parsed.ok and inspect.completeness == COMPLETENESS_COMPLETE
                else f"FRAMED_{inspect.completeness}"
                if FrameCodec.looks_framed(data)
                else inspect.completeness
            )
            print(
                f"[{channel}] notification={stats.notifications} bytes={inspect.observed_bytes} "
                f"completeness={inspect.completeness} classification={classification} "
                f"crc={crc_note} dumped={dumped_note}"
            )
            if inspect.completeness == COMPLETENESS_PLAINTEXT:
                print(
                    f"[{channel}] plaintext JSON observed; still not MQTT live sensors."
                )

        return _inner

    async with BleakClient(device) as client:
        if not client.is_connected:
            print("[STOP] BLE connection failed; details suppressed.")
            return 3
        print(f"[LISTEN] Subscribing to FF01 for {listen_seconds:g} seconds.")
        await client.start_notify(FF01_NOTIFY_UUID, handle("FF01"))
        ff02_notify_on = False
        if ff02_notify:
            try:
                await client.start_notify(FF02_WRITE_UUID, handle("FF02"))
                ff02_notify_on = True
                print(
                    "[LISTEN] FF02 notify/indicate subscribed. This still does not "
                    "capture writes from the official app on another connection."
                )
            except Exception:
                print(
                    "[LISTEN] FF02 notify/indicate not available on this GATT; "
                    "use Android HCI snoop for official-app writes."
                )
        if write_hex:
            payload = load_hex(write_hex)
            print(
                f"[DANGER] Writing {len(payload)} bytes to FF02 (opt-in). "
                "This is not the Phase 6 success path."
            )
            await client.write_gatt_char(FF02_WRITE_UUID, payload, response=True)
        try:
            await asyncio.sleep(listen_seconds)
        finally:
            await client.stop_notify(FF01_NOTIFY_UUID)
            if ff02_notify_on:
                await client.stop_notify(FF02_WRITE_UUID)

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
        f"OVERSIZED={counts['OVERSIZED']};{dump_note}; BLE addresses suppressed; "
        "claimed_decrypt=false claimed_mqtt_live=false."
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dump_dir = Path(args.dump_frames) if args.dump_frames else None
    if args.from_hex_dir:
        report = classify_hex_dir(Path(args.from_hex_dir), dump_dir)
        print(json.dumps(report, separators=(",", ":"), sort_keys=True))
        return 0 if report["files"] else 1
    _positive(args.scan_attempts, "--scan-attempts")
    _positive(args.scan_seconds, "--scan-seconds")
    _positive(args.listen_seconds, "--listen-seconds")
    write_hex = ""
    if write_ff02_allowed(
        write_hex=args.dangerous_write_ff02_hex,
        understand_flag=args.i_understand_this_writes_ff02,
    ):
        write_hex = args.dangerous_write_ff02_hex
    return asyncio.run(
        capture_live(
            args.scan_attempts,
            args.scan_seconds,
            args.listen_seconds,
            args.dump_frames,
            ff02_notify=not args.no_ff02_notify,
            write_hex=write_hex,
        )
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("[STOP] Interrupted; no additional capture files were written.")
    except Exception as exc:
        print(f"[STOP] BLE capture failed ({type(exc).__name__}); details suppressed.")
        raise SystemExit(1) from None
