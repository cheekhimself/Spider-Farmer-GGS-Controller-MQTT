"""CRC-16 helpers used by frame CRC checks (no decrypt)."""

from __future__ import annotations

# CRC-16/MODBUS: poly 0x8005 reflected (0xA001), init 0xFFFF, xorout 0, refin/refout.


def crc16_modbus(data: bytes | bytearray | memoryview) -> int:
    """Return CRC-16/MODBUS as an integer 0..65535."""
    crc = 0xFFFF
    for byte in bytes(data):
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def crc16_modbus_be_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Big-endian two-byte CRC-16/MODBUS digest."""
    return crc16_modbus(data).to_bytes(2, "big")
