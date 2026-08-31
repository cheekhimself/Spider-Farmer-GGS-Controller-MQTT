from __future__ import annotations

import json
import math
from typing import Any


class FragmentedJsonStreamParser:
    """Emit JSON objects from fragmented UTF-8 plaintext and reject binary input."""

    def __init__(self, max_buffer_chars: int = 2500) -> None:
        self.max_buffer_chars = max_buffer_chars
        self._buffer = ""

    def feed(self, chunk: bytes | bytearray | str) -> list[dict]:
        if isinstance(chunk, (bytes, bytearray)):
            try:
                text = bytes(chunk).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                # Never splice plaintext around an opaque/binary notification.
                self._buffer = ""
                return []
        else:
            text = chunk

        self._buffer += "".join(c for c in text if c == "{" or c == "}" or 32 <= ord(c) <= 126)
        self._trim_noise()
        emitted = self._extract_complete_json_objects()
        self._enforce_max_buffer()
        return emitted

    def _trim_noise(self) -> None:
        first_json_start = self._buffer.find("{")
        if first_json_start > 0:
            self._buffer = self._buffer[first_json_start:]
        elif first_json_start < 0:
            self._buffer = ""

    def _extract_complete_json_objects(self) -> list[dict]:
        depth = 0
        start = -1
        last_consumed = 0
        out: list[dict] = []

        for index, char in enumerate(self._buffer):
            if char == "{":
                if depth == 0:
                    start = index
                depth += 1
            elif char == "}" and depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    candidate = self._buffer[start : index + 1]
                    try:
                        parsed = json.loads(candidate)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, dict):
                        out.append(parsed)
                    last_consumed = index + 1
                    start = -1

        if last_consumed > 0:
            self._buffer = self._buffer[last_consumed:]
        return out

    def _enforce_max_buffer(self) -> None:
        if len(self._buffer) <= self.max_buffer_chars:
            return
        keep_from = self._buffer.rfind("{")
        if keep_from < 0:
            self._buffer = ""
            return
        self._buffer = self._buffer[keep_from:]


def extract_safe_get_dev_status(message: dict[str, Any]) -> dict[str, Any] | None:
    """Return only allowlisted getDevSta telemetry, excluding identifiers and secrets."""

    if message.get("method") != "getDevSta":
        return None

    data = message.get("data")
    if not isinstance(data, dict):
        return None

    sensor = data.get("sensor")
    fan = data.get("fan")
    if not isinstance(sensor, dict) or not isinstance(fan, dict):
        return None

    sensor_values = _finite_numbers(sensor, ("temp", "humi", "vpd"))
    fan_values = _finite_numbers(fan, ("on", "level"))
    if sensor_values is None or fan_values is None:
        return None

    return {
        "method": "getDevSta",
        "data": {
            "sensor": sensor_values,
            "fan": fan_values,
        },
    }


def _finite_numbers(source: dict[str, Any], keys: tuple[str, ...]) -> dict[str, int | float] | None:
    out: dict[str, int | float] = {}
    for key in keys:
        value = source.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if not math.isfinite(value):
            return None
        out[key] = value
    return out
