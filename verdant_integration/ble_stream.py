from __future__ import annotations

import json


class FragmentedJsonStreamParser:
    """Collect BLE chunks and emit parsed JSON objects from noisy fragmented input."""

    def __init__(self, max_buffer_chars: int = 2500) -> None:
        self.max_buffer_chars = max_buffer_chars
        self._buffer = ""

    def feed(self, chunk: bytes | bytearray | str) -> list[dict]:
        if isinstance(chunk, (bytes, bytearray)):
            text = chunk.decode("utf-8", errors="ignore")
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
