from __future__ import annotations

from dataclasses import asdict, dataclass


TOPIC_SUFFIX_TO_FIELD = {
    "sensor/temp": "temperature_c",
    "sensor/humi": "humidity_pct",
    "sensor/vpd": "vpd",
    "fan/on": "fan_on",
    "fan/level": "fan_level",
    "light/on": "light_on",
    "light/level": "light_level",
    "blower/level": "blower_level",
}


@dataclass
class GgsTelemetrySnapshot:
    bridge_status: str | None = None
    temperature_c: float | None = None
    humidity_pct: float | None = None
    vpd: float | None = None
    fan_on: int | None = None
    fan_level: int | None = None
    light_on: int | None = None
    light_level: int | None = None
    blower_level: int | None = None

    def to_verdant_record(self) -> dict[str, float | int | str | None]:
        return asdict(self)


def _parse_value(field_name: str, payload: str) -> float | int | str:
    if field_name in {"temperature_c", "humidity_pct", "vpd"}:
        return float(payload)
    if field_name in {"fan_on", "fan_level", "light_on", "light_level", "blower_level"}:
        return int(float(payload))
    return payload


def apply_telemetry_message(
    snapshot: GgsTelemetrySnapshot,
    topic: str,
    payload: str,
    topic_prefix: str = "grow/GGS",
) -> bool:
    normalized_prefix = topic_prefix.strip("/")
    normalized_topic = topic.strip("/")
    if not normalized_topic.startswith(normalized_prefix + "/"):
        return False

    suffix = normalized_topic[len(normalized_prefix) + 1 :]
    if suffix == "status":
        snapshot.bridge_status = payload.strip().lower()
        return True

    field_name = TOPIC_SUFFIX_TO_FIELD.get(suffix)
    if not field_name:
        return False

    parsed = _parse_value(field_name, payload.strip())
    setattr(snapshot, field_name, parsed)
    return True
