from __future__ import annotations

import os
from dataclasses import dataclass


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class VerdantGgsConfig:
    enabled: bool
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str
    mqtt_tls_enabled: bool
    mqtt_tls_ca_cert_path: str
    mqtt_topic_prefix: str
    ggs_ble_address: str
    telemetry_stale_after_seconds: int
    command_retries: int

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "VerdantGgsConfig":
        values = env if env is not None else os.environ
        cfg = cls(
            enabled=_as_bool(values.get("VERDANT_GGS_ENABLED"), False),
            mqtt_host=(values.get("VERDANT_GGS_MQTT_HOST") or "").strip(),
            mqtt_port=int(values.get("VERDANT_GGS_MQTT_PORT", "1883")),
            mqtt_username=(values.get("VERDANT_GGS_MQTT_USERNAME") or "").strip(),
            mqtt_password=(values.get("VERDANT_GGS_MQTT_PASSWORD") or "").strip(),
            mqtt_tls_enabled=_as_bool(values.get("VERDANT_GGS_MQTT_TLS_ENABLED"), False),
            mqtt_tls_ca_cert_path=(values.get("VERDANT_GGS_MQTT_TLS_CA_CERT_PATH") or "").strip(),
            mqtt_topic_prefix=(values.get("VERDANT_GGS_TOPIC_PREFIX") or "grow/GGS").strip().strip("/"),
            ggs_ble_address=(values.get("VERDANT_GGS_BLE_ADDRESS") or "").strip().lower(),
            telemetry_stale_after_seconds=int(values.get("VERDANT_GGS_TELEMETRY_STALE_SECONDS", "90")),
            command_retries=int(values.get("VERDANT_GGS_COMMAND_RETRIES", "2")),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        errors: list[str] = []

        if self.enabled and not self.mqtt_host:
            errors.append("VERDANT_GGS_MQTT_HOST is required when VERDANT_GGS_ENABLED is true.")
        if self.mqtt_port <= 0:
            errors.append("VERDANT_GGS_MQTT_PORT must be a positive integer.")
        if self.mqtt_username and not self.mqtt_password:
            errors.append("VERDANT_GGS_MQTT_PASSWORD is required when username is set.")
        if self.mqtt_password and not self.mqtt_username:
            errors.append("VERDANT_GGS_MQTT_USERNAME is required when password is set.")
        if self.mqtt_tls_enabled and not self.mqtt_tls_ca_cert_path:
            errors.append("VERDANT_GGS_MQTT_TLS_CA_CERT_PATH is required when TLS is enabled.")
        if not self.mqtt_topic_prefix:
            errors.append("VERDANT_GGS_TOPIC_PREFIX cannot be empty.")
        if self.telemetry_stale_after_seconds <= 0:
            errors.append("VERDANT_GGS_TELEMETRY_STALE_SECONDS must be > 0.")
        if self.command_retries < 0:
            errors.append("VERDANT_GGS_COMMAND_RETRIES must be >= 0.")

        if errors:
            raise ValueError("Invalid Verdant GGS configuration: " + " ".join(errors))
