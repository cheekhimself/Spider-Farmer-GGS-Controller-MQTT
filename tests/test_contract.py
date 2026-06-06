import unittest

from verdant_integration.contract import GgsTelemetrySnapshot, apply_telemetry_message


class ContractTests(unittest.TestCase):
    def test_maps_topic_values(self) -> None:
        snapshot = GgsTelemetrySnapshot()

        applied_temp = apply_telemetry_message(snapshot, "grow/GGS/sensor/temp", "23.3")
        applied_fan = apply_telemetry_message(snapshot, "grow/GGS/fan/level", "5")
        applied_status = apply_telemetry_message(snapshot, "grow/GGS/status", "online")

        self.assertTrue(applied_temp)
        self.assertTrue(applied_fan)
        self.assertTrue(applied_status)
        self.assertEqual(snapshot.temperature_c, 23.3)
        self.assertEqual(snapshot.fan_level, 5)
        self.assertEqual(snapshot.bridge_status, "online")

    def test_ignores_unknown_topic(self) -> None:
        snapshot = GgsTelemetrySnapshot()
        self.assertFalse(apply_telemetry_message(snapshot, "grow/GGS/unknown", "1"))

    def test_ignores_other_prefix(self) -> None:
        snapshot = GgsTelemetrySnapshot()
        self.assertFalse(apply_telemetry_message(snapshot, "other/sensor/temp", "23.3"))


if __name__ == "__main__":
    unittest.main()
