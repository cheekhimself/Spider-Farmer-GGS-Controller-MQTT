import unittest

from verdant_integration.config import VerdantGgsConfig


class VerdantConfigTests(unittest.TestCase):
    def test_enabled_requires_host(self) -> None:
        with self.assertRaises(ValueError):
            VerdantGgsConfig.from_env(
                {
                    "VERDANT_GGS_ENABLED": "true",
                    "VERDANT_GGS_MQTT_PORT": "1883",
                }
            )

    def test_tls_requires_ca_cert(self) -> None:
        with self.assertRaises(ValueError):
            VerdantGgsConfig.from_env(
                {
                    "VERDANT_GGS_ENABLED": "true",
                    "VERDANT_GGS_MQTT_HOST": "broker.local",
                    "VERDANT_GGS_MQTT_TLS_ENABLED": "true",
                }
            )

    def test_accepts_valid_configuration(self) -> None:
        cfg = VerdantGgsConfig.from_env(
            {
                "VERDANT_GGS_ENABLED": "true",
                "VERDANT_GGS_MQTT_HOST": "broker.local",
                "VERDANT_GGS_MQTT_PORT": "1883",
                "VERDANT_GGS_TOPIC_PREFIX": "grow/GGS",
                "VERDANT_GGS_COMMAND_RETRIES": "3",
            }
        )
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.mqtt_host, "broker.local")
        self.assertEqual(cfg.command_retries, 3)


if __name__ == "__main__":
    unittest.main()
