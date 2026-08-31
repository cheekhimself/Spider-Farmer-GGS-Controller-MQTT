import unittest
from pathlib import Path

from verdant_integration.ble_stream import (
    FragmentedJsonStreamParser,
    extract_safe_get_dev_status,
)


class FragmentedParserTests(unittest.TestCase):
    def test_reassembles_fragmented_json(self) -> None:
        parser = FragmentedJsonStreamParser()
        part1 = b"\x01\x02garbage{\"method\":\"getDevSta\",\"data\":{\"sensor\":"
        part2 = b"{\"temp\":23.3,\"humi\":37.7,\"vpd\":1.78},\"fan\":{\"level\":5,\"on\":1}}}"

        self.assertEqual(parser.feed(part1), [])
        parsed = parser.feed(part2)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["data"]["sensor"]["temp"], 23.3)
        self.assertEqual(parsed[0]["data"]["fan"]["level"], 5)
        self.assertEqual(
            extract_safe_get_dev_status(parsed[0]),
            {
                "method": "getDevSta",
                "data": {
                    "sensor": {"temp": 23.3, "humi": 37.7, "vpd": 1.78},
                    "fan": {"on": 1, "level": 5},
                },
            },
        )

    def test_multiple_json_messages_in_single_chunk(self) -> None:
        parser = FragmentedJsonStreamParser()
        payload = '{"a":1}{"b":2}'
        parsed = parser.feed(payload)
        self.assertEqual(parsed, [{"a": 1}, {"b": 2}])
        self.assertTrue(all(extract_safe_get_dev_status(message) is None for message in parsed))

    def test_overflow_resets_but_keeps_latest_json_start(self) -> None:
        parser = FragmentedJsonStreamParser(max_buffer_chars=20)
        parser.feed("noise-noise-noise")
        parsed = parser.feed('{"ok":1}')
        self.assertEqual(parsed, [{"ok": 1}])

    def test_synthetic_non_utf8_frame_with_json_tail_is_not_live(self) -> None:
        parser = FragmentedJsonStreamParser()
        synthetic_non_utf8 = b'\xff\xfe{"a":1}'  # SYNTHETIC; not a controller frame.

        parsed = parser.feed(synthetic_non_utf8)

        self.assertEqual(parsed, [])

    def test_synthetic_binary_frame_breaks_fragment_reassembly(self) -> None:
        parser = FragmentedJsonStreamParser()
        synthetic_partial = '{"a":'  # SYNTHETIC; not a controller frame.
        synthetic_binary = b"\x80\x81\xff"  # SYNTHETIC; not a controller frame.

        self.assertEqual(parser.feed(synthetic_partial), [])
        self.assertEqual(parser.feed(synthetic_binary), [])
        self.assertEqual(parser.feed("1}"), [])

    def test_synthetic_opaque_plaintext_is_not_json_or_live(self) -> None:
        parser = FragmentedJsonStreamParser()
        synthetic_opaque_text = b"U1lOVEhFVElDX09QQVFVRV9URVhU"  # SYNTHETIC.

        self.assertEqual(parser.feed(synthetic_opaque_text), [])

    def test_safe_status_projection_drops_unallowlisted_values(self) -> None:
        synthetic_status = {  # SYNTHETIC; not a captured controller frame.
            "method": "getDevSta",
            "ble_address": "SYNTHETIC_BLE_ADDRESS",
            "data": {
                "sensor": {
                    "temp": 23.3,
                    "humi": 37.7,
                    "vpd": 1.78,
                    "credential": "SYNTHETIC_CREDENTIAL_VALUE",
                },
                "fan": {"on": 1, "level": 5},
                "token": "SYNTHETIC_TOKEN_VALUE",
            },
        }

        safe = extract_safe_get_dev_status(synthetic_status)

        self.assertIsNotNone(safe)
        self.assertNotIn("SYNTHETIC", repr(safe))

    def test_incomplete_status_is_not_live(self) -> None:
        synthetic_incomplete = {  # SYNTHETIC; not a captured controller frame.
            "method": "getDevSta",
            "data": {"sensor": {"temp": 23.3, "humi": 37.7, "vpd": 1.78}},
        }

        self.assertIsNone(extract_safe_get_dev_status(synthetic_incomplete))


class ReceiveOnlySnifferTests(unittest.TestCase):
    def test_sniffer_is_name_bound_ff01_receive_only(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "ggs_ff00_sniffer.py").read_text(encoding="utf-8").lower()

        self.assertIn("sf-ggs-cb", source)
        self.assertIn("0000ff01-0000-1000-8000-00805f9b34fb", source)
        self.assertNotIn("0000ff02", source)
        self.assertNotIn("write_gatt", source)
        self.assertNotIn("read_gatt", source)
        self.assertNotIn(".address", source)
        self.assertNotIn("open(", source)
        self.assertNotIn("write_text", source)
        self.assertNotIn("write_bytes", source)
        self.assertNotIn("mqtt", source)
        self.assertNotIn("http", source)

    def test_implementation_has_no_decryption_guess_or_lossy_decode(self) -> None:
        root = Path(__file__).resolve().parents[1]
        parser_source = (root / "verdant_integration" / "ble_stream.py").read_text(
            encoding="utf-8"
        )
        implementation = parser_source.lower()

        self.assertIn('errors="strict"', parser_source)
        self.assertNotIn('errors="ignore"', parser_source)
        self.assertNotIn("decrypt", implementation)
        self.assertNotIn("cryptography", implementation)
        self.assertNotIn("padding", implementation)
        self.assertNotIn("aes", implementation)


if __name__ == "__main__":
    unittest.main()
