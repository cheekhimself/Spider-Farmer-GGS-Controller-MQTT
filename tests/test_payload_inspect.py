import json
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.payload_inspect import (
    DECRYPT_NO_PLAINTEXT_FIXTURE,
    DECRYPT_REFUSED,
    attempt_framed_decrypt,
    inspect_frame,
    main as inspect_main,
    shannon_entropy_bits,
)


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# Live size classes 422/390/230; 246 is the earlier continuation class.
SIZE_CLASSES = (
    ("frame_422.hex", 422, 414),
    ("frame_390.hex", 390, 382),
    ("frame_230.hex", 230, 222),
)


def _load_fixture(name: str) -> bytes:
    text = (FIXTURE_DIR / name).read_text(encoding="ascii")
    return bytes.fromhex("".join(text.split()))


class FixtureLoadingTests(unittest.TestCase):
    def test_live_size_class_fixtures_exist(self) -> None:
        for name, total, declared in SIZE_CLASSES:
            with self.subTest(name=name):
                buffer = _load_fixture(name)
                self.assertEqual(len(buffer), total)
                self.assertEqual(int.from_bytes(buffer[4:6], "big"), declared)


class PayloadInspectTests(unittest.TestCase):
    def test_splits_header_and_opaque_body(self) -> None:
        for name, total, declared in SIZE_CLASSES:
            with self.subTest(name=name):
                buffer = _load_fixture(name)
                report = inspect_frame(buffer)
                self.assertTrue(report["ok"], report)
                self.assertIsNone(report["error"])
                self.assertEqual(report["header"], buffer[:6].hex())
                self.assertEqual(report["body_bytes"], total - 6)
                self.assertEqual(report["declared_length"], declared)
                self.assertEqual(report["leftover_bytes"], 0)
                stats = report["stats"]
                assert isinstance(stats, dict)
                self.assertEqual(stats["length"], total - 6)
                self.assertNotIn("body", report)
                self.assertLess(stats["shannon_entropy_bits"], 2.0)
                self.assertGreater(stats["zero_fraction"], 0.5)

    def test_hypotheses_are_labeled_and_layout_consistent(self) -> None:
        buffer = _load_fixture("frame_422.hex")
        report = inspect_frame(buffer)
        hypotheses = report["hypotheses"]
        assert isinstance(hypotheses, dict)
        self.assertEqual(hypotheses["label"], "hypothesis_only")
        self.assertTrue(hypotheses["layout_consistent"])
        self.assertEqual(hypotheses["message_type_u16be"], 2)
        self.assertEqual(hypotheses["chunk_offset_u32be"], 0)
        self.assertEqual(hypotheses["chunk_length_u16be"], 400)
        self.assertEqual(hypotheses["total_ciphertext_u32be"], 624)
        self.assertEqual(hypotheses["chunk_length_mod_16"], 0)
        self.assertFalse(hypotheses["trailer_crc16_modbus_matches"])
        self.assertIn("hypothesis", json.dumps(hypotheses))

    def test_422_and_246_reassembly_arithmetic_is_hypothesis(self) -> None:
        first = inspect_frame(_load_fixture("frame_422.hex"))["hypotheses"]
        second = inspect_frame(_load_fixture("frame_246.hex"))["hypotheses"]
        assert isinstance(first, dict) and isinstance(second, dict)
        self.assertEqual(first["chunk_offset_u32be"] + first["chunk_length_u16be"], 400)
        self.assertEqual(second["chunk_offset_u32be"], 400)
        self.assertEqual(
            first["chunk_length_u16be"] + second["chunk_length_u16be"],
            first["total_ciphertext_u32be"],
        )

    def test_rejects_plaintext_json_without_hypotheses(self) -> None:
        report = inspect_frame(b'{"method":"getDevSta"}')
        self.assertFalse(report["ok"])
        self.assertEqual(report["error"], "plaintext_json")
        self.assertIsNone(report["hypotheses"])
        self.assertEqual(report["body_bytes"], 0)

    def test_cli_omits_full_body_and_can_show_decrypt_refusal(self) -> None:
        buffer = _load_fixture("frame_230.hex")
        with patch("sys.stdout", new=StringIO()) as stdout:
            status = inspect_main(["--hex", buffer.hex(), "--attempt-decrypt"])
        printed = stdout.getvalue()
        payload = json.loads(printed)
        self.assertEqual(status, 0)
        self.assertTrue(payload["ok"])
        self.assertNotIn("payload", payload)
        self.assertFalse(payload["decrypt"]["claimed_success"])
        self.assertFalse(payload["decrypt"]["ok"])
        self.assertIn(DECRYPT_REFUSED, payload["decrypt"]["reason"])


class DecryptStubTests(unittest.TestCase):
    def test_refuses_without_plaintext_fixture(self) -> None:
        result = attempt_framed_decrypt(_load_fixture("frame_390.hex"))
        self.assertFalse(result.ok)
        self.assertFalse(result.claimed_success)
        self.assertFalse(result.known_good_plaintext_provided)
        self.assertIn(DECRYPT_NO_PLAINTEXT_FIXTURE, result.reason)

    def test_refuses_even_when_plaintext_bytes_are_supplied(self) -> None:
        pretend = b'{"method":"getDevSta","data":{"sensor":{"temp":1}}}'
        result = attempt_framed_decrypt(
            _load_fixture("frame_422.hex"),
            known_good_plaintext=pretend,
        )
        self.assertFalse(result.ok)
        self.assertFalse(result.claimed_success)
        self.assertTrue(result.known_good_plaintext_provided)
        self.assertIn(DECRYPT_REFUSED, result.reason)

    def test_stub_source_does_not_embed_key_material(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "verdant_integration" / "payload_inspect.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("from cryptography", source)
        self.assertNotIn(".decrypt(", source)
        self.assertNotIn("KEY =", source)
        self.assertNotIn("IV =", source)

    def test_shannon_entropy_of_zeros_is_zero(self) -> None:
        self.assertEqual(shannon_entropy_bits(b""), 0.0)
        self.assertEqual(shannon_entropy_bits(b"\x00\x00\x00"), 0.0)


if __name__ == "__main__":
    unittest.main()
