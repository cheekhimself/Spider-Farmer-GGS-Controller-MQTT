import json
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.frame_crc import (
    HYPOTHESIS_CCITT_TRAILER,
    HYPOTHESIS_CRC32_LAST4,
    HYPOTHESIS_PER_FRAME_MODBUS,
    HYPOTHESIS_XMODEM_TRAILER,
    HYPOTHESIS_XOR_LAST_BYTE,
    check_complete_frame_crc,
    classify_dump_dir,
    main as crc_main,
)
from verdant_integration.frame_dump import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_TRUNCATED,
)


LIVE_DIR = Path(__file__).resolve().parent / "fixtures" / "live_phase3"
PADDED_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_hex_file(path: Path) -> bytes:
    return bytes.fromhex("".join(path.read_text(encoding="ascii").split()))


def _live_files() -> list[Path]:
    return sorted(LIVE_DIR.glob("*.hex"))


class LiveFixtureProvenanceTests(unittest.TestCase):
    def test_live_dump_counts_and_nonzero_bodies(self) -> None:
        files = _live_files()
        self.assertEqual(len(files), 45)
        by_size: dict[int, int] = {}
        for path in files:
            buffer = _load_hex_file(path)
            by_size[len(buffer)] = by_size.get(len(buffer), 0) + 1
            nonzero = sum(1 for byte in buffer if byte)
            if len(buffer) == 422:
                self.assertGreaterEqual(nonzero, 400)
            elif len(buffer) == 230:
                self.assertGreaterEqual(nonzero, 200)
            elif len(buffer) == 54:
                self.assertGreaterEqual(nonzero, 40)
            else:
                self.fail(f"unexpected size {len(buffer)} in {path.name}")
        self.assertEqual(by_size.get(422), 28)
        self.assertEqual(by_size.get(54), 11)
        self.assertEqual(by_size.get(230), 6)

    def test_padded_research_fixtures_are_not_crc_truth(self) -> None:
        padded = _load_hex_file(PADDED_DIR / "frame_422.hex")
        live = _load_hex_file(LIVE_DIR / "0001_422b_len414.hex")
        self.assertEqual(len(padded), 422)
        self.assertGreater(padded.count(0), 400)
        self.assertLess(live.count(0), 20)
        result = check_complete_frame_crc(padded)
        self.assertEqual(result.completeness, COMPLETENESS_COMPLETE)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "crc_mismatch")


class ProvenTrailerCrcTests(unittest.TestCase):
    def test_all_live_frames_pass_modbus_trailer(self) -> None:
        for path in _live_files():
            with self.subTest(name=path.name):
                result = check_complete_frame_crc(_load_hex_file(path))
                self.assertTrue(result.ok, result.as_summary())
                self.assertIsNone(result.error)
                self.assertEqual(result.completeness, COMPLETENESS_COMPLETE)
                names = {item.name: item for item in result.hypotheses}
                self.assertEqual(names[HYPOTHESIS_PER_FRAME_MODBUS].status, "PASS")
                self.assertTrue(names[HYPOTHESIS_PER_FRAME_MODBUS].proven)
                self.assertEqual(names[HYPOTHESIS_XMODEM_TRAILER].status, "FAIL")
                self.assertEqual(names[HYPOTHESIS_CCITT_TRAILER].status, "FAIL")
                self.assertEqual(names[HYPOTHESIS_CRC32_LAST4].status, "FAIL")
                self.assertEqual(names[HYPOTHESIS_XOR_LAST_BYTE].status, "FAIL")
                self.assertFalse(names[HYPOTHESIS_XMODEM_TRAILER].proven)

    def test_flipped_byte_fails_closed(self) -> None:
        buffer = bytearray(_load_hex_file(LIVE_DIR / "0003_54b_len46.hex"))
        self.assertTrue(check_complete_frame_crc(bytes(buffer)).ok)
        buffer[30] ^= 0x01
        result = check_complete_frame_crc(bytes(buffer))
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "crc_mismatch")

    def test_truncated_is_not_padded_or_crc_passed(self) -> None:
        buffer = _load_hex_file(LIVE_DIR / "0001_422b_len414.hex")[:40]
        result = check_complete_frame_crc(buffer)
        self.assertFalse(result.ok)
        self.assertEqual(result.completeness, COMPLETENESS_TRUNCATED)
        self.assertIsNone(result.expected_crc_hex)
        self.assertEqual(result.hypotheses, ())

    def test_dir_classifier_passes_live_corpus(self) -> None:
        report = classify_dump_dir(LIVE_DIR)
        self.assertEqual(report["files"], 45)
        self.assertEqual(report["crc_pass"], 45)
        self.assertEqual(report["crc_fail"], 0)

    def test_cli_dir_and_single_file(self) -> None:
        with patch("sys.stdout", new=StringIO()) as stdout:
            status = crc_main(["--dir", str(LIVE_DIR)])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["crc_pass"], 45)
        live = LIVE_DIR / "0005_230b_len222.hex"
        with patch("sys.stdout", new=StringIO()) as stdout:
            status = crc_main(["--hex-file", str(live)])
        row = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(row["ok"])
        self.assertNotIn("payload", row)

    def test_source_has_no_decrypt_or_mqtt(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "verdant_integration" / "frame_crc.py").read_text(
            encoding="utf-8"
        )
        lowered = source.lower()
        self.assertNotIn("from cryptography", lowered)
        self.assertNotIn(".decrypt", lowered)
        self.assertNotIn("mqtt", lowered)
        self.assertNotIn("aes", lowered)


if __name__ == "__main__":
    unittest.main()
