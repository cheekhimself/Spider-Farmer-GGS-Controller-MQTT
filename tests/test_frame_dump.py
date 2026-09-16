import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.frame_codec import (
    ERROR_INVALID_LENGTH,
    ERROR_PLAINTEXT_JSON,
    ERROR_TRUNCATED,
)
from verdant_integration.frame_dump import (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_OVERSIZED,
    COMPLETENESS_PLAINTEXT,
    COMPLETENESS_TRUNCATED,
    COMPLETENESS_UNKNOWN,
    CaptureStats,
    apply_dump,
    inspect_notification,
    main as dump_main,
    write_complete_frame,
)


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> bytes:
    text = (FIXTURE_DIR / name).read_text(encoding="ascii")
    return bytes.fromhex("".join(text.split()))


class CompleteFramedDumpTests(unittest.TestCase):
    def test_complete_framed_fixture_is_dumpable(self) -> None:
        buffer = _load_fixture("frame_422.hex")
        inspect = inspect_notification(buffer)
        self.assertEqual(inspect.completeness, COMPLETENESS_COMPLETE)
        self.assertEqual(inspect.observed_bytes, 422)
        self.assertEqual(inspect.expected_bytes, 422)
        self.assertIsNotNone(inspect.frame_bytes)
        self.assertEqual(inspect.frame_bytes, buffer)

        with tempfile.TemporaryDirectory() as tmp:
            path = write_complete_frame(Path(tmp), inspect, index=1)
            self.assertIsNotNone(path)
            written = bytes.fromhex(path.read_text(encoding="ascii").strip())
            self.assertEqual(written, buffer)
            self.assertEqual(len(written), 422)


class TruncatedAndWrongLengthTests(unittest.TestCase):
    def test_truncated_prefix_is_not_dumped(self) -> None:
        buffer = _load_fixture("frame_422.hex")[:20]
        inspect = inspect_notification(buffer)
        self.assertEqual(inspect.completeness, COMPLETENESS_TRUNCATED)
        self.assertEqual(inspect.parsed.error, ERROR_TRUNCATED)
        self.assertIsNone(inspect.frame_bytes)
        self.assertEqual(inspect.expected_bytes, 422)
        self.assertEqual(inspect.observed_bytes, 20)

        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(write_complete_frame(Path(tmp), inspect, index=1))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_wrong_declared_length_is_unknown_not_padded(self) -> None:
        buffer = b"\xaa\xaa\x00\x03\xff\xff" + bytes(8)
        inspect = inspect_notification(buffer)
        self.assertEqual(inspect.completeness, COMPLETENESS_UNKNOWN)
        self.assertEqual(inspect.parsed.error, ERROR_INVALID_LENGTH)
        self.assertIsNone(inspect.frame_bytes)

    def test_oversized_buffer_is_not_dumped(self) -> None:
        buffer = _load_fixture("frame_230.hex") + b"\x00\x01"
        inspect = inspect_notification(buffer)
        self.assertEqual(inspect.completeness, COMPLETENESS_OVERSIZED)
        self.assertTrue(inspect.parsed.ok)
        self.assertIsNone(inspect.frame_bytes)
        with tempfile.TemporaryDirectory() as tmp:
            stats = CaptureStats()
            self.assertIsNone(apply_dump(stats, inspect, Path(tmp)))
            self.assertEqual(stats.oversized, 1)
            self.assertEqual(stats.dumped, 0)
            self.assertEqual(list(Path(tmp).iterdir()), [])


class PlaintextRejectTests(unittest.TestCase):
    def test_plaintext_json_is_not_complete(self) -> None:
        plaintext = b'{"method":"getDevSta","data":{"sensor":{"temp":1}}}'
        inspect = inspect_notification(plaintext)
        self.assertEqual(inspect.completeness, COMPLETENESS_PLAINTEXT)
        self.assertEqual(inspect.parsed.error, ERROR_PLAINTEXT_JSON)
        self.assertIsNone(inspect.frame_bytes)


class CaptureStatsAndCliTests(unittest.TestCase):
    def test_stats_buckets(self) -> None:
        stats = CaptureStats()
        apply_dump(stats, inspect_notification(_load_fixture("frame_246.hex")), None)
        apply_dump(stats, inspect_notification(_load_fixture("frame_246.hex")[:10]), None)
        apply_dump(stats, inspect_notification(b'{"a":1}'), None)
        apply_dump(stats, inspect_notification(b"\x00\x01\x02\x03\x04\x05"), None)
        summary = stats.as_summary()
        self.assertEqual(summary["COMPLETE"], 1)
        self.assertEqual(summary["TRUNCATED"], 1)
        self.assertEqual(summary["PLAINTEXT"], 1)
        self.assertEqual(summary["UNKNOWN"], 1)
        self.assertEqual(summary["dumped"], 0)

    def test_cli_dumps_only_complete(self) -> None:
        buffer = _load_fixture("frame_230.hex")
        with tempfile.TemporaryDirectory() as tmp:
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = dump_main(["--hex", buffer.hex(), "--dump-frames", tmp])
            report = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["completeness"], COMPLETENESS_COMPLETE)
            files = list(Path(tmp).glob("*.hex"))
            self.assertEqual(len(files), 1)
            self.assertEqual(bytes.fromhex(files[0].read_text().strip()), buffer)

    def test_cli_hex_file_complete(self) -> None:
        fixture = FIXTURE_DIR / "frame_246.hex"
        with tempfile.TemporaryDirectory() as tmp:
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = dump_main(["--hex-file", str(fixture), "--dump-frames", tmp])
            report = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(report["completeness"], COMPLETENESS_COMPLETE)
            self.assertEqual(len(list(Path(tmp).glob("*.hex"))), 1)

    def test_cli_truncated_exit_nonzero_no_file(self) -> None:
        buffer = _load_fixture("frame_230.hex")[:12]
        with tempfile.TemporaryDirectory() as tmp:
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = dump_main(["--hex", buffer.hex(), "--dump-frames", tmp])
            report = json.loads(stdout.getvalue())
            self.assertEqual(status, 1)
            self.assertEqual(report["completeness"], COMPLETENESS_TRUNCATED)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_dump_source_has_no_crypto_or_mqtt(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "verdant_integration" / "frame_dump.py").read_text(
            encoding="utf-8"
        )
        lowered = source.lower()
        self.assertNotIn("from cryptography", lowered)
        self.assertNotIn(".decrypt", lowered)
        self.assertNotIn("aes", lowered)
        self.assertNotIn("mqtt", lowered)
        self.assertNotIn(".address", lowered)
