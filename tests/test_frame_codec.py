import json
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.ble_stream import FragmentedJsonStreamParser
from verdant_integration.frame_codec import (
    ERROR_INVALID_LENGTH,
    ERROR_NOT_FRAMED,
    ERROR_PLAINTEXT_JSON,
    ERROR_TOO_SHORT,
    ERROR_TRUNCATED,
    FrameCodec,
    main as frame_codec_main,
)


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# Redacted prefixes from Cheek 2026-09-16; padded with 0x00 to observed sizes.
# SYNTHETIC; not live controller captures and not MACs.
SIZE_CLASSES = (
    ("frame_422.hex", 422, 414),
    ("frame_390.hex", 390, 382),
    ("frame_246.hex", 246, 238),
    ("frame_230.hex", 230, 222),
)


def _load_fixture(name: str) -> bytes:
    text = (FIXTURE_DIR / name).read_text(encoding="ascii")
    return bytes.fromhex("".join(text.split()))


class FrameCodecSizeClassTests(unittest.TestCase):
    def test_parses_observed_size_classes(self) -> None:
        for name, total, declared in SIZE_CLASSES:
            with self.subTest(name=name):
                buffer = _load_fixture(name)
                self.assertEqual(len(buffer), total)
                result = FrameCodec.parse(buffer)
                self.assertTrue(result.ok, result.error)
                self.assertIsNone(result.error)
                self.assertEqual(result.length, declared)
                self.assertEqual(result.header, buffer[:6])
                self.assertEqual(result.header[:4], b"\xaa\xaa\x00\x03")
                self.assertEqual(len(result.payload), total - 6)
                self.assertEqual(result.leftover, b"")
                self.assertTrue(FrameCodec.looks_framed(buffer))

    def test_leftover_bytes_after_one_complete_frame(self) -> None:
        buffer = _load_fixture("frame_230.hex") + b"\x00\x01"
        result = FrameCodec.parse(buffer)
        self.assertTrue(result.ok)
        self.assertEqual(result.length, 222)
        self.assertEqual(result.leftover, b"\x00\x01")


class FrameCodecRejectTests(unittest.TestCase):
    def test_rejects_plaintext_json(self) -> None:
        plaintext = b'{"method":"getDevSta","data":{"sensor":{"temp":1}}}'
        result = FrameCodec.parse(plaintext)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, ERROR_PLAINTEXT_JSON)
        self.assertFalse(FrameCodec.looks_framed(plaintext))
        self.assertTrue(FrameCodec.looks_plaintext_json(plaintext))

    def test_rejects_whitespace_prefixed_json(self) -> None:
        result = FrameCodec.parse(b'  {"a":1}')
        self.assertFalse(result.ok)
        self.assertEqual(result.error, ERROR_PLAINTEXT_JSON)

    def test_rejects_too_short(self) -> None:
        result = FrameCodec.parse(b"\xaa\xaa\x00")
        self.assertFalse(result.ok)
        self.assertEqual(result.error, ERROR_TOO_SHORT)

    def test_rejects_garbage(self) -> None:
        result = FrameCodec.parse(b"\x00\x01\x02\x03\x04\x05")
        self.assertFalse(result.ok)
        self.assertEqual(result.error, ERROR_NOT_FRAMED)

    def test_rejects_truncated_framed_buffer(self) -> None:
        buffer = _load_fixture("frame_422.hex")[:20]
        result = FrameCodec.parse(buffer)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, ERROR_TRUNCATED)
        self.assertEqual(result.length, 414)
        self.assertEqual(result.header, buffer[:6])

    def test_rejects_declared_length_over_cap(self) -> None:
        buffer = b"\xaa\xaa\x00\x03\xff\xff" + bytes(8)
        result = FrameCodec.parse(buffer)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, ERROR_INVALID_LENGTH)
        self.assertEqual(result.length, 65535)


class FrameCodecDoesNotWeakenJsonParserTests(unittest.TestCase):
    def test_json_brace_parser_still_rejects_framed_bytes(self) -> None:
        framed = _load_fixture("frame_246.hex")
        parser = FragmentedJsonStreamParser()
        self.assertEqual(parser.feed(framed), [])

    def test_cli_prints_header_and_length_only(self) -> None:
        buffer = _load_fixture("frame_246.hex")
        with patch("sys.stdout", new=StringIO()) as stdout:
            status = frame_codec_main(["--hex", buffer.hex()])
        printed = stdout.getvalue()
        summary = json.loads(printed)
        self.assertEqual(status, 0)
        self.assertEqual(summary["length"], 238)
        self.assertEqual(summary["header"], buffer[:6].hex())
        self.assertNotIn("payload", summary)
        self.assertNotIn(buffer[8:24].hex(), printed)

    def test_codec_source_has_no_crypto(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "verdant_integration" / "frame_codec.py").read_text(
            encoding="utf-8"
        )
        lowered = source.lower()
        self.assertNotIn("from cryptography", lowered)
        self.assertNotIn(".decrypt", lowered)
        self.assertNotIn("aes", lowered)
        self.assertNotIn("derive", lowered)


if __name__ == "__main__":
    unittest.main()
