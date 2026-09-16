import json
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.crc16 import crc16_modbus_be_bytes
from verdant_integration.payload_inspect import inspect_frame
from verdant_integration.reassembly import (
    load_hex_dir,
    main as reassembly_main,
    parse_chunk_view,
    reassemble_dump_frames,
    reassemble_group,
)


LIVE_DIR = Path(__file__).resolve().parent / "fixtures" / "live_phase3"
PADDED_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_hex_file(path: Path) -> bytes:
    return bytes.fromhex("".join(path.read_text(encoding="ascii").split()))


class InnerLayoutTests(unittest.TestCase):
    def test_live_layout_fits_all_size_classes(self) -> None:
        counts = {422: 0, 230: 0, 54: 0}
        for path in sorted(LIVE_DIR.glob("*.hex")):
            buffer = _load_hex_file(path)
            view = parse_chunk_view(buffer)
            self.assertIsNotNone(view, path.name)
            assert view is not None
            self.assertEqual(view.chunk_length, len(view.chunk))
            self.assertEqual(20 + view.chunk_length + 2, len(buffer))
            self.assertLessEqual(view.offset + view.chunk_length, view.total_ciphertext)
            if len(buffer) == 422:
                self.assertEqual(view.chunk_length, 400)
                self.assertIn(view.offset, (0, 400))
                self.assertIn(view.total_ciphertext, (832, 608))
            elif len(buffer) == 230:
                self.assertEqual(view.offset, 400)
                self.assertEqual(view.chunk_length, 208)
                self.assertEqual(view.total_ciphertext, 608)
            elif len(buffer) == 54:
                self.assertEqual(view.offset, 800)
                self.assertEqual(view.chunk_length, 32)
                self.assertEqual(view.total_ciphertext, 832)
            else:
                self.fail(path.name)
            counts[len(buffer)] += 1
        self.assertEqual(counts, {422: 28, 230: 6, 54: 11})

    def test_payload_inspect_trailer_matches_on_live_not_padded(self) -> None:
        live = inspect_frame(_load_hex_file(LIVE_DIR / "0001_422b_len414.hex"))
        hypotheses = live["hypotheses"]
        assert isinstance(hypotheses, dict)
        self.assertTrue(hypotheses["layout_consistent"])
        self.assertTrue(hypotheses["trailer_crc16_modbus_matches"])
        padded = inspect_frame(_load_hex_file(PADDED_DIR / "frame_422.hex"))
        padded_h = padded["hypotheses"]
        assert isinstance(padded_h, dict)
        self.assertFalse(padded_h["trailer_crc16_modbus_matches"])


class ReassemblyTests(unittest.TestCase):
    def test_live_dir_emits_seventeen_ciphertext_candidates(self) -> None:
        frames = load_hex_dir(LIVE_DIR)
        self.assertEqual(len(frames), 45)
        results = reassemble_dump_frames(frames)
        ok = [item for item in results if item.ok]
        self.assertEqual(len(ok), 17)
        totals = sorted(item.total_ciphertext for item in ok)
        self.assertEqual(totals.count(832), 11)
        self.assertEqual(totals.count(608), 6)
        for item in ok:
            self.assertFalse(item.claimed_plaintext)
            self.assertFalse(item.claimed_decrypt)
            self.assertIsNotNone(item.assembled)
            assert item.assembled is not None
            self.assertEqual(len(item.assembled), item.total_ciphertext)
            self.assertEqual(
                crc16_modbus_be_bytes(item.assembled).hex(),
                item.message_crc_hex,
            )

    def test_first_832_group_tiles_400_400_32(self) -> None:
        group = [
            _load_hex_file(LIVE_DIR / "0001_422b_len414.hex"),
            _load_hex_file(LIVE_DIR / "0002_422b_len414.hex"),
            _load_hex_file(LIVE_DIR / "0003_54b_len46.hex"),
        ]
        result = reassemble_group(group)
        self.assertTrue(result.ok, result.as_summary())
        self.assertEqual(result.chunk_count, 3)
        self.assertEqual(result.total_ciphertext, 832)
        self.assertEqual(result.assembled_bytes, 832)

    def test_incomplete_group_does_not_emit(self) -> None:
        group = [
            _load_hex_file(LIVE_DIR / "0001_422b_len414.hex"),
            _load_hex_file(LIVE_DIR / "0002_422b_len414.hex"),
        ]
        result = reassemble_group(group)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "incomplete_coverage")
        self.assertIsNone(result.assembled)
        self.assertFalse(result.claimed_decrypt)

    def test_overlap_conflict_fails_closed(self) -> None:
        original = _load_hex_file(LIVE_DIR / "0001_422b_len414.hex")
        mutated = bytearray(original)
        mutated[20] ^= 0x01
        mutated[-2:] = crc16_modbus_be_bytes(bytes(mutated[:-2]))
        result = reassemble_group([original, bytes(mutated)])
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "chunk_overlap_conflict")
        self.assertIsNone(result.assembled)

    def test_padded_frame_is_rejected_by_crc_before_reassembly(self) -> None:
        padded = _load_hex_file(PADDED_DIR / "frame_422.hex")
        result = reassemble_group([padded])
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "crc_mismatch")
        self.assertIsNone(result.assembled)

    def test_cli_emits_counts_without_claiming_decrypt(self) -> None:
        with patch("sys.stdout", new=StringIO()) as stdout:
            status = reassembly_main(["--dir", str(LIVE_DIR)])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["emitted_candidates"], 17)
        self.assertFalse(payload["claimed_decrypt"])
        self.assertFalse(payload["claimed_plaintext"])
        self.assertNotIn("assembled_hex", json.dumps(payload))

    def test_source_has_no_crypto_keys(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "verdant_integration" / "reassembly.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("from cryptography", source)
        self.assertNotIn(".decrypt(", source)
        self.assertNotIn("KEY =", source)
        self.assertNotIn("IV =", source)
        self.assertNotIn("mqtt", source.lower())


if __name__ == "__main__":
    unittest.main()
