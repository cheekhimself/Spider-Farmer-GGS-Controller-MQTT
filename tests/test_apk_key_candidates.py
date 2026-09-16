import json
import tempfile
import unittest
import zipfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.apk_key_candidates import (
    REFUSE_DOWNLOAD,
    REFUSE_TRACKED_OUT,
    allowed_output_path,
    harvest_path,
    harvest_text,
    main as apk_main,
    ranked_candidates,
    refuse_remote_path,
)


ROOT = Path(__file__).resolve().parents[1]
# Synthetic only — not a vendor secret.
SYN_KEY_ASCII = b"TESTKEYTESTKEY12"
SYN_IV_HEX = "00112233445566778899aabbccddeeff"
SYN_KEY_HEX32 = "ffeeddccbbaa99887766554433221100"


class CandidateFilterTests(unittest.TestCase):
    def test_ranks_quoted_aes_ascii_and_hex_near_keywords(self) -> None:
        blob = (
            b'SecretKeySpec("' + SYN_KEY_ASCII + b'") AES/CBC '
            b"IvParameterSpec " + SYN_IV_HEX.encode("ascii") + b" "
            + SYN_KEY_HEX32.encode("ascii")
        )
        pool = {}
        harvest_text(blob, pool)
        ranked = ranked_candidates(pool)
        hexs = {item.hex for item in ranked}
        self.assertIn(SYN_KEY_ASCII.hex(), hexs)
        self.assertIn(SYN_IV_HEX, hexs)
        self.assertIn(SYN_KEY_HEX32, hexs)
        by_hex = {item.hex: item for item in ranked}
        self.assertGreater(by_hex[SYN_KEY_ASCII.hex()].score, 0)
        self.assertIn(by_hex[SYN_IV_HEX].kind, {"iv", "key_or_iv"})
        isolated = {}
        harvest_text(b"IvParameterSpec " + SYN_IV_HEX.encode("ascii"), isolated)
        self.assertEqual(ranked_candidates(isolated)[0].kind, "iv")
        self.assertEqual(by_hex[SYN_KEY_ASCII.hex()].length, 16)

    def test_rejects_ble_uuid_shaped_hex(self) -> None:
        blob = b"0000ff0100001000800000805f9b34fb AES/CBC"
        pool = {}
        harvest_text(blob, pool)
        self.assertEqual(pool, {})

    def test_ignores_wrong_lengths(self) -> None:
        pool = {}
        harvest_text(b"SecretKeySpec(\"short\") 00112233", pool)
        self.assertEqual(pool, {})

    def test_constant_bytes_rank_below_keyword_hit(self) -> None:
        blob = (
            b'SecretKeySpec("' + SYN_KEY_ASCII + b'") '
            + (b"00" * 16)
        )
        pool = {}
        harvest_text(blob, pool)
        ranked = ranked_candidates(pool)
        self.assertGreater(ranked[0].score, ranked[-1].score)


class PathPolicyTests(unittest.TestCase):
    def test_refuses_remote_urls(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            refuse_remote_path("https://example.com/app.apk")
        self.assertEqual(str(raised.exception), REFUSE_DOWNLOAD)

    def test_output_path_allows_operator_local_only_inside_repo(self) -> None:
        self.assertTrue(
            allowed_output_path(ROOT / "operator_local" / "candidates.txt", repo_root=ROOT)
        )
        self.assertFalse(allowed_output_path(ROOT / "tests" / "keys.txt", repo_root=ROOT))
        self.assertFalse(
            allowed_output_path(ROOT / "verdant_integration" / "keys.json", repo_root=ROOT)
        )
        self.assertTrue(allowed_output_path(Path("/tmp/operator_keys.json"), repo_root=ROOT))

    def test_cli_refuses_tracked_out_and_download(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            apk_main(["https://example.com/x.apk"])
        self.assertEqual(str(raised.exception), REFUSE_DOWNLOAD)
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as handle:
            path = Path(handle.name)
            handle.write(b'SecretKeySpec("' + SYN_KEY_ASCII + b'")')
        try:
            with self.assertRaises(SystemExit) as raised:
                apk_main([str(path), "--out", str(ROOT / "docs" / "keys.json")])
            self.assertEqual(str(raised.exception), REFUSE_TRACKED_OUT)
        finally:
            path.unlink()


class ApkZipHarvestTests(unittest.TestCase):
    def test_local_zip_apk_is_scanned_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "local.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr(
                    "assets/notes.txt",
                    b'AES/CBC SecretKeySpec("' + SYN_KEY_ASCII + b'")',
                )
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = apk_main([str(apk)])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertFalse(payload["proven_vendor_key"])
            self.assertFalse(payload["claimed_decrypt"])
            self.assertGreaterEqual(payload["candidate_count"], 1)
            self.assertIn(SYN_KEY_ASCII.hex(), {row["hex"] for row in payload["candidates"]})

    def test_strings_file_and_try_key_file_under_tmp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            strings = Path(tmp) / "strings.txt"
            strings.write_bytes(
                b'SecretKeySpec("' + SYN_KEY_ASCII + b'") IvParameterSpec '
                + SYN_IV_HEX.encode("ascii")
                + b"\n"
            )
            out_keys = Path(tmp) / "candidates.txt"
            with patch("sys.stdout", new=StringIO()):
                status = apk_main([str(strings), "--try-key-file", str(out_keys)])
            self.assertEqual(status, 0)
            text = out_keys.read_text(encoding="ascii")
            self.assertIn(SYN_IV_HEX, text)
            self.assertIn("Do not commit", text)

    def test_harvest_path_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "jadx"
            folder.mkdir()
            (folder / "Foo.java").write_bytes(
                b'SecretKeySpec("' + SYN_KEY_ASCII + b'")'
            )
            pool = harvest_path(folder)
            self.assertIn(SYN_KEY_ASCII.hex(), pool)


if __name__ == "__main__":
    unittest.main()
