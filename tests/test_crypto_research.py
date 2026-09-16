import json
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.crypto_research import (
    AES_BLOCK,
    DECRYPT_MISMATCH,
    DECRYPT_NO_KEY_MATERIAL,
    DECRYPT_NO_PLAINTEXT_FIXTURE,
    DECRYPT_REFUSED,
    HYPOTHESIS_JSON_CRIB,
    INVALID_HEX,
    PUBLIC_ISSUE4_SAMPLE_HEX,
    analyze_assemblies,
    common_prefix_length,
    crib_keystream,
    main as crypto_main,
    parse_optional_hex,
    pkcs7_pad,
    repeating_xor,
    trial_decrypt,
)
from verdant_integration.reassembly import load_hex_dir, reassemble_dump_frames


LIVE_DIR = Path(__file__).resolve().parent / "fixtures" / "live_phase3"
ROOT = Path(__file__).resolve().parents[1]

# Isolated AES test vector — not a vendor key, not used on live dumps.
TEST_VECTOR_KEY = bytes(range(16))
TEST_VECTOR_IV = bytes(range(16, 32))
TEST_VECTOR_PLAINTEXT = b'{"method":"getDevSta","code":200}'


def _live_assemblies() -> list[bytes]:
    frames = load_hex_dir(LIVE_DIR)
    bodies: list[bytes] = []
    for item in reassemble_dump_frames(frames):
        if item.ok and item.assembled is not None:
            bodies.append(item.assembled)
    return bodies


def _aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise unittest.SkipTest("install cryptography from requirements.txt") from exc

    padded = pkcs7_pad(plaintext)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


class LiveStructureTests(unittest.TestCase):
    def test_seventeen_assemblies_are_aes_block_aligned_with_class_prefix(self) -> None:
        bodies = _live_assemblies()
        self.assertEqual(len(bodies), 17)
        sized: dict[int, list[bytes]] = {}
        for body in bodies:
            self.assertEqual(len(body) % AES_BLOCK, 0)
            sized.setdefault(len(body), []).append(body)
        self.assertEqual(len(sized[832]), 11)
        self.assertEqual(len(sized[608]), 6)
        self.assertEqual(common_prefix_length(sized[832]), 80)
        self.assertEqual(common_prefix_length(sized[608]), 80)
        self.assertEqual(len({item[:16] for item in sized[832]}), 1)
        self.assertEqual(len({item[:16] for item in sized[608]}), 1)
        self.assertNotEqual(sized[832][0][:16], sized[608][0][:16])
        self.assertTrue(sized[832][0].startswith(bytes.fromhex(PUBLIC_ISSUE4_SAMPLE_HEX)))

    def test_repeating_xor_from_json_crib_does_not_continue(self) -> None:
        body = _live_assemblies()[0]
        stream = crib_keystream(body, HYPOTHESIS_JSON_CRIB)
        self.assertIsNotNone(stream)
        assert stream is not None
        decoded = repeating_xor(body, stream)
        self.assertTrue(decoded.startswith(HYPOTHESIS_JSON_CRIB))
        self.assertFalse(decoded[len(HYPOTHESIS_JSON_CRIB) :].startswith(b',"'))
        self.assertFalse(decoded[len(HYPOTHESIS_JSON_CRIB) :].startswith(b"}"))

    def test_analyze_report_does_not_claim_decrypt(self) -> None:
        report = analyze_assemblies(_live_assemblies())
        self.assertFalse(report["claimed_decrypt"])
        self.assertFalse(report["claimed_plaintext"])
        self.assertTrue(report["hypotheses"]["aes_block_aligned_lengths"])
        self.assertFalse(report["hypotheses"]["static_repeating_xor"])
        self.assertFalse(report["hypotheses"]["aes_ecb_repeated_blocks"])
        self.assertTrue(report["hypotheses"]["cbc_style_shared_prefix_then_avalanche"])
        by_size = {row["total_ciphertext"]: row for row in report["classes"]}
        self.assertTrue(by_size[832]["issue4_sample_is_prefix"])
        self.assertFalse(by_size[608]["issue4_sample_is_prefix"])

    def test_analyze_empty_input_has_no_positive_hypotheses(self) -> None:
        report = analyze_assemblies([])
        self.assertEqual(report["assembly_count"], 0)
        self.assertFalse(report["hypotheses"]["aes_block_aligned_lengths"])
        self.assertFalse(report["hypotheses"]["static_repeating_xor"])
        self.assertFalse(report["hypotheses"]["aes_ecb_repeated_blocks"])
        self.assertFalse(report["hypotheses"]["cbc_style_shared_prefix_then_avalanche"])

    def test_analyze_derives_xor_and_ecb_flags_from_input(self) -> None:
        repeating = bytes(range(16)) * 4
        report = analyze_assemblies([repeating])
        self.assertTrue(report["hypotheses"]["aes_block_aligned_lengths"])
        self.assertTrue(report["hypotheses"]["aes_ecb_repeated_blocks"])
        self.assertFalse(report["hypotheses"]["cbc_style_shared_prefix_then_avalanche"])


class FailClosedTrialTests(unittest.TestCase):
    def test_live_without_key_never_claims_success(self) -> None:
        body = _live_assemblies()[0]
        refused = trial_decrypt(body)
        self.assertFalse(refused.claimed_success)
        self.assertFalse(refused.ok)
        self.assertIn(DECRYPT_REFUSED, refused.reason)
        self.assertIn(DECRYPT_NO_PLAINTEXT_FIXTURE, refused.reason)

        with_fixture = trial_decrypt(body, known_good_plaintext=TEST_VECTOR_PLAINTEXT)
        self.assertFalse(with_fixture.claimed_success)
        self.assertIn(DECRYPT_NO_KEY_MATERIAL, with_fixture.reason)

    def test_known_plaintext_match_is_the_only_success_path(self) -> None:
        ciphertext = _aes_encrypt_cbc(
            TEST_VECTOR_PLAINTEXT, TEST_VECTOR_KEY, TEST_VECTOR_IV
        )
        success = trial_decrypt(
            ciphertext,
            known_good_plaintext=TEST_VECTOR_PLAINTEXT,
            key=TEST_VECTOR_KEY,
            iv=TEST_VECTOR_IV,
            mode="cbc",
        )
        self.assertTrue(success.ok)
        self.assertTrue(success.claimed_success)
        self.assertEqual(success.reason, "known_plaintext_match")

        wrong_plain = trial_decrypt(
            ciphertext,
            known_good_plaintext=b'{"method":"getSysSta"}',
            key=TEST_VECTOR_KEY,
            iv=TEST_VECTOR_IV,
            mode="cbc",
        )
        self.assertFalse(wrong_plain.claimed_success)
        self.assertEqual(wrong_plain.reason, DECRYPT_MISMATCH)

        no_plain = trial_decrypt(
            ciphertext,
            key=TEST_VECTOR_KEY,
            iv=TEST_VECTOR_IV,
            mode="cbc",
        )
        self.assertFalse(no_plain.claimed_success)
        self.assertIn(DECRYPT_NO_PLAINTEXT_FIXTURE, no_plain.reason)

    def test_try_key_file_synthetic_match_and_live_refuse(self) -> None:
        from verdant_integration.crypto_research import (
            KeyIvPair,
            load_try_key_file,
            parse_key_iv_line,
            summarize_trials,
        )

        ciphertext = _aes_encrypt_cbc(
            TEST_VECTOR_PLAINTEXT, TEST_VECTOR_KEY, TEST_VECTOR_IV
        )
        pair = KeyIvPair(key=TEST_VECTOR_KEY, iv=TEST_VECTOR_IV)
        matched = summarize_trials(
            [ciphertext],
            pair,
            known=TEST_VECTOR_PLAINTEXT,
            mode="cbc",
        )
        self.assertEqual(matched["claimed_success_count"], 1)
        self.assertTrue(matched["claimed_success_any"])
        self.assertFalse(matched["claimed_mqtt_live"])

        ctr = summarize_trials(
            [ciphertext],
            pair,
            known=None,
            mode="ctr",
        )
        self.assertEqual(ctr["pkcs7_unpad_ok_count"], 0)
        self.assertFalse(ctr["claimed_success_any"])
        self.assertFalse(ctr["claimed_mqtt_live"])

        live = summarize_trials(
            [_live_assemblies()[0]],
            pair,
            known=TEST_VECTOR_PLAINTEXT,
            mode="cbc",
        )
        self.assertEqual(live["claimed_success_count"], 0)
        self.assertFalse(live["claimed_success_any"])

        self.assertIsNone(parse_key_iv_line("# comment"))
        parsed = parse_key_iv_line(f"{TEST_VECTOR_KEY.hex()} {TEST_VECTOR_IV.hex()}")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed.key, TEST_VECTOR_KEY)

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write(f"{TEST_VECTOR_KEY.hex()} {TEST_VECTOR_IV.hex()}\n")
            key_path = Path(handle.name)
        try:
            loaded = load_try_key_file(key_path)
            self.assertEqual(len(loaded), 1)
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = crypto_main(
                    [
                        "--assemblies-from",
                        "live_phase3",
                        "--try-key-file",
                        str(key_path),
                        "--known-plaintext-hex",
                        TEST_VECTOR_PLAINTEXT.hex(),
                    ]
                )
            payload = json.loads(stdout.getvalue())
            self.assertEqual(status, 0)
            self.assertFalse(payload["trial_claimed_success_any"])
            self.assertFalse(payload["claimed_mqtt_live"])
            self.assertEqual(payload["assembly_count"], 17)
            self.assertEqual(payload["try_key_pair_count"], 1)
            self.assertNotIn(TEST_VECTOR_KEY.hex(), stdout.getvalue())
        finally:
            key_path.unlink()

    def test_cli_requires_dir_or_assemblies_from(self) -> None:
        with self.assertRaises(SystemExit):
            crypto_main([])

    def test_wrong_key_does_not_claim_success_on_live(self) -> None:
        body = _live_assemblies()[0]
        result = trial_decrypt(
            body,
            known_good_plaintext=TEST_VECTOR_PLAINTEXT,
            key=TEST_VECTOR_KEY,
            iv=TEST_VECTOR_IV,
            mode="cbc",
        )
        self.assertFalse(result.claimed_success)

    def test_cli_live_dir_refuses_and_keeps_crc_counts(self) -> None:
        env = {
            "SF_GGS_AES_KEY_HEX": "",
            "SF_GGS_AES_IV_HEX": "",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = crypto_main(["--dir", str(LIVE_DIR)])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["assembly_count"], 17)
        self.assertFalse(payload["claimed_decrypt"])
        self.assertFalse(payload["trial_claimed_success_any"])
        self.assertFalse(payload["operator_key_present"])
        self.assertEqual(len(payload["trials"]), 17)
        for row in payload["trials"]:
            self.assertFalse(row["claimed_success"])

    def test_cli_rejects_malformed_plaintext_hex(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            crypto_main(["--dir", str(LIVE_DIR), "--known-plaintext-hex", "zz"])
        self.assertEqual(str(raised.exception), INVALID_HEX)

    def test_parse_optional_hex_rejects_malformed_operator_env(self) -> None:
        self.assertIsNone(parse_optional_hex(""))
        with self.assertRaises(SystemExit) as raised:
            parse_optional_hex("abc")
        self.assertEqual(str(raised.exception), INVALID_HEX)
        with patch.dict(os.environ, {"SF_GGS_AES_KEY_HEX": "not-hex"}, clear=False):
            with self.assertRaises(SystemExit) as raised:
                crypto_main(["--dir", str(LIVE_DIR)])
            self.assertEqual(str(raised.exception), INVALID_HEX)

    def test_source_has_no_vendor_key_literals_or_mqtt(self) -> None:
        source = (ROOT / "verdant_integration" / "crypto_research.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("KEY =", source)
        self.assertNotIn("IV =", source)
        self.assertNotIn("paho.mqtt", source.lower())
        self.assertNotIn("import paho", source.lower())
        self.assertNotIn("SecretKeySpec", source)


if __name__ == "__main__":
    unittest.main()
