import json
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
    PUBLIC_ISSUE4_SAMPLE_HEX,
    analyze_assemblies,
    common_prefix_length,
    crib_keystream,
    main as crypto_main,
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
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
        self.assertTrue(report["hypotheses"]["cbc_style_shared_prefix_then_avalanche"])


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
