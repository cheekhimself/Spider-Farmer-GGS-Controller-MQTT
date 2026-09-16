import asyncio
import json
import os
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from verdant_integration.ff_session import (
    MAC_REDACT,
    WRITE_REFUSED,
    classify_hex_dir,
    redact_macs,
    write_ff02_allowed,
)
from ggs_ff02_sniff import capture_live, main as sniff_main


ROOT = Path(__file__).resolve().parents[1]
LIVE_DIR = ROOT / "tests" / "fixtures" / "live_phase3"


class HexDirClassifyTests(unittest.TestCase):
    def test_live_complete_frame_reports_crc(self) -> None:
        sample = next(LIVE_DIR.glob("*_422b_*.hex"))
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "ff01_0001.hex"
            dest.write_text(sample.read_text(encoding="ascii"), encoding="ascii")
            report = classify_hex_dir(Path(tmp), dump_frames=None)
        self.assertEqual(report["files"], 1)
        self.assertFalse(report["claimed_decrypt"])
        self.assertFalse(report["claimed_mqtt_live"])
        self.assertEqual(report["ble_macs"], "suppressed")
        row = report["results"][0]
        self.assertEqual(row["completeness"], "COMPLETE")
        self.assertEqual(row["channel_hint"], "ff01")
        self.assertTrue(row["crc_ok"])
        self.assertEqual(report["crc_pass"], 1)

    def test_truncated_is_not_crc_pass(self) -> None:
        sample = next(LIVE_DIR.glob("*_422b_*.hex"))
        prefix = "".join(sample.read_text(encoding="ascii").split())[:40]
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "ff02_trunc.hex"
            dest.write_text(prefix + "\n", encoding="ascii")
            report = classify_hex_dir(Path(tmp), dump_frames=None)
        row = report["results"][0]
        self.assertEqual(row["channel_hint"], "ff02")
        self.assertNotEqual(row["completeness"], "COMPLETE")
        self.assertIsNone(row["crc_ok"])
        self.assertEqual(report["crc_pass"], 0)

    def test_mac_like_filename_is_redacted(self) -> None:
        sample = next(LIVE_DIR.glob("*_422b_*.hex"))
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "ff02_AA-BB-CC-DD-EE-FF.hex"
            dest.write_text(sample.read_text(encoding="ascii"), encoding="ascii")
            report = classify_hex_dir(Path(tmp), dump_frames=None)
        row = report["results"][0]
        self.assertEqual(row["path"], f"ff02_{MAC_REDACT}.hex")
        self.assertNotIn("AA-BB-CC-DD-EE-FF", json.dumps(report))
        self.assertEqual(row["channel_hint"], "ff02")
        self.assertEqual(redact_macs("ff01_aa:bb:cc:dd:ee:ff.hex"), f"ff01_{MAC_REDACT}.hex")

    def test_cli_from_hex_dir(self) -> None:
        sample = next(LIVE_DIR.glob("*_230b_*.hex"))
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "session.hex"
            dest.write_text(sample.read_text(encoding="ascii"), encoding="ascii")
            with patch("sys.stdout", new=StringIO()) as stdout:
                status = sniff_main(["--from-hex-dir", tmp])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(payload["completeness"]["COMPLETE"], 1)


class WriteGateTests(unittest.TestCase):
    def test_write_without_gates_is_refused(self) -> None:
        with patch.dict(os.environ, {"SF_GGS_I_UNDERSTAND_FF02_WRITE": ""}, clear=False):
            with self.assertRaises(SystemExit) as raised:
                write_ff02_allowed(write_hex="00", understand_flag=False)
        self.assertEqual(str(raised.exception), WRITE_REFUSED)

    def test_write_allowed_only_with_flag_and_env(self) -> None:
        with patch.dict(os.environ, {"SF_GGS_I_UNDERSTAND_FF02_WRITE": "yes"}, clear=False):
            self.assertTrue(write_ff02_allowed(write_hex="00ff", understand_flag=True))

    def test_empty_write_hex_is_not_a_write(self) -> None:
        self.assertFalse(write_ff02_allowed(write_hex="", understand_flag=False))

    def test_capture_live_refuses_write_without_gates(self) -> None:
        with patch.dict(os.environ, {"SF_GGS_I_UNDERSTAND_FF02_WRITE": ""}, clear=False):
            with self.assertRaises(SystemExit) as raised:
                asyncio.run(
                    capture_live(
                        1,
                        1.0,
                        1.0,
                        None,
                        ff02_notify=False,
                        write_hex="00",
                        understand_flag=False,
                    )
                )
        self.assertEqual(str(raised.exception), WRITE_REFUSED)

    def test_capture_live_refuses_write_when_only_flag_set(self) -> None:
        with patch.dict(os.environ, {"SF_GGS_I_UNDERSTAND_FF02_WRITE": ""}, clear=False):
            with self.assertRaises(SystemExit) as raised:
                asyncio.run(
                    capture_live(
                        1,
                        1.0,
                        1.0,
                        None,
                        ff02_notify=False,
                        write_hex="00",
                        understand_flag=True,
                    )
                )
        self.assertEqual(str(raised.exception), WRITE_REFUSED)


class SourcePolicyTests(unittest.TestCase):
    def test_sniffer_suppresses_macs_and_does_not_claim_mqtt(self) -> None:
        source = (ROOT / "ggs_ff02_sniff.py").read_text(encoding="utf-8").lower()
        self.assertIn("0000ff01-0000-1000-8000-00805f9b34fb", source)
        self.assertIn("0000ff02-0000-1000-8000-00805f9b34fb", source)
        self.assertIn("hci", source)
        self.assertNotIn(".address", source)
        self.assertNotIn("paho.mqtt", source)
        self.assertIn("completeness", source)
        self.assertIn("claimed_mqtt_live", source)
        self.assertIn("dangerous-write-ff02-hex", source)


if __name__ == "__main__":
    unittest.main()
