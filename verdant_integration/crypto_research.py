"""Fail-closed crypto trials on reassembled opaque FF01 candidates.

Live assemblies are ciphertext candidates (Phase 4). This module never claims
decrypt success unless a caller-supplied known-plaintext fixture equals the
recovered bytes. Vendor AES keys and IVs are not stored here; pass them at
runtime if an operator has APK-derived material. Default is refuse.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from verdant_integration.payload_inspect import shannon_entropy_bits
from verdant_integration.reassembly import load_hex_dir, reassemble_dump_frames

DECRYPT_REFUSED = "unproven_crypto_profile"
DECRYPT_NO_PLAINTEXT_FIXTURE = "no_known_good_plaintext_fixture"
DECRYPT_NO_KEY_MATERIAL = "no_operator_key_iv"
DECRYPT_MISMATCH = "recovered_bytes_do_not_match_known_plaintext"
DECRYPT_BAD_PADDING = "pkcs7_unpad_failed"
DECRYPT_BAD_LENGTH = "ciphertext_not_block_aligned"
DECRYPT_BAD_ARGS = "invalid_key_or_iv_length"
DECRYPT_MISSING_CRYPTO = "cryptography_package_missing"
INVALID_HEX = "hex input is not valid."
AES_BLOCK = 16
HYPOTHESIS_JSON_CRIB = b'{"method":"getDevSta"'
PUBLIC_ISSUE4_SAMPLE_HEX = "8faabc89655c37aa48026729ec81a65dc312fc8243"


@dataclass(frozen=True)
class DecryptTrialResult:
    ok: bool
    claimed_success: bool
    reason: str
    mode: str
    known_good_plaintext_provided: bool
    recovered_len: int
    recovered_prefix_hex: str

    def as_summary(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "claimed_success": self.claimed_success,
            "reason": self.reason,
            "mode": self.mode,
            "known_good_plaintext_provided": self.known_good_plaintext_provided,
            "recovered_len": self.recovered_len,
            "recovered_prefix_hex": self.recovered_prefix_hex,
        }


def pkcs7_unpad(data: bytes) -> bytes | None:
    """Return unpadded bytes, or None if PKCS#7 is invalid."""
    if not data or len(data) % AES_BLOCK != 0:
        return None
    pad = data[-1]
    if pad < 1 or pad > AES_BLOCK:
        return None
    if data[-pad:] != bytes([pad]) * pad:
        return None
    return data[:-pad]


def pkcs7_pad(data: bytes) -> bytes:
    pad = AES_BLOCK - (len(data) % AES_BLOCK)
    return data + bytes([pad]) * pad


def _aes_decrypt(ciphertext: bytes, *, key: bytes, iv: bytes | None, mode: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ImportError(DECRYPT_MISSING_CRYPTO) from exc

    if mode == "cbc":
        if iv is None or len(iv) != AES_BLOCK:
            raise ValueError(DECRYPT_BAD_ARGS)
        algorithm_mode = modes.CBC(iv)
    elif mode == "ecb":
        algorithm_mode = modes.ECB()
    elif mode == "ctr":
        if iv is None or len(iv) != AES_BLOCK:
            raise ValueError(DECRYPT_BAD_ARGS)
        algorithm_mode = modes.CTR(iv)
    else:
        raise ValueError(f"unsupported_mode:{mode}")
    decryptor = Cipher(algorithms.AES(key), algorithm_mode).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def trial_decrypt(
    ciphertext: bytes,
    *,
    known_good_plaintext: bytes | None = None,
    key: bytes | None = None,
    iv: bytes | None = None,
    mode: str = "cbc",
    unpad_pkcs7: bool = True,
) -> DecryptTrialResult:
    """Attempt AES decrypt. ``claimed_success`` requires exact plaintext match.

    Keys and IVs must be supplied by the caller. They are never defaulted to
    invented vendor literals. JSON-looking output without a fixture is not
    success.
    """
    provided = known_good_plaintext is not None

    def _finish(
        *,
        ok: bool,
        claimed: bool,
        reason: str,
        recovered: bytes = b"",
    ) -> DecryptTrialResult:
        shown = recovered[:16].hex() if recovered else ""
        return DecryptTrialResult(
            ok=ok,
            claimed_success=claimed,
            reason=reason,
            mode=mode,
            known_good_plaintext_provided=provided,
            recovered_len=len(recovered),
            recovered_prefix_hex=shown,
        )

    if key is None or (mode in {"cbc", "ctr"} and iv is None):
        extra = DECRYPT_NO_PLAINTEXT_FIXTURE if not provided else DECRYPT_NO_KEY_MATERIAL
        return _finish(ok=False, claimed=False, reason=f"{DECRYPT_REFUSED}:{extra}")
    if len(key) not in (16, 24, 32):
        return _finish(ok=False, claimed=False, reason=DECRYPT_BAD_ARGS)
    if mode in {"cbc", "ecb"} and len(ciphertext) % AES_BLOCK != 0:
        return _finish(ok=False, claimed=False, reason=DECRYPT_BAD_LENGTH)
    if mode in {"cbc", "ctr"} and (iv is None or len(iv) != AES_BLOCK):
        return _finish(ok=False, claimed=False, reason=DECRYPT_BAD_ARGS)

    try:
        raw = _aes_decrypt(ciphertext, key=key, iv=iv, mode=mode)
    except ImportError:
        return _finish(ok=False, claimed=False, reason=DECRYPT_MISSING_CRYPTO)
    except ValueError as exc:
        return _finish(ok=False, claimed=False, reason=str(exc))

    recovered = raw
    if unpad_pkcs7 and mode in {"cbc", "ecb"}:
        unpadded = pkcs7_unpad(raw)
        if unpadded is None:
            return _finish(
                ok=False,
                claimed=False,
                reason=DECRYPT_BAD_PADDING,
                recovered=raw,
            )
        recovered = unpadded

    if known_good_plaintext is None:
        return _finish(
            ok=True,
            claimed=False,
            reason=f"{DECRYPT_REFUSED}:{DECRYPT_NO_PLAINTEXT_FIXTURE}",
            recovered=recovered,
        )
    if recovered != known_good_plaintext:
        return _finish(
            ok=True,
            claimed=False,
            reason=DECRYPT_MISMATCH,
            recovered=recovered,
        )
    return _finish(ok=True, claimed=True, reason="known_plaintext_match", recovered=recovered)


def common_prefix_length(buffers: Sequence[bytes]) -> int:
    if not buffers:
        return 0
    length = 0
    while True:
        if any(length >= len(item) for item in buffers):
            return length
        if len({item[length] for item in buffers}) != 1:
            return length
        length += 1


def repeating_xor(data: bytes, keystream: bytes) -> bytes:
    if not keystream:
        return data
    return bytes(data[i] ^ keystream[i % len(keystream)] for i in range(len(data)))


def crib_keystream(ciphertext: bytes, crib: bytes) -> bytes | None:
    if len(ciphertext) < len(crib) or not crib:
        return None
    return bytes(ciphertext[i] ^ crib[i] for i in range(len(crib)))


def equal_block_histogram(a: bytes, b: bytes) -> list[int]:
    limit = min(len(a), len(b))
    counts: list[int] = []
    for offset in range(0, limit, AES_BLOCK):
        chunk_a = a[offset : offset + AES_BLOCK]
        chunk_b = b[offset : offset + AES_BLOCK]
        n = min(len(chunk_a), len(chunk_b))
        counts.append(sum(1 for i in range(n) if chunk_a[i] == chunk_b[i]))
    return counts


def analyze_assemblies(assemblies: Sequence[bytes]) -> dict[str, object]:
    """Structural hypotheses on opaque candidates. Not a decrypt claim."""
    sized: dict[int, list[bytes]] = {}
    for body in assemblies:
        sized.setdefault(len(body), []).append(body)

    classes: list[dict[str, object]] = []
    for total, group in sorted(sized.items()):
        prefix = common_prefix_length(group)
        unique_first = len({item[:AES_BLOCK] for item in group})
        intra_ecb = []
        for item in group:
            blocks = [item[i : i + AES_BLOCK] for i in range(0, len(item), AES_BLOCK)]
            counts = Counter(blocks)
            intra_ecb.append(sum(1 for _block, n in counts.items() if n > 1))
        xor_repeat_ok = False
        if group:
            stream = crib_keystream(group[0], HYPOTHESIS_JSON_CRIB)
            if stream is not None:
                decoded = repeating_xor(group[0], stream)
                xor_repeat_ok = decoded.startswith(HYPOTHESIS_JSON_CRIB) and decoded[
                    len(HYPOTHESIS_JSON_CRIB) : len(HYPOTHESIS_JSON_CRIB) + 8
                ].isascii() and decoded[len(HYPOTHESIS_JSON_CRIB) : len(HYPOTHESIS_JSON_CRIB) + 1] in (
                    b",",
                    b"}",
                    b" ",
                )
        pair_hist: list[int] | None = None
        last_block_only_twins = 0
        if len(group) >= 2:
            pair_hist = equal_block_histogram(group[0], group[1])
            for i, left in enumerate(group):
                for right in group[i + 1 :]:
                    diffs = [k for k, (x, y) in enumerate(zip(left, right)) if x != y]
                    if diffs and min(diffs) >= len(left) - AES_BLOCK:
                        last_block_only_twins += 1
        sample = bytes.fromhex(PUBLIC_ISSUE4_SAMPLE_HEX)
        sample_hit = bool(group) and all(item.startswith(sample) for item in group)
        classes.append(
            {
                "total_ciphertext": total,
                "count": len(group),
                "mod_16": total % AES_BLOCK,
                "shannon_entropy_bits": round(shannon_entropy_bits(group[0]), 4) if group else 0.0,
                "common_prefix_bytes": prefix,
                "common_prefix_aes_blocks": prefix // AES_BLOCK,
                "unique_first_aes_block": unique_first,
                "ecb_duplicate_block_kinds_max": max(intra_ecb) if intra_ecb else 0,
                "repeating_xor_continues_ascii_json": xor_repeat_ok,
                "first_two_equal_bytes_per_block": pair_hist,
                "last_block_only_twins": last_block_only_twins,
                "issue4_sample_is_prefix": sample_hit,
            }
        )

    aligned = bool(assemblies) and all(len(item) % AES_BLOCK == 0 for item in assemblies)
    xor_hit = any(bool(row["repeating_xor_continues_ascii_json"]) for row in classes)
    ecb_hit = any(int(row["ecb_duplicate_block_kinds_max"]) > 0 for row in classes)
    cbc_style = any(_cbc_style_from_class(row) for row in classes)
    return {
        "assembly_count": len(assemblies),
        "claimed_decrypt": False,
        "claimed_plaintext": False,
        "classes": classes,
        "hypotheses": {
            "aes_block_aligned_lengths": aligned,
            "static_repeating_xor": xor_hit,
            "aes_ecb_repeated_blocks": ecb_hit,
            "cbc_style_shared_prefix_then_avalanche": cbc_style,
        },
    }


def _cbc_style_from_class(row: dict[str, object]) -> bool:
    """True when a class has a shared AES-block prefix then a later 0-equal block."""
    count = int(row["count"])
    prefix_blocks = int(row["common_prefix_aes_blocks"])
    hist = row["first_two_equal_bytes_per_block"]
    if count < 2 or prefix_blocks < 1 or not isinstance(hist, list) or len(hist) <= prefix_blocks:
        return False
    return any(int(equal) == 0 for equal in hist[prefix_blocks:])


def parse_optional_hex(text: str) -> bytes | None:
    """Parse optional hex, or exit like the other CLIs on malformed input."""
    compact = "".join(text.split())
    if not compact:
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        raise SystemExit(INVALID_HEX) from None


def load_operator_key_iv() -> tuple[bytes | None, bytes | None]:
    """Read optional operator hex from the environment. Empty means absent."""
    key = parse_optional_hex(os.environ.get("SF_GGS_AES_KEY_HEX", ""))
    iv = parse_optional_hex(os.environ.get("SF_GGS_AES_IV_HEX", ""))
    return key, iv


REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_PHASE3_DIR = REPO_ROOT / "tests" / "fixtures" / "live_phase3"
CLAIMED_MQTT_LIVE = False


@dataclass(frozen=True)
class KeyIvPair:
    key: bytes
    iv: bytes | None

    def fingerprint(self) -> str:
        iv_part = "none" if self.iv is None else hashlib.sha256(self.iv).hexdigest()[:8]
        return f"key{len(self.key)}_{hashlib.sha256(self.key).hexdigest()[:12]}_iv_{iv_part}"


def resolve_assemblies_dir(
    dir_arg: str | None,
    assemblies_from: str | None,
) -> Path:
    """Resolve --dir / --assemblies-from. Token live_phase3 is the fixture dir."""
    if dir_arg and assemblies_from:
        raise SystemExit("use only one of --dir or --assemblies-from.")
    token = assemblies_from or dir_arg
    if token is None:
        raise SystemExit("--dir or --assemblies-from is required.")
    if token == "live_phase3":
        return LIVE_PHASE3_DIR
    return Path(token)


def parse_key_iv_line(text: str) -> KeyIvPair | None:
    """Parse one candidate line: key_hex [iv_hex]. Comments and blanks skip."""
    stripped = text.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split()
    if not parts:
        return None
    key = parse_optional_hex(parts[0])
    if key is None:
        return None
    iv = parse_optional_hex(parts[1]) if len(parts) > 1 else None
    if len(key) not in (16, 24, 32):
        raise SystemExit(DECRYPT_BAD_ARGS)
    if iv is not None and len(iv) != AES_BLOCK:
        raise SystemExit(DECRYPT_BAD_ARGS)
    return KeyIvPair(key=key, iv=iv)


def load_try_key_file(path: Path) -> list[KeyIvPair]:
    """Load operator key/IV pairs. Empty file is valid (zero trials)."""
    pairs: list[KeyIvPair] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        item = parse_key_iv_line(line)
        if item is not None:
            pairs.append(item)
    return pairs


def summarize_trials(
    assemblies: Sequence[bytes],
    pair: KeyIvPair,
    *,
    known: bytes | None,
    mode: str,
) -> dict[str, object]:
    """Run fail-closed trial_decrypt on every assembly for one key/IV pair."""
    reasons: Counter[str] = Counter()
    claimed = 0
    pkcs7_ok = 0
    for body in assemblies:
        trial = trial_decrypt(
            body,
            known_good_plaintext=known,
            key=pair.key,
            iv=pair.iv,
            mode=mode,
        )
        reasons[trial.reason] += 1
        if trial.claimed_success:
            claimed += 1
        if trial.ok:
            pkcs7_ok += 1
    return {
        "fingerprint": pair.fingerprint(),
        "key_len": len(pair.key),
        "iv_present": pair.iv is not None,
        "assembly_count": len(assemblies),
        "claimed_success_count": claimed,
        "pkcs7_unpad_ok_count": pkcs7_ok,
        "reason_counts": dict(reasons),
        "claimed_success_any": claimed > 0,
        "claimed_mqtt_live": CLAIMED_MQTT_LIVE,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Structural crypto research + fail-closed AES trials on Phase 4 "
            "assemblies (no MQTT, no invented keys)."
        )
    )
    parser.add_argument("--dir", metavar="DIR", help="live_phase3 hex directory")
    parser.add_argument(
        "--assemblies-from",
        metavar="DIR_OR_TOKEN",
        help="Same as --dir. Token 'live_phase3' selects tests/fixtures/live_phase3.",
    )
    parser.add_argument(
        "--try-key-file",
        metavar="PATH",
        help="Operator key/IV listing (key_hex [iv_hex] per line). Not committed.",
    )
    parser.add_argument(
        "--known-plaintext-hex",
        default="",
        help="Optional known-good plaintext as hex. Required to claim success.",
    )
    parser.add_argument(
        "--mode",
        default="cbc",
        choices=("cbc", "ecb", "ctr"),
        help="AES mode for an operator-supplied key trial.",
    )
    args = parser.parse_args(argv)
    dump_dir = resolve_assemblies_dir(args.dir, args.assemblies_from)
    frames = load_hex_dir(dump_dir)
    results = [item for item in reassemble_dump_frames(frames) if item.ok and item.assembled]
    assemblies = [item.assembled for item in results if item.assembled is not None]
    report = analyze_assemblies(assemblies)
    known = parse_optional_hex(args.known_plaintext_hex)
    key, iv = load_operator_key_iv()
    pairs: list[KeyIvPair] = []
    if args.try_key_file:
        pairs.extend(load_try_key_file(Path(args.try_key_file)))
    if key is not None:
        pairs.append(KeyIvPair(key=key, iv=iv))

    trials: list[dict[str, object]] = []
    claimed_any = False
    if not pairs:
        for item in results:
            assert item.assembled is not None
            trial = trial_decrypt(
                item.assembled,
                known_good_plaintext=known,
                key=None,
                iv=None,
                mode=args.mode,
            )
            row = trial.as_summary()
            row["message_crc_hex"] = item.message_crc_hex
            row["total_ciphertext"] = item.total_ciphertext
            trials.append(row)
            if trial.claimed_success:
                claimed_any = True
        report["trials"] = trials
        report["operator_key_present"] = False
    else:
        pair_rows = [
            summarize_trials(assemblies, pair, known=known, mode=args.mode) for pair in pairs
        ]
        claimed_any = any(bool(row["claimed_success_any"]) for row in pair_rows)
        report["try_key_pairs"] = pair_rows
        report["operator_key_present"] = True
        report["try_key_pair_count"] = len(pairs)
        report["trial_claimed_success_count"] = sum(
            int(row["claimed_success_count"]) for row in pair_rows
        )

    report["trial_claimed_success_any"] = claimed_any
    report["claimed_mqtt_live"] = CLAIMED_MQTT_LIVE
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if assemblies else 1


if __name__ == "__main__":
    raise SystemExit(main())
