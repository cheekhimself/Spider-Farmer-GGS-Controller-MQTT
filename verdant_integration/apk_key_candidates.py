"""Rank AES key/IV *candidates* from a local APK or strings dump.

Never downloads APKs. Never writes into tracked source trees. Output is
stdout or a gitignored operator path. Hex printed here is not a proven
vendor key and must be trialed through ``crypto_research.trial_decrypt``.
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from verdant_integration.payload_inspect import shannon_entropy_bits

AES_BLOCK = 16
REFUSE_DOWNLOAD = "refusing to download or fetch APKs; pass a local file path."
REFUSE_TRACKED_OUT = (
    "refusing to write candidates into a tracked path; use stdout or "
    "operator_local/ (gitignored)."
)
HEX_TOKEN = re.compile(rb"\b(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{64})\b")
ASCII_QUOTED = re.compile(rb"""(?P<q>['"])(?P<body>[ -~]{16}|[ -~]{32})(?P=q)""")
PRINTABLE_RUN = re.compile(rb"[ -~]{16,256}")
CONTEXT_WINDOW = 96

KEYWORD_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("secretkeyspec", 10),
    ("ivparameterspec", 9),
    ("aes/cbc/pkcs5padding", 8),
    ("aes/cbc/pkcs7padding", 8),
    ("aes/cbc", 7),
    ("aes-128-cbc", 7),
    ("aes-256-cbc", 6),
    ("pkcs7", 4),
    ("pkcs5", 3),
    ("aes128", 5),
    ("aes256", 4),
    ("encrypt", 2),
    ("cipher", 2),
    ("ble", 2),
    ("ff02", 3),
    ("ff01", 2),
    ("ggs", 2),
)

IV_HINTS = ("ivparameterspec", "initvector", "_iv", " iv", "iv=", "iv_")
KEY_HINTS = ("secretkeyspec", "secretkey", "aes_key", "aeskey", "_key", "key=")

BLE_UUID_HEX = {
    "0000ff0000001000800000805f9b34fb",
    "0000ff0100001000800000805f9b34fb",
    "0000ff0200001000800000805f9b34fb",
    "0000180000001000800000805f9b34fb",
    "0000180100001000800000805f9b34fb",
}

TRACKED_WRITE_PARTS = (
    "verdant_integration",
    "tests",
    "docs",
    ".git",
)


@dataclass(frozen=True)
class KeyCandidate:
    hex: str
    length: int
    encoding: str
    kind: str
    score: int
    signals: tuple[str, ...]
    ascii: str | None

    def as_summary(self) -> dict[str, object]:
        return {
            "hex": self.hex,
            "length": self.length,
            "encoding": self.encoding,
            "kind": self.kind,
            "score": self.score,
            "signals": list(self.signals),
            "ascii": self.ascii,
            "proven_vendor_key": False,
        }


def refuse_remote_path(path: str | Path) -> None:
    text = str(path).strip()
    lowered = text.lower()
    if lowered.startswith(("http://", "https://", "ftp://", "ftps://")):
        raise SystemExit(REFUSE_DOWNLOAD)
    if "://" in lowered:
        raise SystemExit(REFUSE_DOWNLOAD)


def allowed_output_path(path: Path, *, repo_root: Path) -> bool:
    """Stdout is always allowed. Files must sit under gitignored operator dirs."""
    resolved = path.resolve()
    root = repo_root.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return True
    parts = relative.parts
    if not parts:
        return False
    if parts[0] in {"operator_local", "dumps"}:
        return True
    if any(part in TRACKED_WRITE_PARTS for part in parts):
        return False
    if parts[0] in {"verdant_integration", "tests", "docs"}:
        return False
    return False


def _decode_ascii(raw: bytes) -> str | None:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if all(32 <= byte < 127 for byte in raw):
        return text
    return None


def _kind_from_context(context: str, length: int) -> str:
    lowered = context.lower()
    iv_hit = any(hint in lowered for hint in IV_HINTS)
    key_hit = any(hint in lowered for hint in KEY_HINTS)
    if iv_hit and not key_hit and length == AES_BLOCK:
        return "iv"
    if key_hit and not iv_hit:
        return "key"
    if iv_hit and key_hit:
        return "key_or_iv"
    return "key_or_iv"


def _score_context(context: str, raw: bytes) -> tuple[int, tuple[str, ...]]:
    lowered = context.lower()
    score = 0
    signals: list[str] = []
    for token, weight in KEYWORD_WEIGHTS:
        if token in lowered:
            score += weight
            signals.append(token)
    entropy = shannon_entropy_bits(raw)
    if entropy >= 3.5:
        score += 2
        signals.append("entropy_ok")
    elif entropy < 1.5:
        score -= 4
        signals.append("low_entropy")
    if len(set(raw)) == 1:
        score -= 8
        signals.append("constant_bytes")
    if raw == bytes(len(raw)):
        score -= 6
        signals.append("all_zero")
    ascii_text = _decode_ascii(raw)
    if ascii_text is not None and " " in ascii_text:
        score -= 2
        signals.append("contains_space")
    return score, tuple(dict.fromkeys(signals))


def _reject_hex_token(hex_text: str) -> bool:
    compact = hex_text.lower()
    if compact in BLE_UUID_HEX:
        return True
    if compact.startswith("0000ff") and compact.endswith("00001000800000805f9b34fb"):
        return True
    return False


def _record(
    pool: dict[str, KeyCandidate],
    raw: bytes,
    *,
    encoding: str,
    context: str,
) -> None:
    if len(raw) not in (16, 32):
        return
    hex_text = raw.hex()
    if _reject_hex_token(hex_text):
        return
    score, signals = _score_context(context, raw)
    kind = _kind_from_context(context, len(raw))
    ascii_text = _decode_ascii(raw) if encoding == "ascii" else None
    existing = pool.get(hex_text)
    if existing is None or score > existing.score:
        pool[hex_text] = KeyCandidate(
            hex=hex_text,
            length=len(raw),
            encoding=encoding,
            kind=kind,
            score=score,
            signals=signals,
            ascii=ascii_text,
        )


def harvest_text(blob: bytes, pool: dict[str, KeyCandidate]) -> None:
    """Collect 16/32-byte hex and quoted ASCII tokens from a byte blob."""
    if not blob:
        return
    for match in HEX_TOKEN.finditer(blob):
        token = match.group(0)
        start = max(0, match.start() - CONTEXT_WINDOW)
        end = min(len(blob), match.end() + CONTEXT_WINDOW)
        context = blob[start:end].decode("ascii", errors="ignore")
        try:
            raw = bytes.fromhex(token.decode("ascii"))
        except ValueError:
            continue
        _record(pool, raw, encoding="hex", context=context)
    for match in ASCII_QUOTED.finditer(blob):
        body = match.group("body")
        start = max(0, match.start() - CONTEXT_WINDOW)
        end = min(len(blob), match.end() + CONTEXT_WINDOW)
        context = blob[start:end].decode("ascii", errors="ignore")
        _record(pool, body, encoding="ascii", context=context)
    for line in blob.splitlines():
        if len(line) in (16, 32) and all(32 <= byte < 127 for byte in line):
            start = max(0, blob.find(line) - CONTEXT_WINDOW)
            end = min(len(blob), blob.find(line) + len(line) + CONTEXT_WINDOW)
            context = blob[start:end].decode("ascii", errors="ignore")
            _record(pool, line, encoding="ascii", context=context)


def extract_dex_strings(data: bytes) -> list[bytes]:
    """Read MUTF-8 strings from a DEX string_ids table. Empty if not a DEX."""
    if len(data) < 72 or not data.startswith(b"dex\n"):
        return []
    string_ids_size = int.from_bytes(data[56:60], "little")
    string_ids_off = int.from_bytes(data[60:64], "little")
    if string_ids_size > 500_000 or string_ids_off + 4 * string_ids_size > len(data):
        return []
    strings: list[bytes] = []
    for index in range(string_ids_size):
        item = string_ids_off + index * 4
        offset = int.from_bytes(data[item : item + 4], "little")
        if offset >= len(data):
            continue
        cursor = offset
        while cursor < len(data) and data[cursor] & 0x80:
            cursor += 1
        cursor += 1
        start = cursor
        while cursor < len(data) and data[cursor] != 0:
            cursor += 1
        strings.append(data[start:cursor])
    return strings


def _iter_apk_blobs(apk_path: Path) -> Iterable[bytes]:
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            if info.is_dir() or info.file_size > 32 * 1024 * 1024:
                continue
            name = info.filename.lower()
            if name.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".ogg", ".mp3")):
                continue
            try:
                payload = archive.read(info)
            except (RuntimeError, zipfile.BadZipFile):
                continue
            yield payload
            if name.endswith(".dex"):
                for item in extract_dex_strings(payload):
                    yield item


def harvest_apk(apk_path: Path) -> dict[str, KeyCandidate]:
    pool: dict[str, KeyCandidate] = {}
    for blob in _iter_apk_blobs(apk_path):
        harvest_text(blob, pool)
        for match in PRINTABLE_RUN.finditer(blob):
            harvest_text(match.group(0), pool)
    return pool


def harvest_path(path: Path) -> dict[str, KeyCandidate]:
    if path.is_dir():
        pool: dict[str, KeyCandidate] = {}
        for child in path.rglob("*"):
            if not child.is_file() or child.stat().st_size > 32 * 1024 * 1024:
                continue
            harvest_text(child.read_bytes(), pool)
        return pool
    header = path.read_bytes()[:4]
    if header == b"PK\x03\x04":
        return harvest_apk(path)
    pool = {}
    harvest_text(path.read_bytes(), pool)
    return pool


def ranked_candidates(pool: dict[str, KeyCandidate]) -> list[KeyCandidate]:
    return sorted(pool.values(), key=lambda item: (-item.score, item.kind, item.hex))


def write_try_key_file(candidates: Sequence[KeyCandidate], path: Path) -> None:
    """Write key/IV pairs for crypto_research --try-key-file (operator local)."""
    keys = [item for item in candidates if item.kind in {"key", "key_or_iv"}]
    ivs = [item for item in candidates if item.kind == "iv" and item.length == AES_BLOCK]
    lines = [
        "# Operator AES candidates. Not proven. Do not commit.",
        "# Format: <key_hex> [iv_hex]",
    ]
    if not keys and ivs:
        lines.append("# iv-only candidates; CBC still needs a key")
        for iv in ivs:
            lines.append(f"# iv {iv.hex()}")
    elif not ivs:
        for item in keys:
            lines.append(item.hex)
    else:
        for key in keys:
            for iv in ivs:
                lines.append(f"{key.hex} {iv.hex}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract ranked 16/32-byte AES key/IV *candidates* from a local APK "
            "or strings file. Does not download APKs. Does not claim a live key."
        )
    )
    parser.add_argument(
        "path",
        help="Local APK, apktool/jadx dump directory, or UTF-8/binary strings file.",
    )
    parser.add_argument(
        "--out",
        metavar="PATH",
        help="Optional gitignored path (operator_local/...). Default: stdout JSON.",
    )
    parser.add_argument(
        "--try-key-file",
        metavar="PATH",
        help="Also write a --try-key-file listing under a gitignored path.",
    )
    args = parser.parse_args(argv)
    refuse_remote_path(args.path)
    source = Path(args.path)
    if not source.exists():
        raise SystemExit(f"local path does not exist: {source}")
    repo_root = Path(__file__).resolve().parents[1]
    ranked = ranked_candidates(harvest_path(source))
    report = {
        "source_kind": "local_path",
        "candidate_count": len(ranked),
        "proven_vendor_key": False,
        "claimed_decrypt": False,
        "candidates": [item.as_summary() for item in ranked],
        "note": (
            "Candidates are unproven. Trial with "
            "python3 -m verdant_integration.crypto_research "
            "--try-key-file ... --assemblies-from live_phase3"
        ),
    }
    payload = json.dumps(report, separators=(",", ":"), sort_keys=True)
    if args.out:
        refuse_remote_path(args.out)
        out_path = Path(args.out)
        if not allowed_output_path(out_path, repo_root=repo_root):
            raise SystemExit(REFUSE_TRACKED_OUT)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(payload + "\n", encoding="ascii")
    else:
        print(payload)
    if args.try_key_file:
        refuse_remote_path(args.try_key_file)
        key_path = Path(args.try_key_file)
        if not allowed_output_path(key_path, repo_root=repo_root):
            raise SystemExit(REFUSE_TRACKED_OUT)
        write_try_key_file(ranked, key_path)
    return 0 if ranked else 1


if __name__ == "__main__":
    raise SystemExit(main())
