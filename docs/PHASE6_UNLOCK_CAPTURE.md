# Phase 6 — operator unlock tooling (APK candidates + pairing capture)

Status: **tooling and documentation only.** Live AES decrypt remains
**BLOCKED** until Cheek supplies operator key/IV material or a known-good
plaintext that matches a `trial_decrypt` recovery. This slice does not invent
secrets, does not download Spider Farmer APKs, does not commit APKs or keys,
and does not claim MQTT live sensors.

Stacks on Phase 5: 17 reassembled assemblies are structurally compatible with
AES-CBC + a **fixed** IV. Algorithm + key are still unproven.

## Hard stops

- Do **not** paste vendor keys, IVs, or passwords into git, issues, or PRs.
- Do **not** fetch APKs from Play Store / mirrors / `curl` / browsers via these
  scripts. The operator who already has the app supplies a **local** file.
- `claimed_success` stays false unless recovered bytes equal a caller-supplied
  known-plaintext fixture (`crypto_research.trial_decrypt`).
- Prefer **sniffing** official-app traffic over writing FF02. A write helper
  exists only as a clearly marked, double-gated opt-in and is not required.

## A. APK string / literal dump (Windows-friendly)

Prerequisite: you already installed the Spider Farmer Android app and can
copy the APK from the phone or a backup **you own**. These commands never
download the package.

### 1. Copy the APK off the phone (optional)

USB debugging on, then from `cmd.exe`:

```bat
adb shell pm path com.spiderfarmer.ggs
adb pull /data/app/.../base.apk %USERPROFILE%\operator_local\spider-farmer.apk
```

The package id may differ (`pm list packages | findstr -i spider`). If `adb
pull` of `/data/app` is denied, use a backup/export tool you already use, or
copy `base.apk` from an extracted installer. Do not use random APK websites.

Place the file **outside git** or under this repo’s gitignored
`operator_local\` directory.

### 2. Strings without extra tools (this repo)

From the repo root (Python 3.11+):

```bat
python3 -m verdant_integration.apk_key_candidates %USERPROFILE%\operator_local\spider-farmer.apk --out operator_local\apk_candidates.json --try-key-file operator_local\candidates.txt
```

The scanner:

- Opens the APK as a zip (local path only; `http://` is refused).
- Harvests 32/64-char hex tokens and quoted 16/32-char ASCII from zip
  members and DEX string tables when present.
- Ranks hits near `SecretKeySpec`, `IvParameterSpec`, `AES/CBC`, etc.
- Drops BLE UUID-shaped hex (`0000ff01…`).
- Prints JSON to stdout unless `--out` is a gitignored path
  (`operator_local\` or `dumps\`). Writing into `tests\` / `docs\` /
  `verdant_integration\` is refused.
- Does **not** claim any candidate is the live BLE key.

### 3. jadx / apktool (optional, richer literals)

Install [jadx](https://github.com/skylot/jadx/releases) and/or apktool
separately. Examples:

```bat
jadx -d %USERPROFILE%\operator_local\jadx-out %USERPROFILE%\operator_local\spider-farmer.apk
findstr /S /I /C:"SecretKeySpec" /C:"IvParameterSpec" /C:"AES/CBC" %USERPROFILE%\operator_local\jadx-out\*.*
```

apktool:

```bat
apktool d -o %USERPROFILE%\operator_local\apktool-out %USERPROFILE%\operator_local\spider-farmer.apk
findstr /S /I /C:"const-string" %USERPROFILE%\operator_local\apktool-out\smali*\*.smali | findstr /I "AES key iv"
```

Then point the same Python scanner at the dump directory or a `strings`
file:

```bat
python3 -m verdant_integration.apk_key_candidates %USERPROFILE%\operator_local\jadx-out
python3 -m verdant_integration.apk_key_candidates %USERPROFILE%\operator_local\strings.txt
```

Cygwin/Git Bash `strings` on Windows:

```bat
strings -n 16 spider-farmer.apk > %USERPROFILE%\operator_local\apk_strings.txt
```

Flutter/Dart snapshots (if the app is Flutter) often hide literals in
`isolate_snapshot` / `kernel_blob.bin` inside the APK. The zip walker already
extracts printable runs from those blobs; jadx will not decompile Dart. If
you see `libapp.so` / `libflutter.so` only, keep the strings dump — do not
invent a key.

### 4. What to do with candidates

```bat
python3 -m verdant_integration.crypto_research --try-key-file operator_local\candidates.txt --assemblies-from live_phase3
```

Equivalent: `--dir tests\fixtures\live_phase3`.

The JSON report includes per-pair **pass/fail counts**.
`trial_claimed_success_any` stays false without
`--known-plaintext-hex` that **exactly** matches recovered bytes.
`claimed_mqtt_live` is always false in this tool. Valid PKCS7 unpad on
garbage is **not** a decrypt claim.

Keep `operator_local\candidates.txt` off git (gitignored). Format:

```
# key_hex [iv_hex]
00112233445566778899aabbccddeeff 101112131415161718191a1b1c1d1e1f
```

(Those hex values are documentation shape only — use output from *your*
APK scan.)

Optional env still works: `SF_GGS_AES_KEY_HEX` / `SF_GGS_AES_IV_HEX`.

## B. Official-app pairing / session capture (FF02 writes + FF01 notifies)

Goal: capture the **bytes the official app already sends**, plus FF01
notifications, while you pair or open a live session with **SF-GGS-CB**.
Do not invent control JSON (`setLight`, etc.).

### Why a second Python client usually cannot sniff FF02 writes

BLE GATT is typically **one connection**. If the phone is connected, a PC
sniffer is not that connection and will not see FF02 write requests. Bleak
`start_notify` on FF02 only works if the characteristic also **notifies or
indicates** (rare for a write-only command characteristic).

**Preferred:** Android HCI snoop on the phone that runs the official app.

### Android HCI snoop (receive-side evidence)

1. Developer options → **Enable Bluetooth HCI snoop log**.
2. Toggle Bluetooth off/on.
3. Open Spider Farmer, pair / talk to **SF-GGS-CB** (the usual UI flow).
4. Reproduce a minute of status updates so FF01 notifies appear.
5. Pull the log:

```bat
adb bugreport %USERPROFILE%\operator_local\bugreport
```

or, on many builds:

```bat
adb pull /sdcard/btsnoop_hci.log %USERPROFILE%\operator_local\btsnoop_hci.log
```

On Android 12+ the snoop file often lands inside the bugreport zip
(`FS/data/misc/bluetooth/logs/btsnoop_hci.log` or similar).

6. Open the log in Wireshark. Display filter examples:

```
bluetooth.name == "SF-GGS-CB"
btatt
btuuid == 0xff01 || btuuid == 0xff02
```

Writes: `btatt.opcode == 0x12` (Write Request) or `0x52` (Write Command).
Notifications: `btatt.opcode == 0x1b`.

7. For each interesting ATT packet, copy **value** bytes as hex into
   gitignored files, for example:

```
operator_local\pairing\ff02_0001.hex
operator_local\pairing\ff01_0001.hex
```

Do not include adapter MACs in the filenames or the hex files.

Offline classify (Phase 3 completeness + Phase 4 trailer CRC when
COMPLETE):

```bat
python3 ggs_ff02_sniff.py --from-hex-dir operator_local\pairing
```

### Optional live PC listen (FF01, maybe FF02 indicate)

Only useful if the controller is **not** held by the phone, or if FF02
indicates echoes. BLE addresses stay suppressed.

```bat
python3 ggs_ff02_sniff.py --listen-seconds 60 --dump-frames dumps\ff_session
```

`--no-ff02-notify` keeps FF01-only. This is the same completeness/CRC print
path as Phase 3/4 for framed `AA AA 00 03` buffers.

### Dangerous FF02 write (not required)

```bat
set SF_GGS_I_UNDERSTAND_FF02_WRITE=yes
python3 ggs_ff02_sniff.py --listen-seconds 5 --i-understand-this-writes-ff02 --dangerous-write-ff02-hex 0000
```

Both the flag and the env var are required. The script will not write
otherwise. Phase 6 success does **not** depend on this path.

## What this phase does **not** claim

| Claim | Label |
| --- | --- |
| Operator APK scan yields the live BLE AES key | **BLOCKED** until `trial_decrypt` known-plaintext match |
| PKCS7-valid output from a candidate key | compatible at most; **not** `claimed_success` |
| MQTT `temp` / `humi` / `vpd` live | **false** (`claimed_mqtt_live` is always false here) |
| ESP32 flash / firmware crypto port | out of scope |

## Operator commands (summary)

```bat
python3 -m pip install -r requirements.txt
python3 -m verdant_integration.apk_key_candidates <LOCAL_APK_OR_STRINGS> --try-key-file operator_local\candidates.txt
python3 -m verdant_integration.crypto_research --try-key-file operator_local\candidates.txt --assemblies-from live_phase3
python3 ggs_ff02_sniff.py --from-hex-dir operator_local\pairing
```
