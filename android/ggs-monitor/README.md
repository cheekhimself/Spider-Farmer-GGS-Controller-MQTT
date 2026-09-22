# GGS Monitor (Android, receive-only)

Native debug APK for **local FF01 inspection** of a Spider Farmer GGS controller.
It does **not** decrypt telemetry, does **not** write FF02, and has **no cloud/analytics**.

## Design (MVP)

| Choice | Decision |
| --- | --- |
| Location | `android/ggs-monitor/` — isolated from Python/ESP32; those trees are untouched |
| UI | Kotlin + AppCompat XML views (no Compose) |
| Package | `dev.verdant.ggsmonitor` |
| Display name | GGS Monitor |
| minSdk / targetSdk / compileSdk | 24 / 34 / 34 |
| BLE | Scan **exact** name `SF-GGS-CB`; connect; subscribe to `0000ff01-…` |
| Writes | **No** `writeCharacteristic`. CCCD (`0x2902`) descriptor write only, to enable FF01 notify |
| Frames | Port of Phase 1 `FrameCodec`: magic `AA AA 00 03`, BE declared length, `total = declared + 8` |
| Decode | Fail-closed banner: live sensors unavailable until vendor key material is proven |
| Export | Local share/save via Android chooser (`ACTION_SEND` + FileProvider). Captures stay on device |
| Secrets | `*.apk` already gitignored; captures written to app cache only |

Proven facts reused (do not re-litigate): Cheek 2026-09-16 FF01 framed candidates; UUIDs from repo README / `ggs_ff00_sniffer.py`. Hardware connectivity is **not** claimed unless a phone + controller were used.

## Permissions

- API 31+: `BLUETOOTH_SCAN` (`neverForLocation`), `BLUETOOTH_CONNECT`
- API 24–30: `BLUETOOTH`, `BLUETOOTH_ADMIN`, `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`

## Build (debug APK)

From this directory, with Android SDK 34:

```bash
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > local.properties   # gitignored
./gradlew --no-daemon testDebugUnitTest assembleDebug
```

If `./gradlew` is missing, Gradle 8.9 works:

```bash
gradle-8.9/bin/gradle --no-daemon -p android/ggs-monitor testDebugUnitTest assembleDebug
```

APK output:

```
android/ggs-monitor/app/build/outputs/apk/debug/app-debug.apk
```

Unit tests (pure classifier, no device):

```bash
./gradlew --no-daemon testDebugUnitTest
```

## Install

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On the phone: grant BLE (and on Android 11 and older, location) permissions, turn Bluetooth on, tap **Scan SF-GGS-CB**. You should see packet counts, timestamps, classification (`complete` / `truncated` / `not_framed` / …), declared vs observed length, and a bounded hex list. **Export log** opens the system share sheet.

## What this APK will not do

- Invent AES keys, IVs, or decrypted `getDevSta` fields
- Write FF02 / `setLight` / `getDevSta` requests
- Upload captures
- Claim LIVE sensors on the cloud runner (no controller attached)

Operator APKs, keys, and captures belong in gitignored `operator_local/` or on-device storage — never in git.
