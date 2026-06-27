<div align="center">

<img src="branding/ic_riskscope_512.png" width="132" alt="RiskScope" />

# RiskScope

**Know what's really running on your phone.**

An on-device malware & risk scanner for Android. It fingerprints every installed app, cross-checks it against a live threat database, and does its own detective work to flag the sketchy ones.

<img src="https://img.shields.io/badge/Platform-Android%208.0%2B-3DDC84?logo=android&logoColor=white" alt="Android 8.0+" />
<img src="https://img.shields.io/badge/Kotlin-7F52FF?logo=kotlin&logoColor=white" alt="Kotlin" />
<img src="https://img.shields.io/badge/Jetpack%20Compose-4285F4?logo=jetpackcompose&logoColor=white" alt="Jetpack Compose" />
<img src="https://img.shields.io/badge/License-MIT-2FA86A" alt="MIT" />

</div>

---

> You install apps. Some of them lie about what they do. **RiskScope catches them.**

## 🔍 How it works

1. **Fingerprint** — compute the SHA-256 hash of every installed APK.
2. **Cross-check** — send those hashes (and *nothing else*) to a [RiskScope-Server](https://github.com/rongo270/RiskScope-Server) to match against known malware.
3. **Investigate** — in parallel, on-device heuristics sniff out red flags: debug certificates, dangerous permission combos, accessibility abuse, hidden startup receivers, and more.
4. **Verdict** — it all collapses into one of three clear calls:

|     | Level | What it means |
| --- | --- | --- |
| 🔴 | **DANGER** | The APK matches confirmed malware in the database. Delete it. |
| 🟡 | **WATCH** | Not known malware, but the heuristics noticed something. Worth a look. |
| 🟢 | **SAFE** | Nothing known, nothing suspicious — where normal apps land. |

Apps from trusted stores (Play, Galaxy Store…) and system apps stay **SAFE** unless their hash is a confirmed match.

<div align="center">
  <img width="460" alt="RiskScope scan results" src="https://github.com/user-attachments/assets/875dfefc-0ae9-4d5c-8874-0af86be6a854" />
</div>

## ✨ What you get

- 🛡️ **Batch hash-checking** against a live threat database
- 🧠 **A heuristic engine** that scores and *explains* every finding
- 📋 **Tap any app** for the full story — permissions, install source, signing certificate, every risk signal
- 🌐 **Bring your own server**, or use the bundled public demo
- ✈️ **Works offline** — heuristics keep running when the server's unreachable
- 🎚️ **Optional deep scan** of system apps

## 🚀 Get started

**You'll need:** Android 8.0 (API 26)+ and a [RiskScope-Server](https://github.com/rongo270/RiskScope-Server) — a public demo comes pre-configured, so you can just run it.

```bash
git clone https://github.com/rongo270/RiskScope.git
cd RiskScope
./gradlew installDebug
```

Or open it in Android Studio (Ladybug or newer) and hit **Run**. Swap the server anytime under **Settings → Threat database server URL**.

## 🔒 Privacy

RiskScope sends **only SHA-256 hashes** of APK files — never file contents, personal data, or device identifiers. No accounts, no tracking, no telemetry.

## 📄 License

[MIT](LICENSE) — do what you like. Issues and pull requests welcome.
