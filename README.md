# RiskScope

An Android app that scans every installed application on your device, computes its APK hash, and checks it against a threat database to detect known malware — while also running on-device heuristic analysis for sideloaded or suspicious apps.

---

## How it works

1. **Hash** — RiskScope computes the SHA-256 hash of each installed APK.
2. **Server check** — The hashes are sent in batches to a [RiskScope-Server](https://github.com/rongo270/RiskScope-Server) instance, which checks them against a malware signature database.
3. **Heuristics** — In parallel, the app analyzes each installed package for behavioral risk signals: debug certificates, dangerous permission combinations, active accessibility services, hidden startup receivers, etc.
4. **Verdict** — Results are combined into a three-level threat classification:

| Level | Meaning |
|-------|---------|
| **DANGER** | The APK hash matches a confirmed malware sample in the database |
| **WATCH** | No known-malware match, but on-device heuristics flagged a notable signal (advisory only) |
| **SAFE** | Not known malware, nothing notable — where normal apps land |

<img width="712" height="578" alt="Screenshot_20260625-210036" src="https://github.com/user-attachments/assets/875dfefc-0ae9-4d5c-8874-0af86be6a854" />


System apps and apps installed from trusted stores (Google Play, Galaxy Store, etc.) are always **SAFE** unless their hash is confirmed malicious.

---

## Features

- Batch SHA-256 hash checking against a remote threat database
- On-device heuristic engine with scored behavioral findings
- Per-app detail sheet with full permission list, install source, certificate, and all risk findings
- Optional scan of system apps
- Configurable server URL — point to your own RiskScope-Server instance
- Works offline (heuristics only when the server is unreachable)
- Jetpack Compose UI with Material 3

---

## Screenshots

> Coming soon

---

## Requirements

- Android 8.0 (API 26) or higher
- A running [RiskScope-Server](https://github.com/rongo270/RiskScope-Server) instance (a public demo is pre-configured)

---

## Getting started

### Build from source

1. Clone the repository:
   ```bash
   git clone https://github.com/rongo270/RiskScope.git
   cd RiskScope
   ```

2. Open in Android Studio (Ladybug or newer recommended).

3. Build and run on a device or emulator:
   ```bash
   ./gradlew installDebug
   ```

### Server

The app ships with a default server URL pointing to a public demo deployment. You can change it at runtime in **Settings → Threat database server URL**.

To run your own server, see [RiskScope-Server](https://github.com/rongo270/RiskScope-Server).

---

## Architecture

```
app/src/main/java/com/rongo/riskscope/
├── data/
│   └── SettingsStore.kt          # SharedPreferences-backed settings (server URL, options)
├── model/
│   └── Models.kt                 # Domain models (AppRisk, ThreatLevel, RiskFinding, …)
├── network/
│   ├── ApiDtos.kt                # Retrofit request/response DTOs
│   ├── RiskScopeApi.kt           # Retrofit API interface
│   └── HashCheckRepository.kt    # OkHttp client, batch check logic
├── scan/
│   ├── ApkHasher.kt              # Computes SHA-256 of installed APKs
│   ├── AppScanner.kt             # Queries PackageManager, runs heuristics
│   └── VerdictEngine.kt          # Combines server verdict + heuristics → ThreatLevel
└── ui/
    ├── ScanScreen.kt             # Main scan list
    ├── SettingsScreen.kt         # Server URL and options
    ├── AppDetailSheet.kt         # Per-app detail bottom sheet
    ├── ScanViewModel.kt          # ViewModel driving the scan flow
    ├── RiskScopeApp.kt           # Navigation host
    ├── components/               # Shared Compose components
    └── theme/                    # Material 3 color scheme and risk-level visuals
```

**Tech stack:** Kotlin · Jetpack Compose · Retrofit 2 · OkHttp 4 · Kotlinx Serialization · Coroutines

---

## Permissions

| Permission | Why |
|------------|-----|
| `INTERNET` | Send APK hashes to the threat database server |
| `ACCESS_NETWORK_STATE` | Check connectivity before attempting server calls |
| `QUERY_ALL_PACKAGES` | Enumerate all installed apps for scanning |

No user data is collected. Only SHA-256 hashes of APK files are sent to the server — not file contents, personal data, or device identifiers.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

## License

[MIT](LICENSE)
