# APKDeepLens

<div align="center">

**Android security insights in full spectrum.**

[Features](#features) • [Detection](#detection-at-a-glance) • [Installation](#installation) • [Usage](#usage) • [Reports](#reports)

*Featured at [Black Hat MEA 2023](https://blackhatmea.com/session/apkaleidoscope-android-security-insights-full-spectrum-0) and [Black Hat ASIA 2024](https://www.blackhat.com/asia-24/arsenal/schedule/index.html#apkdeeplens---android-security-insights-in-full-spectrum-37182)*

</div>

---

![image](https://github.com/d78ui98/APKDeepLens/assets/27950739/c9236e3d-60d5-4832-85dc-f09a449bade3)

## What is APKDeepLens?

APKDeepLens is a Python-based static analysis tool for Android APK files. It decompiles APKs using JADX and runs a deep multi-layer security scan covering the OWASP Mobile Top 10 (2024). Every finding is tagged with a severity level (CRITICAL / HIGH / MEDIUM / LOW / INFO) and an OWASP category, and results are exported in JSON, HTML, PDF, or TXT format.

---

## Features

- **APK decompilation** via JADX (Windows, Linux, macOS, Docker)
- **AndroidManifest.xml analysis** — permissions, exported components, misconfigurations
- **Deep code scanning** — walks all decompiled Java/Kotlin/XML source
- **Hardcoded secret detection** — API keys, OAuth tokens, private keys, passwords
- **Insecure communication detection** — HTTP, FTP, SMTP, JavaScript protocol URLs
- **Cryptographic weakness detection** — weak algorithms, ECB mode, insecure random
- **WebView security analysis** — JavaScript interface, file access, SSL ignore
- **SSL/TLS misconfiguration** — trust-all certs, hostname bypass, legacy protocols
- **Dynamic code execution** — DexClassLoader, Runtime.exec(), ProcessBuilder
- **Insecure data storage** — world-readable files, clipboard, external storage, raw SQL
- **Sensitive data in logs** — Log.*, System.out.println, printStackTrace
- **Intent security** — implicit PendingIntents, sticky broadcasts
- **Zip path traversal** (Zip Slip) detection
- **Severity classification** — CRITICAL, HIGH, MEDIUM, LOW, INFO per finding
- **OWASP Mobile Top 10 (2024) mapping** on every finding
- **Multi-format reports** — JSON, HTML, PDF, TXT
- **CI/CD ready** — JSON output integrates directly into pipelines
- **Cross-platform** — Windows, Linux, macOS, Docker

---

## Detection at a Glance

| Category                | Checks | Severity Range    | OWASP           |
|-------------------------|--------|-------------------|-----------------|
| Manifest Security       | 10     | CRITICAL → MEDIUM | M3–M9           |
| Cryptography            | 7      | CRITICAL → MEDIUM | M1, M10         |
| WebView Security        | 6      | CRITICAL → HIGH   | M4, M5, M7, M9  |
| SSL / TLS               | 5      | CRITICAL → MEDIUM | M5              |
| Dynamic Code Execution  | 4      | HIGH → MEDIUM     | M4, M7          |
| Insecure Data Storage   | 6      | HIGH → LOW        | M4, M6, M9      |
| Logs / Privacy          | 3      | MEDIUM → LOW      | M6              |
| Intent Security         | 2      | HIGH → MEDIUM     | M4              |
| Zip Path Traversal      | 1      | HIGH              | M4              |
| Hardcoded Secrets       | 16+    | —                 | M1              |
| Insecure Communications | —      | —                 | M5              |

For full check IDs, regex patterns, and evidence examples see [DETECTION.md](DETECTION.md).

---

## Installation

**Requirements:** Python 3.10+, Java / OpenJDK

### Linux / macOS

```bash
git clone https://github.com/d78ui98/APKDeepLens.git
cd APKDeepLens
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python APKDeepLens.py --help
```

### Windows

```bash
git clone https://github.com/d78ui98/APKDeepLens.git
cd APKDeepLens
python3 -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python APKDeepLens.py --help
```

### Docker

```bash
docker build -t apkdeeplens .
docker run --rm -v /path/to/apk/files:/apk apkdeeplens -apk /apk/file.apk
```

---

## Usage

```bash
# Basic scan — outputs JSON report
python APKDeepLens.py -apk app.apk

# Skip decompilation when source is already extracted
python APKDeepLens.py -apk app.apk -source_code_path /path/to/source

# Generate HTML report
python APKDeepLens.py -apk app.apk -report html

# Generate PDF report
python APKDeepLens.py -apk app.apk -report pdf

# Generate plain-text report
python APKDeepLens.py -apk app.apk -report txt

# Specify output directory
python APKDeepLens.py -apk app.apk -report json -o /path/to/output/

# Skip virtualenv check (CI/CD)
python APKDeepLens.py -apk app.apk --ignore_virtualenv
```

All reports are saved to a `reports/` subdirectory of the output path.

---

## Reports

| Format | Description |
|--------|-------------|
| **JSON** (default) | Machine-readable. All findings include `id`, `severity`, `owasp`, `description`, and `evidence`. Ideal for pipeline integration. |
| **HTML / PDF** | Colour-coded severity tables — CRITICAL in red, HIGH in orange, MEDIUM in amber. |
| **TXT** | Human-readable, severity-sorted findings with file locations and descriptions. |

See [DETECTION.md](DETECTION.md) for the full JSON output schema.

---

## Project Structure

```
APKDeepLens/
├── APKDeepLens.py               # Main entry point
├── report_gen.py                # Report generation (JSON, HTML, PDF, TXT)
├── report_template.html         # HTML report template
├── requirements.txt
└── static_tools/
    ├── code_scanner.py          # Deep code-pattern security scanner (40+ checks)
    ├── scan_android_manifest.py # Manifest parser + security checker
    ├── sensitive_info_extractor.py  # Hardcoded secret + insecure URL scanner
    ├── known_false_positives.txt    # Curated false-positive filter list
    └── utility/
        └── utility_class.py    # Shared constants (DANGEROUS_PERMISSIONS, util)
```

---

## Contributing

Feature requests, bug reports, and pull requests are welcome at [github.com/d78ui98/APKDeepLens/issues](https://github.com/d78ui98/APKDeepLens/issues).

---

## Featured at

- Black Hat MEA 2023 — [APKaleidoscope: Android Security Insights in Full Spectrum](https://blackhatmea.com/session/apkaleidoscope-android-security-insights-full-spectrum-0)
- Black Hat ASIA 2024 — [APKDeepLens: Android Security Insights in Full Spectrum](https://www.blackhat.com/asia-24/arsenal/schedule/index.html#apkdeeplens---android-security-insights-in-full-spectrum-37182)
- Black Hat MEA 2024 — [APKDeepLens: Android Security Insights in Full Spectrum](https://attend.blackhatevents.virtual.informatech.com/event/black-hat-mea-2024/planning/UGxhbm5pbmdfMjE5Nzg5OA==)
- GISEC Global Dubai 2024 — APKDeepLens: Android Security Insights in Full Spectrum
