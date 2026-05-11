# APKDeepLens — Detection Reference

Full check IDs, patterns, severity levels, and OWASP mappings for every rule in APKDeepLens. See the [README](README.md) for installation and usage.

---

## Manifest Security (AndroidManifest.xml)

| ID | Check | Severity | OWASP |
|---|---|---|---|
| MANIFEST_DEBUGGABLE | `android:debuggable="true"` in release build | CRITICAL | M8 |
| MANIFEST_ALLOW_BACKUP | `android:allowBackup="true"` or not set (default true) | HIGH | M9 |
| MANIFEST_CLEARTEXT | `android:usesCleartextTraffic="true"` | HIGH | M5 |
| MANIFEST_EXPORTED_NO_PERM | Exported component (activity/service/receiver/provider) with no `android:permission` | HIGH | M4 |
| MANIFEST_GRANT_URI | `android:grantUriPermissions="true"` on a provider | HIGH | M4 |
| MANIFEST_TASK_HIJACK | Activity with non-default `android:taskAffinity` (task hijacking risk) | MEDIUM | M4 |
| MANIFEST_CUSTOM_PERM_NORMAL | Custom `<permission>` with `protectionLevel="normal"` or unset | MEDIUM | M3 |
| MANIFEST_MIN_SDK_LOW | `minSdkVersion` below 21 | MEDIUM | M8 |
| MANIFEST_TARGET_SDK_LOW | `targetSdkVersion` below 28 | MEDIUM | M8 |
| MANIFEST_DEEP_LINK | Browsable activity with custom URI scheme and no permission | MEDIUM | M4 |

---

## Cryptography

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| CRYPTO_ECB_MODE | `Cipher.getInstance(...)` using ECB mode | CRITICAL | M10 |
| CRYPTO_HARDCODED_KEY | `new SecretKeySpec("hardcoded_string", ...)` | CRITICAL | M1 |
| CRYPTO_WEAK_MD5 | `MessageDigest.getInstance("MD5")` | HIGH | M10 |
| CRYPTO_INSECURE_RANDOM | `new Random()` or `Math.random()` for security-sensitive values | HIGH | M10 |
| CRYPTO_WEAK_ALG | DES, 3DES, RC2, RC4, or Blowfish cipher usage | HIGH | M10 |
| CRYPTO_STATIC_IV | `new IvParameterSpec(new byte[...])` — hardcoded IV | HIGH | M10 |
| CRYPTO_WEAK_SHA1 | `MessageDigest.getInstance("SHA-1")` | MEDIUM | M10 |

---

## WebView Security

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| WEBVIEW_JS_INTERFACE | `addJavascriptInterface()` — Java object exposed to JavaScript | CRITICAL | M4 |
| WEBVIEW_SSL_IGNORE | `onReceivedSslError()` override — likely accepts bad certificates | CRITICAL | M5 |
| WEBVIEW_UNIV_ACCESS | `setAllowUniversalAccessFromFileURLs(true)` | CRITICAL | M9 |
| WEBVIEW_JS_ENABLED | `setJavaScriptEnabled(true)` | HIGH | M4 |
| WEBVIEW_FILE_ACCESS | `setAllowFileAccess(true)` or `setAllowFileAccessFromFileURLs(true)` | HIGH | M9 |
| WEBVIEW_DEBUG | `setWebContentsDebuggingEnabled(true)` | HIGH | M7 |

---

## SSL / TLS

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| SSL_TRUST_ALL_CERTS | `TrustAllCerts`, `ALLOW_ALL_HOSTNAME_VERIFIER`, or `trustAllCerts` pattern | CRITICAL | M5 |
| SSL_HOSTNAME_ALL | `HostnameVerifier` or `verify()` returning `true` unconditionally | CRITICAL | M5 |
| SSL_INSECURE_SOCKET | `SSLSocketFactory.getInsecure()` or `TLS_ALLOW_ALL` | CRITICAL | M5 |
| SSL_WEAK_TRUSTMANAGER | `X509TrustManager` / `checkServerTrusted` / `checkClientTrusted` present | CRITICAL | M5 |
| SSL_LEGACY_SSL | `SSLContext.getInstance("SSL")` — enables SSLv3 | MEDIUM | M5 |

---

## Dynamic Code Execution

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| DYN_DEXCLASSLOADER | `DexClassLoader`, `PathClassLoader`, `InMemoryDexClassLoader` | HIGH | M7 |
| DYN_RUNTIME_EXEC | `Runtime.getRuntime().exec()` — OS command execution | HIGH | M4 |
| DYN_PROCESS_BUILDER | `new ProcessBuilder(...)` | HIGH | M4 |
| DYN_REFLECTION | `getDeclaredMethod`, `getDeclaredField`, `forName(...).invoke(...)` | MEDIUM | M7 |

---

## Insecure Data Storage

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| STORAGE_WORLD_READ | `MODE_WORLD_READABLE` | HIGH | M9 |
| STORAGE_WORLD_WRITE | `MODE_WORLD_WRITEABLE` | HIGH | M9 |
| STORAGE_SQLITE_RAW | `rawQuery(... +` or `execSQL(... +` — SQL injection risk | HIGH | M4 |
| STORAGE_CLIPBOARD | `setPrimaryClip()` / `ClipboardManager` — sensitive data to clipboard | MEDIUM | M6 |
| STORAGE_EXTERNAL | `getExternalStorageDirectory()` / `getExternalFilesDir()` | MEDIUM | M9 |
| STORAGE_SHARED_PREFS | `getSharedPreferences()` — plaintext storage risk | LOW | M9 |

---

## Sensitive Data in Logs

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| LOG_SENSITIVE | `Log.d/e/i/v/w(...)` containing keywords: password, token, secret, key, auth, credential | MEDIUM | M6 |
| LOG_SYSOUT | `System.out.println(...)` in production code | LOW | M6 |
| LOG_STACKTRACE | `printStackTrace()` exposing internal stack details | LOW | M6 |

---

## Intent Security

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| INTENT_PENDING_IMPLICIT | `PendingIntent.getActivity/getBroadcast/getService(... new Intent())` — implicit pending intent | HIGH | M4 |
| INTENT_STICKY_BROADCAST | `sendStickyBroadcast()` — deprecated, any app can receive | MEDIUM | M4 |

---

## Zip Path Traversal

| ID | What is detected | Severity | OWASP |
|---|---|---|---|
| ZIP_PATH_TRAVERSAL | `ZipEntry.getName()`, `ZipInputStream`, `new ZipFile()` — Zip Slip risk | HIGH | M4 |

---

## Hardcoded Secrets (Pattern Matching)

Scans every decompiled source file for embedded credentials:

| Pattern | Examples |
|---|---|
| Slack tokens | `xoxb-...`, `xoxp-...` |
| Google API keys | `AIza...` |
| AWS access keys | `AKIA...` |
| Stripe API keys | `sk_live_...`, `rk_live_...` |
| Twilio keys | `SK...`, `AC...`, `AP...` |
| GitHub tokens | `username:token@github.com` |
| Facebook OAuth | Facebook app secrets |
| Twitter OAuth | Twitter access tokens |
| Mailgun / Mailchimp / Picatic | Service API keys |
| Square OAuth / access tokens | Payment keys |
| PayPal Braintree tokens | `access_token$production$...` |
| Private SSH / RSA / PGP keys | `-----BEGIN PRIVATE KEY-----` |
| Generic API keys | `api_key = "..."` patterns |
| Generic secrets | `secret = "..."` patterns |
| Passwords in URLs | `protocol://user:pass@host` |
| IP addresses | Internal/external IP literals |

---

## Insecure Communications

Detects all non-HTTPS/non-secure protocol usage in source code:
- `http://` URLs
- `ftp://` / `sftp://` URLs
- `smtp://` endpoints
- `javascript:` protocol handlers
- `www.` domain references

All results are filtered against a curated false-positive list to reduce noise.

---

## OWASP Mobile Top 10 Coverage

| OWASP Category | Checks |
|---|---|
| M1: Improper Credential Usage | Hardcoded secrets, `CRYPTO_HARDCODED_KEY` |
| M3: Insecure Auth/Authorization | `MANIFEST_CUSTOM_PERM_NORMAL` |
| M4: Insufficient Input/Output Validation | `WEBVIEW_JS_INTERFACE`, `DYN_RUNTIME_EXEC`, `DYN_PROCESS_BUILDER`, `STORAGE_SQLITE_RAW`, `ZIP_PATH_TRAVERSAL`, `INTENT_PENDING_IMPLICIT`, `MANIFEST_EXPORTED_NO_PERM`, `MANIFEST_DEEP_LINK`, `MANIFEST_GRANT_URI`, `MANIFEST_TASK_HIJACK`, `INTENT_STICKY_BROADCAST` |
| M5: Insecure Communication | `SSL_TRUST_ALL_CERTS`, `SSL_HOSTNAME_ALL`, `SSL_INSECURE_SOCKET`, `SSL_WEAK_TRUSTMANAGER`, `WEBVIEW_SSL_IGNORE`, `MANIFEST_CLEARTEXT`, `SSL_LEGACY_SSL`, insecure URL detection |
| M6: Inadequate Privacy Controls | `LOG_SENSITIVE`, `LOG_SYSOUT`, `LOG_STACKTRACE`, `STORAGE_CLIPBOARD` |
| M7: Insufficient Binary Protections | `DYN_DEXCLASSLOADER`, `DYN_REFLECTION`, `WEBVIEW_DEBUG` |
| M8: Security Misconfiguration | `MANIFEST_DEBUGGABLE`, `MANIFEST_MIN_SDK_LOW`, `MANIFEST_TARGET_SDK_LOW` |
| M9: Insecure Data Storage | `MANIFEST_ALLOW_BACKUP`, `STORAGE_WORLD_READ`, `STORAGE_WORLD_WRITE`, `STORAGE_EXTERNAL`, `STORAGE_SHARED_PREFS`, `WEBVIEW_FILE_ACCESS`, `WEBVIEW_UNIV_ACCESS` |
| M10: Insufficient Cryptography | `CRYPTO_ECB_MODE`, `CRYPTO_WEAK_MD5`, `CRYPTO_WEAK_SHA1`, `CRYPTO_INSECURE_RANDOM`, `CRYPTO_STATIC_IV`, `CRYPTO_WEAK_ALG` |

---

## JSON Output Schema

```json
{
  "apk_name": "app.apk",
  "package_name": "com.example.app",
  "permission": ["android.permission.INTERNET", "..."],
  "dangerous_permission": ["android.permission.CAMERA", "..."],
  "manifest_analysis": {
    "activities": { "all": [...], "exported": [...] },
    "services":   { "all": [...], "exported": [...] },
    "receivers":  { "all": [...], "exported": [...] },
    "providers":  { "all": [...], "exported": [...] }
  },
  "manifest_security": [
    {
      "id": "MANIFEST_DEBUGGABLE",
      "title": "Application is Debuggable",
      "severity": "CRITICAL",
      "owasp": "M8: Security Misconfiguration",
      "description": "...",
      "evidence": "android:debuggable=\"true\""
    }
  ],
  "hardcoded_secrets": [
    { "type": "google_api", "ioc": "AIzaSy...", "path": "sources/MainActivity.java" }
  ],
  "insecure_requests": ["http://api.example.com/endpoint"],
  "code_findings": [
    {
      "id": "CRYPTO_ECB_MODE",
      "title": "ECB Mode Encryption",
      "severity": "CRITICAL",
      "owasp": "M10: Insufficient Cryptography",
      "description": "...",
      "file": "sources/crypto/EncryptionHelper.java",
      "line": 42,
      "evidence": "Cipher.getInstance(\"AES/ECB/PKCS5Padding\")"
    }
  ]
}
```
