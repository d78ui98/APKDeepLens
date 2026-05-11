import os
import re
from .utility.utility_class import util

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class CodeScanner:
    """
    Source-code level security scanner. Walks decompiled APK source and
    detects security issues mapped to OWASP Mobile Top 10 (2024).
    """

    SCAN_EXTENSIONS = (".java", ".kt", ".xml", ".js")

    def __init__(self, source_path: str):
        self.source_path = source_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_all(self) -> list:
        findings = []
        findings += self.check_crypto()
        findings += self.check_webview()
        findings += self.check_ssl()
        findings += self.check_dynamic_code()
        findings += self.check_data_storage()
        findings += self.check_logging()
        findings += self.check_intent_issues()
        findings += self.check_zip_traversal()
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
        return findings

    # ------------------------------------------------------------------
    # Crypto
    # ------------------------------------------------------------------

    def check_crypto(self) -> list:
        checks = [
            {
                "id": "CRYPTO_ECB_MODE",
                "title": "ECB Mode Encryption",
                "severity": "CRITICAL",
                "owasp": "M10: Insufficient Cryptography",
                "description": (
                    "ECB (Electronic Codebook) mode encrypts identical plaintext blocks "
                    "to identical ciphertext, leaking data patterns. Attackers can "
                    "detect and manipulate encrypted data without the key."
                ),
                "pattern": r'Cipher\.getInstance\s*\(.*ECB',
            },
            {
                "id": "CRYPTO_HARDCODED_KEY",
                "title": "Hardcoded Cryptographic Key",
                "severity": "CRITICAL",
                "owasp": "M1: Improper Credential Usage",
                "description": (
                    "A cryptographic key is hardcoded as a string literal in "
                    "SecretKeySpec. Any attacker who decompiles the APK can extract "
                    "the key and decrypt all protected data."
                ),
                "pattern": r'new\s+SecretKeySpec\s*\(\s*["\']',
            },
            {
                "id": "CRYPTO_WEAK_MD5",
                "title": "Weak Hash Algorithm: MD5",
                "severity": "HIGH",
                "owasp": "M10: Insufficient Cryptography",
                "description": (
                    "MD5 is cryptographically broken and unsuitable for security "
                    "purposes. Collisions can be computed in seconds. Do not use "
                    "for password hashing, integrity checks, or digital signatures."
                ),
                "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
            },
            {
                "id": "CRYPTO_INSECURE_RANDOM",
                "title": "Insecure Random Number Generator",
                "severity": "HIGH",
                "owasp": "M10: Insufficient Cryptography",
                "description": (
                    "java.util.Random and Math.random() are not cryptographically "
                    "secure. Outputs are predictable. Use SecureRandom for any "
                    "security-sensitive value (tokens, keys, nonces, salts)."
                ),
                "pattern": r'new\s+Random\s*\(|Math\.random\s*\(',
            },
            {
                "id": "CRYPTO_WEAK_ALG",
                "title": "Weak Cipher Algorithm",
                "severity": "HIGH",
                "owasp": "M10: Insufficient Cryptography",
                "description": (
                    "DES, 3DES, RC2, RC4, and Blowfish are considered weak or broken. "
                    "Use AES-256-GCM or ChaCha20-Poly1305 instead."
                ),
                "pattern": r'Cipher\.getInstance\s*\(.*["\'](?:DES|RC2|RC4|Blowfish|3DES|DESede)',
            },
            {
                "id": "CRYPTO_STATIC_IV",
                "title": "Static / Hardcoded IV",
                "severity": "HIGH",
                "owasp": "M10: Insufficient Cryptography",
                "description": (
                    "A hardcoded byte array is used as the Initialization Vector (IV). "
                    "Reusing the same IV with the same key can allow attackers to "
                    "recover plaintext. Generate a random IV for each encryption."
                ),
                "pattern": r'new\s+IvParameterSpec\s*\(\s*new\s+byte\s*\[',
            },
            {
                "id": "CRYPTO_WEAK_SHA1",
                "title": "Weak Hash Algorithm: SHA-1",
                "severity": "MEDIUM",
                "owasp": "M10: Insufficient Cryptography",
                "description": (
                    "SHA-1 is deprecated for security use. Practical collision attacks "
                    "exist. Avoid for digital signatures, certificate fingerprints, or "
                    "password hashing. Use SHA-256 or SHA-3."
                ),
                "pattern": r'MessageDigest\.getInstance\s*\(\s*["\'](?:SHA-1|SHA1)["\']',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # WebView
    # ------------------------------------------------------------------

    def check_webview(self) -> list:
        checks = [
            {
                "id": "WEBVIEW_JS_INTERFACE",
                "title": "JavaScript Interface Exposed to WebView",
                "severity": "CRITICAL",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "addJavascriptInterface() exposes Java objects to JavaScript. "
                    "Any JavaScript running in the WebView (including injected scripts "
                    "via XSS) can call these methods, potentially leading to arbitrary "
                    "code execution."
                ),
                "pattern": r'addJavascriptInterface\s*\(',
            },
            {
                "id": "WEBVIEW_SSL_IGNORE",
                "title": "WebView Ignores SSL Errors",
                "severity": "CRITICAL",
                "owasp": "M5: Insecure Communication",
                "description": (
                    "Overriding onReceivedSslError() and calling handler.proceed() "
                    "disables SSL certificate validation, making the app vulnerable "
                    "to MITM attacks. The app will trust any certificate."
                ),
                "pattern": r'onReceivedSslError',
            },
            {
                "id": "WEBVIEW_UNIV_ACCESS",
                "title": "WebView Universal File Access Enabled",
                "severity": "CRITICAL",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "setAllowUniversalAccessFromFileURLs(true) allows JavaScript in "
                    "file:// URLs to read any file accessible to the app, including "
                    "private data, tokens, and databases."
                ),
                "pattern": r'setAllowUniversalAccessFromFileURLs\s*\(\s*true',
            },
            {
                "id": "WEBVIEW_JS_ENABLED",
                "title": "JavaScript Enabled in WebView",
                "severity": "HIGH",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "Enabling JavaScript in WebView opens attack surface for XSS. "
                    "Combine only with strict Content-Security-Policy and input "
                    "sanitisation. Avoid if the app does not require it."
                ),
                "pattern": r'setJavaScriptEnabled\s*\(\s*true',
            },
            {
                "id": "WEBVIEW_FILE_ACCESS",
                "title": "WebView File Access Enabled",
                "severity": "HIGH",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "setAllowFileAccess(true) or setAllowFileAccessFromFileURLs(true) "
                    "allows WebView to read local files. Combined with JavaScript, "
                    "this can expose app-private data to malicious pages."
                ),
                "pattern": r'setAllowFileAccess\s*\(\s*true|setAllowFileAccessFromFileURLs\s*\(\s*true',
            },
            {
                "id": "WEBVIEW_DEBUG",
                "title": "WebView Remote Debugging Enabled",
                "severity": "HIGH",
                "owasp": "M7: Insufficient Binary Protections",
                "description": (
                    "setWebContentsDebuggingEnabled(true) allows Chrome DevTools to "
                    "attach to the WebView remotely. This should never be enabled "
                    "in production builds."
                ),
                "pattern": r'setWebContentsDebuggingEnabled\s*\(\s*true',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # SSL / TLS
    # ------------------------------------------------------------------

    def check_ssl(self) -> list:
        checks = [
            {
                "id": "SSL_TRUST_ALL_CERTS",
                "title": "Trust-All SSL Certificate Implementation",
                "severity": "CRITICAL",
                "owasp": "M5: Insecure Communication",
                "description": (
                    "Custom TrustManager that trusts all certificates disables SSL "
                    "validation entirely. Any certificate — including self-signed, "
                    "expired, or from a malicious CA — will be accepted, enabling MITM."
                ),
                "pattern": r'TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|trustAllCerts|TrustAll',
            },
            {
                "id": "SSL_HOSTNAME_ALL",
                "title": "HostnameVerifier Accepts Any Hostname",
                "severity": "CRITICAL",
                "owasp": "M5: Insecure Communication",
                "description": (
                    "A HostnameVerifier that always returns true bypasses hostname "
                    "verification. An attacker with any valid certificate can intercept "
                    "traffic destined for the real server."
                ),
                "pattern": r'verify\s*\(.*\)\s*\{[^}]*return\s+true|HostnameVerifier.*return\s+true',
            },
            {
                "id": "SSL_INSECURE_SOCKET",
                "title": "Insecure SSLSocketFactory",
                "severity": "CRITICAL",
                "owasp": "M5: Insecure Communication",
                "description": (
                    "SSLSocketFactory.getInsecure() or equivalent creates a socket "
                    "factory that does not validate server certificates."
                ),
                "pattern": r'SSLSocketFactory\.getInsecure|TLS_ALLOW_ALL',
            },
            {
                "id": "SSL_LEGACY_SSL",
                "title": "Legacy SSL Protocol in Use",
                "severity": "MEDIUM",
                "owasp": "M5: Insecure Communication",
                "description": (
                    'SSLContext.getInstance("SSL") enables SSLv3 which is vulnerable '
                    "to POODLE and other attacks. Use TLSv1.2 or TLSv1.3 explicitly."
                ),
                "pattern": r'SSLContext\.getInstance\s*\(\s*["\']SSL["\']',
            },
            {
                "id": "SSL_WEAK_TRUSTMANAGER",
                "title": "Empty or Permissive TrustManager",
                "severity": "CRITICAL",
                "owasp": "M5: Insecure Communication",
                "description": (
                    "An X509TrustManager with an empty checkServerTrusted() method "
                    "accepts all server certificates without validation."
                ),
                "pattern": r'X509TrustManager|checkServerTrusted|checkClientTrusted',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # Dynamic code execution
    # ------------------------------------------------------------------

    def check_dynamic_code(self) -> list:
        checks = [
            {
                "id": "DYN_DEXCLASSLOADER",
                "title": "Dynamic DEX/Class Loading",
                "severity": "HIGH",
                "owasp": "M7: Insufficient Binary Protections",
                "description": (
                    "DexClassLoader, PathClassLoader, or InMemoryDexClassLoader loads "
                    "code at runtime from external sources. Malicious code could be "
                    "loaded if the source is attacker-controlled or poorly validated."
                ),
                "pattern": r'DexClassLoader|PathClassLoader|InMemoryDexClassLoader',
            },
            {
                "id": "DYN_RUNTIME_EXEC",
                "title": "Runtime Command Execution",
                "severity": "HIGH",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "Runtime.exec() or Runtime.getRuntime().exec() executes OS "
                    "commands. If any part of the command is derived from user input "
                    "or an external source, command injection is possible."
                ),
                "pattern": r'Runtime\.getRuntime\(\)\.exec|Runtime\.exec\(',
            },
            {
                "id": "DYN_PROCESS_BUILDER",
                "title": "ProcessBuilder Command Execution",
                "severity": "HIGH",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "ProcessBuilder constructs and launches OS processes. User-controlled "
                    "arguments can lead to command injection if not properly sanitised."
                ),
                "pattern": r'new\s+ProcessBuilder\s*\(',
            },
            {
                "id": "DYN_REFLECTION",
                "title": "Reflection-Based Method Invocation",
                "severity": "MEDIUM",
                "owasp": "M7: Insufficient Binary Protections",
                "description": (
                    "getDeclaredMethod/getDeclaredField with invoke() can bypass access "
                    "controls and is commonly used to evade static analysis. Also "
                    "indicates potential for runtime code manipulation."
                ),
                "pattern": r'getDeclaredMethod|getDeclaredField|forName.*invoke',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # Insecure data storage
    # ------------------------------------------------------------------

    def check_data_storage(self) -> list:
        checks = [
            {
                "id": "STORAGE_WORLD_READ",
                "title": "World-Readable File Created",
                "severity": "HIGH",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "MODE_WORLD_READABLE makes files readable by all apps on the device. "
                    "Deprecated since API 17 and disallowed on modern Android, but "
                    "still a critical data exposure risk on older devices."
                ),
                "pattern": r'MODE_WORLD_READABLE',
            },
            {
                "id": "STORAGE_WORLD_WRITE",
                "title": "World-Writable File Created",
                "severity": "HIGH",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "MODE_WORLD_WRITEABLE makes files writable by all apps on the device, "
                    "allowing malicious apps to tamper with the data."
                ),
                "pattern": r'MODE_WORLD_WRITEABLE',
            },
            {
                "id": "STORAGE_SQLITE_RAW",
                "title": "Possible SQL Injection in SQLite Query",
                "severity": "HIGH",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "rawQuery() or execSQL() called with string concatenation (+). "
                    "If any concatenated value originates from user input or external "
                    "data, SQL injection is possible."
                ),
                "pattern": r'rawQuery\s*\(.*\+|execSQL\s*\(.*\+',
            },
            {
                "id": "STORAGE_CLIPBOARD",
                "title": "Data Written to Clipboard",
                "severity": "MEDIUM",
                "owasp": "M6: Inadequate Privacy Controls",
                "description": (
                    "Data written to ClipboardManager is accessible to any app with "
                    "FOREGROUND permission. Avoid storing sensitive data (passwords, "
                    "tokens, PII) in the clipboard."
                ),
                "pattern": r'setPrimaryClip\s*\(|ClipboardManager',
            },
            {
                "id": "STORAGE_EXTERNAL",
                "title": "Sensitive Data on External Storage",
                "severity": "MEDIUM",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "Data written to external storage is readable by any app with "
                    "READ_EXTERNAL_STORAGE permission. Do not store sensitive data "
                    "on SD card or external volumes."
                ),
                "pattern": r'getExternalStorageDirectory\s*\(\)|getExternalFilesDir\s*\(',
            },
            {
                "id": "STORAGE_SHARED_PREFS",
                "title": "SharedPreferences Usage Detected",
                "severity": "LOW",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "SharedPreferences stores data in plaintext XML. Sensitive values "
                    "(tokens, passwords, keys) should be encrypted using EncryptedSharedPreferences "
                    "from the Jetpack Security library."
                ),
                "pattern": r'getSharedPreferences\s*\(|SharedPreferences',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def check_logging(self) -> list:
        checks = [
            {
                "id": "LOG_SENSITIVE",
                "title": "Sensitive Data in Log Statement",
                "severity": "MEDIUM",
                "owasp": "M6: Inadequate Privacy Controls",
                "description": (
                    "Log.d/e/i/v/w() call contains keywords suggesting sensitive data "
                    "(password, token, key, secret, auth, credential). Log output is "
                    "accessible to other apps via logcat on unpatched or rooted devices."
                ),
                "pattern": r'Log\s*\.[devwiDEVWI]\s*\(.*(?:password|passwd|secret|token|apikey|api_key|auth|credential|ssn|cvv)',
            },
            {
                "id": "LOG_SYSOUT",
                "title": "System.out.println in Production Code",
                "severity": "LOW",
                "owasp": "M6: Inadequate Privacy Controls",
                "description": (
                    "System.out.println() output appears in logcat on debug builds "
                    "and is a common source of accidental data leakage. Remove or "
                    "guard with BuildConfig.DEBUG."
                ),
                "pattern": r'System\.out\.print',
            },
            {
                "id": "LOG_STACKTRACE",
                "title": "printStackTrace() Leaks Stack Information",
                "severity": "LOW",
                "owasp": "M6: Inadequate Privacy Controls",
                "description": (
                    "printStackTrace() prints internal class names, method names, and "
                    "file paths to logcat, aiding reverse engineering and revealing "
                    "architectural details to attackers."
                ),
                "pattern": r'printStackTrace\s*\(\s*\)',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # Intent security
    # ------------------------------------------------------------------

    def check_intent_issues(self) -> list:
        checks = [
            {
                "id": "INTENT_PENDING_IMPLICIT",
                "title": "Implicit PendingIntent",
                "severity": "HIGH",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "PendingIntent wrapping an empty or implicit Intent can be "
                    "intercepted and filled by a malicious app, leading to privilege "
                    "escalation. Always use explicit intents with PendingIntent. "
                    "Requires FLAG_IMMUTABLE or FLAG_MUTABLE in Android 12+."
                ),
                "pattern": r'PendingIntent\s*\.\s*(?:getActivity|getBroadcast|getService)\s*\(.*new\s+Intent\s*\(\s*\)',
            },
            {
                "id": "INTENT_STICKY_BROADCAST",
                "title": "Sticky Broadcast Used",
                "severity": "MEDIUM",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "sendStickyBroadcast() is deprecated since API 21. Sticky broadcasts "
                    "linger in the system and any app can receive them at any time, "
                    "potentially exposing sensitive broadcast data."
                ),
                "pattern": r'sendStickyBroadcast\s*\(',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # Zip path traversal
    # ------------------------------------------------------------------

    def check_zip_traversal(self) -> list:
        checks = [
            {
                "id": "ZIP_PATH_TRAVERSAL",
                "title": "Potential Zip Path Traversal (Zip Slip)",
                "severity": "HIGH",
                "owasp": "M4: Insufficient Input/Output Validation",
                "description": (
                    "ZipEntry.getName() returns the entry path as stored in the archive. "
                    "If this path is used to write files without canonicalisation and "
                    "containment checks (e.g., startsWith(destDir)), an attacker can "
                    "craft a ZIP file with '../' entries to overwrite arbitrary files."
                ),
                "pattern": r'ZipEntry.*getName\s*\(\s*\)|ZipInputStream|new\s+ZipFile\s*\(',
            },
        ]
        return self._scan_pattern(checks)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_pattern(self, checks: list, extensions: tuple = None) -> list:
        """
        For each check, compiles the regex and walks source_path.
        Returns one finding dict per (check, file, line) match.
        De-duplicates by (id, file, line).
        """
        if extensions is None:
            extensions = self.SCAN_EXTENSIONS

        compiled_checks = []
        for chk in checks:
            try:
                compiled_checks.append((chk, re.compile(chk["pattern"], re.IGNORECASE)))
            except re.error as e:
                util.mod_log(f"[-] Bad pattern for {chk['id']}: {e}", util.WARNING)

        findings = []
        seen = set()

        for root, _, files in os.walk(self.source_path):
            for fname in files:
                if not fname.endswith(extensions):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, 1):
                            for chk, compiled in compiled_checks:
                                if compiled.search(line):
                                    key = (chk["id"], fpath, line_no)
                                    if key in seen:
                                        continue
                                    seen.add(key)
                                    rel_path = os.path.relpath(fpath, self.source_path)
                                    findings.append({
                                        "id":          chk["id"],
                                        "title":       chk["title"],
                                        "severity":    chk["severity"],
                                        "owasp":       chk["owasp"],
                                        "description": chk["description"],
                                        "file":        rel_path,
                                        "line":        line_no,
                                        "evidence":    line.strip()[:200],
                                    })
                except Exception:
                    continue

        return findings
