import os
import xml.etree.ElementTree as ET
import re
from static_tools.utility.utility_class import util, DANGEROUS_PERMISSIONS

class ScanAndroidManifest(object):

    def __init__(self) -> None:
        pass

    def extract_manifest_info(self, extracted_source_path):
        """
        Extracts basic information from an Android Manifest file.
        """
        manifest_path = os.path.join(extracted_source_path, "resources", "AndroidManifest.xml")
        
        if not os.path.isfile(manifest_path):
            util.mod_log(f"[-] ERROR: Manifest file {manifest_path} not found.", util.FAIL)

        etparse = ET.parse(manifest_path)
        manifest = etparse.getroot()

        if not manifest:
            util.mod_log(f"[-] ERROR: Error parsing the manifest file for {extracted_source_path}.", util.FAIL)

        android_namespace = '{http://schemas.android.com/apk/res/android}'

        components, exported_components = self.parse_android_manifest(manifest_path)

        data = {
        'platform_build_version_code': manifest.attrib.get('platformBuildVersionCode', "Not available"),
        'complied_sdk_version': manifest.attrib.get('compileSdkVersion', "Not available"),
        'permissions': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('uses-permission')],
        'dangerous_permission': "",
        'package_name': manifest.attrib.get('package', "Not available"),
        'activities': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/activity')],
        'exported_activity': exported_components['activity'],
        'services': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/service')],
        'exported_service': exported_components['service'],
        'receivers': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/receiver')],
        'exported_receiver': exported_components['receiver'],
        'providers': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/provider')],
        'exported_provider': exported_components['provider'],
        }

        indent = "    "

        dangerous_permissions = [perm for perm in data['permissions'] if perm in DANGEROUS_PERMISSIONS]

        util.mod_log(f"[+] Package Name:", util.OKCYAN)
        print(indent + data['package_name'] + "\n")

        util.mod_log(f"[+] Platform Build Version Code:", util.OKCYAN)
        print(indent + str(data['platform_build_version_code']) + "\n")

        util.mod_log(f"[+] Compile SDK Version:", util.OKCYAN)
        print(indent + str(data['complied_sdk_version']) + "\n")

        if data['permissions']:
            util.mod_log(f"[+] Permissions:", util.OKCYAN)
            for permission in data['permissions']:
                print(indent + permission)
            print()
        
        if dangerous_permissions:
            util.mod_log(f"[+] Dangerous Permissions:", util.FAIL)
            data['dangerous_permission'] = dangerous_permissions
            for permission in dangerous_permissions:
                print(indent + permission)
            print()
        
        if data['activities']:
            util.mod_log(f"[+] Activities:", util.OKCYAN)
            for activity in data['activities']:
                print(indent + activity)
            print()
        
        if data['exported_activity']:
            util.mod_log(f"[+] Exported Activities:", util.OKCYAN)
            for activity in data['exported_activity']:
                print(indent + activity)
            print()

        if data['services']:
            util.mod_log(f"[+] Services:", util.OKCYAN)
            for service in data['services']:
                print(indent + service)
            print()
        
        if data['exported_service']:
            util.mod_log(f"[+] Exported Services:", util.OKCYAN)
            for activity in data['exported_service']:
                print(indent + activity)
            print()

        if data['receivers']:
            util.mod_log(f"[+] Receivers:", util.OKCYAN)
            for receiver in data['receivers']:
                print(indent + receiver)
            print()
        
        if data['exported_receiver']:
            util.mod_log(f"[+] Exported Receivers:", util.OKCYAN)
            for activity in data['exported_receiver']:
                print(indent + activity)
            print()

        if data['providers']:
            util.mod_log(f"[+] Providers:", util.OKCYAN)
            for provider in data['providers']:
                print(indent + provider)
            print()
        
        if data['exported_provider']:
            util.mod_log(f"[+] Exported Providers:", util.OKCYAN)
            for activity in data['exported_provider']:
                print(indent + activity)
            print()

        data['manifest_security'] = self.check_manifest_security(manifest, android_namespace)

        if data['manifest_security']:
            util.mod_log(f"[+] Manifest Security Issues: {len(data['manifest_security'])} finding(s)", util.WARNING)

        return data

    def check_manifest_security(self, manifest, android_ns: str) -> list:
        """
        Inspects AndroidManifest.xml for security misconfigurations.
        Returns a list of finding dicts: {id, title, severity, owasp, description, evidence}.
        """
        ns = android_ns  # e.g. '{http://schemas.android.com/apk/res/android}'
        findings = []

        app = manifest.find('application')
        if app is None:
            return findings

        def attr(elem, name):
            return elem.get(f"{ns}{name}")

        # --- MANIFEST_DEBUGGABLE ---
        if attr(app, 'debuggable') == 'true':
            findings.append({
                "id": "MANIFEST_DEBUGGABLE",
                "title": "Application is Debuggable",
                "severity": "CRITICAL",
                "owasp": "M8: Security Misconfiguration",
                "description": (
                    "android:debuggable=\"true\" allows attackers to attach a debugger "
                    "to the running app via adb, inspect memory, bypass certificate "
                    "pinning, and extract sensitive data at runtime. Must be false in "
                    "release builds."
                ),
                "evidence": 'android:debuggable="true"',
            })

        # --- MANIFEST_ALLOW_BACKUP ---
        backup = attr(app, 'allowBackup')
        if backup is None or backup == 'true':
            findings.append({
                "id": "MANIFEST_ALLOW_BACKUP",
                "title": "Application Data Backup Allowed",
                "severity": "HIGH",
                "owasp": "M9: Insecure Data Storage",
                "description": (
                    "android:allowBackup is true (or not set, defaulting to true). "
                    "Any user or attacker with USB access can extract the full app "
                    "data directory using 'adb backup' without root. Set to false or "
                    "use android:fullBackupOnly with a proper backup rule."
                ),
                "evidence": f'android:allowBackup="{backup if backup is not None else "true (default)"}"',
            })

        # --- MANIFEST_CLEARTEXT ---
        if attr(app, 'usesCleartextTraffic') == 'true':
            findings.append({
                "id": "MANIFEST_CLEARTEXT",
                "title": "Cleartext Traffic Permitted",
                "severity": "HIGH",
                "owasp": "M5: Insecure Communication",
                "description": (
                    "android:usesCleartextTraffic=\"true\" permits the app to send "
                    "unencrypted HTTP traffic. All data in transit is visible to any "
                    "observer on the network. Use HTTPS exclusively."
                ),
                "evidence": 'android:usesCleartextTraffic="true"',
            })

        # --- MANIFEST_EXPORTED_NO_PERM ---
        for comp_type in ('activity', 'service', 'receiver', 'provider'):
            for comp in manifest.findall(f'.//{comp_type}'):
                if attr(comp, 'exported') == 'true' and not attr(comp, 'permission'):
                    name = attr(comp, 'name') or '(unknown)'
                    findings.append({
                        "id": "MANIFEST_EXPORTED_NO_PERM",
                        "title": f"Exported {comp_type.capitalize()} Without Permission",
                        "severity": "HIGH",
                        "owasp": "M4: Insufficient Input/Output Validation",
                        "description": (
                            f"The {comp_type} '{name}' is exported (accessible from other apps) "
                            "but has no android:permission protection. Any app on the device "
                            "can start, bind, or send data to it without restriction."
                        ),
                        "evidence": f'<{comp_type} android:name="{name}" android:exported="true">',
                    })

        # --- MANIFEST_GRANT_URI ---
        for provider in manifest.findall('.//provider'):
            if attr(provider, 'grantUriPermissions') == 'true':
                name = attr(provider, 'name') or '(unknown)'
                findings.append({
                    "id": "MANIFEST_GRANT_URI",
                    "title": "Provider Grants URI Permissions Broadly",
                    "severity": "HIGH",
                    "owasp": "M4: Insufficient Input/Output Validation",
                    "description": (
                        f"Provider '{name}' has android:grantUriPermissions=\"true\", allowing "
                        "any app that receives a URI-granted Intent to access all URIs of "
                        "this provider. Use <grant-uri-permission> path patterns to restrict scope."
                    ),
                    "evidence": f'<provider android:name="{name}" android:grantUriPermissions="true">',
                })

        # --- MANIFEST_TASK_HIJACK ---
        for activity in manifest.findall('.//activity'):
            task_affinity = attr(activity, 'taskAffinity')
            if task_affinity is not None and task_affinity != '':
                name = attr(activity, 'name') or '(unknown)'
                findings.append({
                    "id": "MANIFEST_TASK_HIJACK",
                    "title": "Potential Task Hijacking via taskAffinity",
                    "severity": "MEDIUM",
                    "owasp": "M4: Insufficient Input/Output Validation",
                    "description": (
                        f"Activity '{name}' sets a non-default android:taskAffinity. "
                        "Combined with launchMode=singleTask, a malicious app with the same "
                        "affinity can hijack this activity's task and intercept user data."
                    ),
                    "evidence": f'android:taskAffinity="{task_affinity}"',
                })

        # --- MANIFEST_CUSTOM_PERM_NORMAL ---
        for perm in manifest.findall('permission'):
            level = attr(perm, 'protectionLevel')
            pname = attr(perm, 'name') or '(unknown)'
            if level is None or level == 'normal' or level == '0x0':
                findings.append({
                    "id": "MANIFEST_CUSTOM_PERM_NORMAL",
                    "title": "Custom Permission with Normal Protection Level",
                    "severity": "MEDIUM",
                    "owasp": "M3: Insecure Authentication/Authorization",
                    "description": (
                        f"Custom permission '{pname}' uses protectionLevel=\"normal\" "
                        "(or is unset, defaulting to normal). Any app can request and "
                        "be automatically granted this permission without user interaction. "
                        "Use 'signature' for intra-app permissions."
                    ),
                    "evidence": f'<permission android:name="{pname}" android:protectionLevel="{level or "normal (default)"}">',
                })

        # --- MANIFEST_MIN_SDK_LOW ---
        uses_sdk = manifest.find('uses-sdk')
        if uses_sdk is not None:
            min_sdk_str = attr(uses_sdk, 'minSdkVersion')
            target_sdk_str = attr(uses_sdk, 'targetSdkVersion')
            if min_sdk_str and min_sdk_str.isdigit() and int(min_sdk_str) < 21:
                findings.append({
                    "id": "MANIFEST_MIN_SDK_LOW",
                    "title": f"Low Minimum SDK Version ({min_sdk_str})",
                    "severity": "MEDIUM",
                    "owasp": "M8: Security Misconfiguration",
                    "description": (
                        f"minSdkVersion={min_sdk_str} targets Android versions that lack "
                        "modern security controls (full-disk encryption, SELinux enforcement, "
                        "runtime permissions). Minimum recommended is 21 (Android 5.0)."
                    ),
                    "evidence": f'android:minSdkVersion="{min_sdk_str}"',
                })
            if target_sdk_str and target_sdk_str.isdigit() and int(target_sdk_str) < 28:
                findings.append({
                    "id": "MANIFEST_TARGET_SDK_LOW",
                    "title": f"Low Target SDK Version ({target_sdk_str})",
                    "severity": "MEDIUM",
                    "owasp": "M8: Security Misconfiguration",
                    "description": (
                        f"targetSdkVersion={target_sdk_str} opts out of security improvements "
                        "introduced in Android 9+ (Pie), including default HTTPS enforcement, "
                        "restricted access to device identifiers, and background restrictions. "
                        "Target SDK 28 or higher is strongly recommended."
                    ),
                    "evidence": f'android:targetSdkVersion="{target_sdk_str}"',
                })

        # --- MANIFEST_DEEP_LINK ---
        for activity in manifest.findall('.//activity'):
            for intent_filter in activity.findall('intent-filter'):
                for data_elem in intent_filter.findall('data'):
                    scheme = attr(data_elem, 'scheme')
                    if scheme and scheme not in ('http', 'https'):
                        name = attr(activity, 'name') or '(unknown)'
                        findings.append({
                            "id": "MANIFEST_DEEP_LINK",
                            "title": "Deep Link Activity Without Permission",
                            "severity": "MEDIUM",
                            "owasp": "M4: Insufficient Input/Output Validation",
                            "description": (
                                f"Activity '{name}' handles custom deep link scheme "
                                f"'{scheme}://'. Any app or web page can launch this activity "
                                "with arbitrary intent data. Validate all incoming URI "
                                "parameters before use."
                            ),
                            "evidence": f'<data android:scheme="{scheme}"> in {name}',
                        })

        return findings

    def is_exported(self, component, ns):
        return component.get(f"{{{ns['android']}}}exported") == "true"

    def parse_android_manifest(self, manifest_path):
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        
        # Parse the XML content
        etparse = ET.parse(manifest_path)
        root = etparse.getroot()

        # Dictionary to hold components and exported components
        components = {'activity': [], 'service': [], 'receiver': [], 'provider': []}
        exported_components = {'activity': [], 'service': [], 'receiver': [], 'provider': []}
        # Extract components and check if they are exported
        for component_type in components.keys():
            for component in root.findall(f".//{component_type}"):
                name = component.get(f"{{{ns['android']}}}name")
                components[component_type].append(name)
                if self.is_exported(component, ns):
                    exported_components[component_type].append(name)

        return components, exported_components
