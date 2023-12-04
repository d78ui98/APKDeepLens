import os
import xml.etree.ElementTree as ET
import re
from static_tools.utility.utility_class import util


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

        data = {
        'platformBuildVersionCode': manifest.attrib.get('platformBuildVersionCode', "Not available"),
        'compileSdkVersion': manifest.attrib.get('compileSdkVersion', "Not available"),
        'permissions': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('uses-permission')],
        'activities': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/activity')],
        'services': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/service')],
        'receivers': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/receiver')],
        'providers': [elem.attrib[f'{android_namespace}name'] for elem in manifest.findall('application/provider')],
        'package_name': manifest.attrib.get('package', "Not available")
    }

        indent = "    "

        DANGEROUS_TYPES = [
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
            "android.permission.READ_HISTORY_BOOKMARKS",
            "android.permission.WRITE_HISTORY_BOOKMARKS",
            "android.permission.INSTALL_PACKAGES",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_LOGS",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.DISABLE_KEYGUARD",
            "android.permission.GET_TASKS",
            "android.permission.BLUETOOTH",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
        ]
        dangerous_permissions = [perm for perm in data['permissions'] if perm in DANGEROUS_TYPES]

        util.mod_log(f"[+] Package Name:", util.OKCYAN)
        print(indent + data['package_name'] + "\n")

        util.mod_log(f"[+] Platform Build Version Code:", util.OKCYAN)
        print(indent + str(data['platformBuildVersionCode']) + "\n")

        util.mod_log(f"[+] Compile SDK Version:", util.OKCYAN)
        print(indent + str(data['compileSdkVersion']) + "\n")

        if data['permissions']:
            util.mod_log(f"[+] Permissions:", util.OKCYAN)
            for permission in data['permissions']:
                print(indent + permission)
            print()
        
        if dangerous_permissions:
            util.mod_log(f"[+] Dangerous Permissions:", util.FAIL)
            for permission in dangerous_permissions:
                print(indent + permission)
            print()

        if data['activities']:
            util.mod_log(f"[+] Activities:", util.OKCYAN)
            for activity in data['activities']:
                print(indent + activity)
            print()

        if data['services']:
            util.mod_log(f"[+] Services:", util.OKCYAN)
            for service in data['services']:
                print(indent + service)
            print()

        if data['receivers']:
            util.mod_log(f"[+] Receivers:", util.OKCYAN)
            for receiver in data['receivers']:
                print(indent + receiver)
            print()

        if data['providers']:
            util.mod_log(f"[+] Providers:", util.OKCYAN)
            for provider in data['providers']:
                print(indent + provider)
            print()

        return data