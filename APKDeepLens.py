import os
import subprocess
import traceback
import sys
import logging
import argparse
import time 
import xml.etree.ElementTree as ET
from static_tools import sensitive_info_extractor, scan_android_manifest
from report_gen import ReportGen

"""
    Title:      APKDeepLens
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Version:    1.0.0
    GitHub URL: https://github.com/d78ui98/APKDeepLens
"""

logging.basicConfig(level=logging.ERROR, format="%(message)s")

class util:
    '''
    A static class for which contain some useful variables and methods
    '''
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def mod_print(text_output, color):
        """
        Better mod print. It gives the line number, file name in which error occured. 
        """
        stack = traceback.extract_stack()
        filename, line_no, func_name, text = stack[-2]
        formatted_message = f"{filename}:{line_no}: {text_output}"
        print(color + formatted_message + util.ENDC)

    def mod_log(text, color):
        logging.info(color + "{}".format(text) + util.ENDC)
    
    def print_logo():
        """
        Logo for APKDeepLens
        """
        logo =f"""                 
{util.OKGREEN} ████  █████  ██  ██    ( )                  (_ )                           {util.ENDC}
{util.OKGREEN}██  ██ ██  ██ ██ ██    _| |  __     __  _ _   | |     __    ___    ___      {util.ENDC}
{util.OKGREEN}██████ █████  ████   /'_` | /'_`\ /'_`\( '_`\ | |    /'_`\/' _ `\/',__)     {util.ENDC}
{util.OKGREEN}██  ██ ██     ██ ██ ( (_| |(  __/(  __/| (_) )| |__ (  __/| ( ) |\__, \     {util.ENDC}
{util.OKGREEN}██  ██ ██     ██  ██`\__,_)`\___)`\___)| ,__/'(____/`\___)(_) (_)(____/     {util.ENDC}
{util.OKGREEN}                                       | |                                  {util.ENDC}
{util.OKGREEN}                                       (_)                                  {util.ENDC}
{util.OKCYAN}                                              - Made By Deepanshu{util.ENDC}
        """
        print(logo)            
                                                                                                    
def parse_args():
    """
    Parse command-line arguments.
    """
    util.print_logo()

    parser = argparse.ArgumentParser(
        description="{BOLD}{GREEN}APKDeepLens:{ENDC} Android security insights in full spectrum. ".format(BOLD=util.BOLD, GREEN=util.OKCYAN, ENDC=util.ENDC),
        epilog="For more information, visit our GitHub repository - https://github.com/d78ui98/APKDeepLens",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-apk", metavar="APK", type=str, required=True,
                    help="Path to the APK file to be analyzed.")
    parser.add_argument("-v", "--version", action="version", version="APKDeepLens v1.0",
                        help="Display the version of APKDeepLens.")
    parser.add_argument("-source_code_path", metavar="APK", type=str,
                    help="Enter a valid path of extracted source for apk.")
    parser.add_argument("-l", "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set the logging level. Default is INFO.")
    parser.add_argument("-report", action="store_true", help="Generates a report if this argument is provided.")


    return parser.parse_args()


class AutoApkScanner(object):

    def __init__(self):
        pass

    def create_dir_to_extract(self, apk_file, extracted_path=None):
        '''
        Creating a folder to extract apk source code
        '''
        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_file)

        resources_path = os.path.join(extracted_source_path, "resources")
        sources_path = os.path.join(extracted_source_path, "sources")

        if os.path.exists(extracted_source_path) and os.path.isdir(extracted_source_path) and \
           os.path.exists(resources_path) and os.path.isdir(resources_path) and \
           os.path.exists(sources_path) and os.path.isdir(sources_path):
            util.mod_log("[+] Source code for apk - {} Already extracted. Skipping this step.".format(apk_file), util.OKCYAN)
            return {'result':0,"path":extracted_source_path}
        else:
            os.makedirs(extracted_source_path, exist_ok=True)
            util.mod_log("[+] Creating new directory for extracting apk : " + extracted_source_path, util.OKCYAN)
            return {'result':1,"path":extracted_source_path}
    
    def extract_source_code(self, apk_file, target_dir):
        '''
        Extracting source code with Jdax
        '''
        util.mod_log("[+] Extracting the source code to : "+target_dir, util.OKCYAN)
        
        is_windows = os.name == 'nt'
        jadx_executable = "jadx.bat" if is_windows else "jadx"
        jadx_path = os.path.join(os.getcwd(), "static_tools", "jadx", "bin", jadx_executable)
        output = subprocess.run([jadx_path, apk_file, "-d", target_dir])
        print(output)

    def return_abs_path(self, path):
        '''
        Returns the absolute path
        '''
        return os.path.abspath(path)
    
    def apk_exists(self, apk_filename):
        '''
        Check if the apk file exists or not.
        '''
        return os.path.isfile(apk_filename)

if __name__ == "__main__":
    try:
        args = parse_args()

        # Check if virtual environment is activated.
        try:
            os.environ['VIRTUAL_ENV']
        except KeyError:
            util.mod_log("[-] ERROR: Not inside virtualenv. Do source venv/bin/activate", util.FAIL)
            exit(0)

        if not args.apk:
            util.mod_log("[-] ERROR: Please provide the apk file using the -apk flag.", util.FAIL)
            exit(0)

        apk = args.apk

        def is_path_or_filename(apk):
            """
            Added function to better handle apk names and apk paths
            """
            global apk_name, apk_path

            if os.sep in apk:
                apk_name = os.path.basename(apk)  # Extracts the filename from the path
                apk_path = apk
                return "file path"
            else:
                apk_name = apk
                apk_path = apk
                return "It's just the filename"
        
        # Calling function to handle apk names and path.
        is_path_or_filename(apk)

        # Results dict store all the response in json.
        results_dict = {
            "apk_name": apk_name,
            "package_name":"",
            "permission": "",
            "dangerous_permission":"",
            "manifest_analysis":"",
            "hardcoded_secrets":"",
        }

        # Creating object for autoapkscanner class
        obj_self = AutoApkScanner()
        apk_file_abs_path = obj_self.return_abs_path(apk_path)
        if not obj_self.apk_exists(apk_file_abs_path):
            util.mod_log(f"[-] ERROR: {apk_file_abs_path} not found.", util.FAIL)
            exit(0)
        else:
            util.mod_log(f"[+] {apk_file_abs_path} found!", util.OKGREEN)
        time.sleep(1)
        
        # Extracting source code
        target_dir = obj_self.create_dir_to_extract(apk_name, extracted_path=args.source_code_path if args.source_code_path else None)
        if target_dir["result"] == 1:
            obj_self.extract_source_code(apk_file_abs_path, target_dir["path"])

        # Extracting abs path of extracted source code dir
        extracted_apk_path = obj_self.return_abs_path(target_dir["path"])

        # Extraction useful infomration from android menifest file
        #obj_self.extract_manifest_info(apk_name)
        extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_name)
        manifest_results = scan_android_manifest.ScanAndroidManifest().extract_manifest_info(extracted_source_path)

        results_dict["package_name"] = manifest_results["package_name"]
        results_dict["permission"] = manifest_results["permissions"]
        results_dict["dangerous_permission"] = manifest_results["dangerous_permission"] 
        results_dict["manifest_analysis"] = {
            "activities": {
                "all": manifest_results["activities"],
                "exported": manifest_results["exported_activity"]
            },
            "services": {
                "all": manifest_results["services"],
                "exported": manifest_results["exported_service"]
            },
            "receivers": {
                "all": manifest_results["receivers"],
                "exported": manifest_results["exported_receiver"]
            },
            "providers": {
                "all": manifest_results["providers"],
                "exported": manifest_results["exported_provider"]
            }
        }
        
        # Extracting hardcoded secrets
        obj = sensitive_info_extractor.SensitiveInfoExtractor()
        util.mod_log("[+] Reading all file paths ", util.OKCYAN)
        file_paths = obj.get_all_file_paths(extracted_apk_path)
        relative_to = extracted_apk_path
        util.mod_log("[+] Extracting all hardcoded secrets ", util.OKCYAN)
        obj.extract_all_sensitive_info(file_paths, relative_to)
    
        # extracting insecure connections
        util.mod_log("[+] Extracting all insecure connections ", util.OKCYAN)
        all_file_path = obj.get_all_file_paths(extracted_apk_path)
        result = obj.extract_insecure_request_protocol(all_file_path)
        print(result)

        ############## REPORT GENERATION #############
        if args.report:
            
            # Extracting all the required paths
            extracted_source_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_source", apk_name)
            res_path = os.path.join(extracted_source_path, "resources")
            source_path = os.path.join(extracted_source_path, "sources")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            template_path = os.path.join(script_dir, "report_template.html")

            # Reading the android manifest file.
            android_manifest_path = os.path.join(res_path, "AndroidManifest.xml")
            etparse = ET.parse(android_manifest_path)
            manifest = etparse.getroot()
            # Update the attributes by stripping out the namespace
            for elem in manifest.iter():
                elem.attrib = {k.replace('{http://schemas.android.com/apk/res/android}', 'android:'): v for k, v in elem.attrib.items()}

            # Creating object for report generation module.
            obj = ReportGen(apk_name, manifest, res_path, source_path, template_path)
            obj.generate_html_pdf_report()
        
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        line_number = exc_traceback.tb_lineno
        util.mod_print(f"[-] {str(e)} at line {line_number}", util.FAIL)
        exit(0)
