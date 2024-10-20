import datetime
import json
import logging
import os
import re
import subprocess

from xhtml2pdf import pisa

logging.basicConfig(level=logging.DEBUG, format="%(message)s")

"""
    Title:      APKDeepLens
    Desc:       Android security insights in full spectrum.
    Author:     Deepanshu Gajbhiye
    Version:    1.0.0
    GitHub URL: https://github.com/d78ui98/APKDeepLens
"""


class util:
    """
    A static class for which contain some useful variables and methods
    """

    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @staticmethod
    def mod_print(text_output, color):
        print(color + "{}".format(text_output) + util.ENDC)

    @staticmethod
    def mod_log(text, color):
        logging.info(color + "{}".format(text) + util.ENDC)


class ReportGen(object):

    def __init__(
        self,
        apk_name,
        manifest,
        res_path,
        source_path,
        template_path,
        out_path: str = None
    ):
        """
        Defining few important variables which are used throughout the class.
        """
        self.apk_name = apk_name
        self.manifest = manifest
        self.res_path = res_path
        self.source_path = source_path
        self.template_path = template_path
        self.out_path = out_path
        if not self.out_path:
            self.out_path = os.getcwd()

    def render_template(self, template_name, datas, escape=False):
        """
        This method is used to render the template and relevant html data.

        """
        try:
            t_templates_str = {
                "report_template.html": self.load_template(self.template_path),
                "grep_lines.html": ('<div><span class="grep_filepath">{{ filepath }}</span>:'
                                '<span class="grep_line">{{ line }}</span>:{{ content }}</div>'),
            }
            render = t_templates_str.get(template_name, "")
            if not render:
                util.mod_log(
                    f"[-] ERROR: Template {template_name} not found.", util.FAIL
                )
                return ""

            for k, v in datas.items():
                if isinstance(v, list):
                    v = self.list_to_html(v)
                render = re.sub(
                    "{{\\s*" + re.escape(k) + "\\s*}}", v.replace("\\", "\\\\"), render
                )
            return render

        except Exception as e:
            util.mod_log(f"[-] ERROR in render_template: {str(e)}", util.FAIL)
            return ""

    def list_to_html(self, list_items):
        """
        This method is used to covert list to unordered list in html
        """
        try:
            if not isinstance(list_items, list):
                util.mod_log("[-] ERROR: The provided input is not a list.", util.FAIL)
                return ""
            items = [f"<li>{perm}</li>" for perm in list_items]
            return "<ul>" + "\n".join(items) + "</ul>"

        except Exception as e:
            util.mod_log(f"[-] ERROR in list_to_html: {str(e)}", util.FAIL)
            return ""

    def grenerate_html_report(self, report, html_report_path):
        """
        This method is used to generate a final html report which can be later converted to pdf
        """
        try:
            with open(html_report_path, "w") as fp:
                fp.write(report)
            print("report generated")

        except Exception as e:
            util.mod_log(f"[-] ERROR in generate_html_report: {str(e)}", util.FAIL)

    def load_template(self, template_path):
        """
        read of the template.
        """
        try:
            with open(self.template_path) as f:
                return f.read()
        except Exception as e:
            util.mod_log(f"[-] ERROR in load_template: {str(e)}", util.FAIL)
            return ""

    def grep_keyword(self, keyword, txt_ouput: bool = False):
        """
        This function is used to read keyword dict and run the grep commands on the extracted android source code.
        """
        output = ""

        """
        This dictionary stores the keywords to search with the grep command.
        Grep is much much faster than re.
        ToDo -
        - Add more search keywords
        - move entire project to use grep.
        """
        keyword_search_dict = {
            "external_call": [
                r"([^a-zA-Z0-9](OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|"
                r"MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|"
                r"MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|"
                r"SEARCH|ARBITRARY)[^a-zA-Z0-9])",

                r"(@(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|"
                r"MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|"
                r"UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|"
                r"ARBITRARY)\()"
            ],
            "intent": [
                r"(new Intent|new android\.content\.Intent|PendingIntent|sendBroadcast|"
                r"sendOrderedBroadcast|startActivity|resolveActivity|createChooser|startService|"
                r"bindService|registerReceiver)"
            ],
            "internal_storage": [
                r"(createTempFile|SQLiteDatabase|openOrCreateDatabase|execSQL|rawQuery)"
            ],
            "external_storage": [r"(EXTERNAL_STORAGE|EXTERNAL_CONTENT|getExternal)"],
        }
        if not keyword in keyword_search_dict:
            return ""

        for regexp in keyword_search_dict[keyword]:
            cmd = (
                'cd "'
                + self.res_path
                + '" ; grep -ErIn "'
                + regexp
                + '" "'
                + self.source_path
                + '" 2>/dev/null'
            )
            # Eren yeager
            try:
                o = subprocess.check_output(cmd, shell=True).decode("utf-8")
            except Exception as e:
                print(str(e))
                continue

            o.strip()
            if not txt_ouput:
                output += self.add_html_tag(o, regexp)
            else:
                output += self.add_sundarta_for_grep(o, regexp)

        return output

    def add_sundarta_for_grep(self, grep_result, regexp):
        "For prettifing grep output, outputs for txt file."
        try:
            output = ""
            for grep in grep_result.split("\n"):
                tmp = grep.split(":")
                if (
                    len(tmp) < 3
                ):  # Ensure there are enough components in the split result
                    continue
                filepath, line, content = tmp[0], tmp[1], ":".join(tmp[2:])
                filepath = (
                    "source" + filepath[len(self.source_path) :]
                )  # Dont include full path
                content = content.strip()
                _match = re.search(regexp, content)
                start_pos = _match.start()
                end_pos = _match.end()
                content_f = content + "\n"
                content_f += " " * (
                    start_pos + len(filepath) + len(line) + 2
                )  # +2 for two ":"
                content_f += "^" * (end_pos - start_pos)
                content_f += "\n"
                output += f"{filepath}:{line}:{content_f}"
            return output

        except Exception as e:
            util.mod_log(f"[-] ERROR in add_sundarta_for_grep: {str(e)}", util.FAIL)
            return ""

    def add_html_tag(self, grep_result, regexp):
        """
        This method is used add the html tags to grep output to color the output for better presentation
        """
        try:
            output = ""
            for grep in grep_result.split("\n"):
                tmp = grep.split(":")
                if (
                    len(tmp) < 3
                ):  # Ensure there are enough components in the split result
                    continue
                filepath, line, content = tmp[0], tmp[1], ":".join(tmp[2:])
                content = re.sub(regexp, "ABRACADABRA1\\1ABRACADABRA2", content)
                output += self.render_template(
                    "grep_lines.html",
                    {"filepath": filepath, "line": line, "content": content},
                    True,
                )
                output = output.replace(
                    "ABRACADABRA1", '<span class="grep_keyword">'
                ).replace("ABRACADABRA2", "</span>")
            return output

        except Exception as e:
            util.mod_log(f"[-] ERROR in add_html_tag: {str(e)}", util.FAIL)
            return ""

    def get_build_information(self):
        """
        This method is used to get build information from android manifest.xml.
        """
        try:
            version = self.manifest.attrib.get(
                "platformBuildVersionCode",
                self.manifest.attrib.get("compileSdkVersion", "?"),
            )
            return version

        except Exception as e:
            util.mod_log(f"[-] ERROR in get_build_information: {str(e)}", util.FAIL)
            return "?"

    def extract_permissions(self, manifest):
        """
        This method is used to extract permissions from the android manifest.xml.
        """
        try:
            permissions = []
            for permission_elem in self.manifest.findall(".//uses-permission"):
                permission_name = permission_elem.attrib.get("android:name")
                if permission_name:
                    permissions.append(permission_name)
            return permissions

        except Exception as e:
            util.mod_log(f"[-] ERROR in extract_permissions: {str(e)}", util.FAIL)
            return []

    def extract_dangerous_permissions(self, manifest):
        """
        This method is used to extracts dangerous permissions from the android  manifest.xml.
        """
        permissions = []
        try:
            for permission_elem in self.manifest.findall(".//uses-permission"):
                permission_name = permission_elem.attrib.get("android:name")
                dangerous_permission_list = [
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
                if permission_name:
                    if permission_name in dangerous_permission_list:
                        permissions.append(permission_name)
            return permissions
        except Exception as e:
            util.mod_log(
                f"[-] ERROR in extract_dangerous_permissions: {str(e)}", util.FAIL
            )
            return []

    def convert_html_to_pdf(self, html_file, pdf_name):
        """
        Convert an HTML file to a PDF.
        """
        # read content from html report
        with open(html_file, "r") as f:
            source_html = f.read()

        # write content from html report to pdf
        with open(pdf_name, "w+b") as result_file:
            pisa.CreatePDF(source_html, dest=result_file)

    def clean_apk_name(self, apk_name):
        """
        This function removes 'com' and 'apk' parts from the apk_name if they exist.
        """
        cleaned_name = re.sub(r"(\.com|\.apk)", "", apk_name)
        return cleaned_name

    def generate_json_report(self, json_response):
        """
        This function generates the json report based on the json output
        """
        clean_apk_name = self.clean_apk_name(self.apk_name)
        reports_dir = os.path.join(self.out_path, 'reports')
        json_report_path = os.path.join(reports_dir, f"report_{clean_apk_name}.json")
        if not os.path.exists(reports_dir):
            os.makedirs(
                os.path.dirname(json_report_path), exist_ok=True
            )
        with open(json_report_path, "w") as json_file:
            json.dump(json_response, json_file, indent=4)
        util.mod_print(
            f"[+] Generated JSON report - {json_report_path}", util.OKCYAN
        )

    def create_obj_for_report(
        self, txt_output: bool = False
    ):
        manifest = self.manifest
        res_path = self.res_path
        source_path = self.source_path
        template_path = self.template_path
        apk_name = self.apk_name

        obj = ReportGen(apk_name, manifest, res_path, source_path, template_path)
        permissions = obj.extract_permissions(manifest)
        dangerous_permission = obj.extract_dangerous_permissions(manifest)

        html_dict = {}
        html_dict["build"] = obj.get_build_information()
        html_dict["package_name"] = manifest.attrib["package"]
        html_dict["android_version"] = manifest.attrib["android:versionCode"]
        html_dict["date"] = datetime.datetime.today().strftime("%d/%m/%Y")
        html_dict["permissions"] = permissions
        html_dict["dangerous_permission"] = dangerous_permission
        html_dict["intent_grep"] = obj.grep_keyword("intent", txt_output)
        html_dict["internal_storage_grep"] = obj.grep_keyword(
            "internal_storage", txt_output
        )
        html_dict["external_storage_grep"] = obj.grep_keyword(
            "external_storage", txt_output
        )
        # print(html_dict)
        return obj, html_dict

    def generate_txt_report(self, result_dict: dict):
        try:
            result = "Basic Info -\n"
            obj, html_dict = self.create_obj_for_report(True)
            for text, value in zip(
                ["Report date", "Package name", "Build", "Android version"],
                [
                    html_dict["date"],
                    html_dict["package_name"],
                    html_dict["build"],
                    html_dict["android_version"],
                ],
            ):
                result += f"{text}: {value}\n"
            result += "\nPermissions:\n"
            if len(html_dict["permissions"]) < 1:
                result += "No permission(s) found.\n"
            for perm in html_dict["permissions"]:
                result += f"- {perm}\n"
            result += "\nPotentially dangerous permissions:\n"
            if len(html_dict["dangerous_permission"]) < 1:
                result += "No permission(s) found.\n"
            for perm in html_dict["dangerous_permission"]:
                result += f"- {perm}\n"

            def _manif_analysis_parser(index: str) -> str:
                _res = f"\n{index.capitalize()}:\n"
                if len(result_dict["manifest_analysis"][index]["all"]) < 1:
                    _res += f"No {index} found.\n"
                for val in result_dict["manifest_analysis"][index]["all"]:
                    if val in result_dict["manifest_analysis"][index]["exported"]:
                        _res += f"- {val} [exported]\n"
                    else:
                        _res += f"- {val}\n"
                return _res

            result += "".join(
                [
                    _manif_analysis_parser(index)
                    for index in ["activities", "services", "receivers", "providers"]
                ]
            )

            result += "\nInsecure connections:\n"
            if len(result_dict["insecure_requests"]) < 1:
                result += "No insecure connections found.\n"
            for conn in result_dict["insecure_requests"]:
                result += f"- {conn}\n"

            result += "\nIntents:\n"
            result += html_dict["intent_grep"]
            result += "\nInternal storage:\n"
            result += html_dict["internal_storage_grep"]
            result += "\nExternal storage:\n"
            result += html_dict["external_storage_grep"]

            # Saving the report
            cleaned_apk_name = obj.clean_apk_name(self.apk_name)

            if not os.path.isfile(self.out_path):
                txt_report_path = os.path.join(self.out_path, f"report_{cleaned_apk_name}.txt")
            else:
                txt_report_path = self.out_path
            if not os.path.exists(txt_report_path):
                os.makedirs(
                    os.path.dirname(txt_report_path), exist_ok=True
                )
            with open(txt_report_path, "w", encoding="utf-8") as f:
                f.write(result)
            util.mod_print(f"[+] Generated TXT report - {txt_report_path}", util.OKCYAN)
        except Exception as e:
            util.mod_print(f"[-] {str(e)}", util.FAIL)

    def generate_html_pdf_report(self, report_type):
        """
        This the function generates an html and pdf report using functions mentioned in report_gen.py
        """

        try:
            # Creating object for report generation module.
            obj, html_dict = self.create_obj_for_report()

            # Ensure reports directory exists
            cleaned_apk_name = obj.clean_apk_name(self.apk_name)
            if not os.path.isfile(self.out_path):
                html_report_path = os.path.join(self.out_path, f"report_{cleaned_apk_name}.html")
            else:
                html_report_path = self.out_path
            if not os.path.exists(html_report_path):
                os.makedirs(
                    os.path.dirname(html_report_path), exist_ok=True
                )

            # Generating the html report
            report_content = obj.render_template("report_template.html", html_dict)
            
            obj.grenerate_html_report(report_content, html_report_path)
            if report_type == "html":
                util.mod_print(f"[+] Generated HTML report - {html_report_path}", util.OKCYAN)

            # Converting html report to pdf.
            if report_type == "pdf":
                pdf_name = f"report_{cleaned_apk_name}.pdf"
                pdf_path = os.path.join(os.path.dirname(html_report_path), pdf_name)
                obj.convert_html_to_pdf(html_report_path, pdf_path)
                util.mod_print(f"[+] Generated PDF report - {pdf_path}", util.OKCYAN)

        except Exception as e:
            util.mod_print(f"[-] {str(e)}", util.FAIL)
