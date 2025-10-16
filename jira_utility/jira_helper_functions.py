import string
import re

class JiraHelperFunctions:
    
    @staticmethod
    def is_readable(text):
        # Check if all characters in a string are readable (printable)
        if all(char in string.printable for char in text):
            return True
        return False

    @staticmethod
    def remove_all_null_key_values(data: dict):
        try:
            cleaned_data = {k: v for k, v in data.items() if v is not None}
            return cleaned_data
        except Exception as e:
            print(f"Error in removing key values: {e}")
            return None
    
    @staticmethod
    def parse_sast_input(data: dict):
        try:
            vulnerabilities = [v for k, v in data.items() if k.startswith("vulnerability_id_")] 
            formatted_data = {
                "scan_id" : data.get("scan_id"),
                "vuln_ids" : vulnerabilities,  
                "scan_type" : data.get("scan_engine"),
                "jira_issue" : data.get("jira_issue")
            }

            return formatted_data
        except Exception as e:
            print(f"Error in parsing SAST: {e}")
            return None

    @staticmethod
    def parse_sca_input(data: str):
        try:
            input_packages = data.split(';')
            packages = []

            for pkg in input_packages:
                pkg = pkg.strip()
                if pkg:  # make sure it's not empty
                    packages.append(pkg)
            return packages

        except Exception as e:
            print(f"Error in parsing SCA: {e}")
            return None

    @staticmethod
    def parse_csec_input(data: dict):
        try:
            input_packages = data.split(';')
            packages = []

            for pkg in input_packages:
                pkg = pkg.strip()
                if pkg:  # make sure it's not empty
                    packages.append(pkg)

            packages = [s.replace(" ", ":") for s in packages]

            return packages 

        except Exception as e:
            print(f"Error in parsing CSEC: {e}")
            return None

    @staticmethod
    def parse_dast_input(data: dict):
        try:

            urls = [v for k, v in data.items() if k.startswith("url")] 
            formatted_data = {
                "scan_id" : data.get("scan_id"),
                "urls" : urls
            }
            return formatted_data
        except Exception as e:
            print(f"Error in parsing DAST: {e}")
            return None
