from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_helper_functions import CxHelperFunctions

from utils.logger import Logger

import os
import sys
import json

def _parse_package_csec(pkg: str) -> str:
    """
    Changes csec packages to add colon if user input 'name:package' as 'name package'
    Example: 'sqlite3 3.40.1-2+deb12u1' -> sqlite3:3.40.1-2+deb12u1
    """
    pkg = pkg.strip()
    
    if ":" in pkg:
        return pkg
    
    parts = pkg.split()
    if len(parts) == 2:
        return f"{parts[0]}:{parts[1]}"
    
    return pkg

def _assemble_sast_scan_url(cx_tenant_url: str, scan_data: dict, vuln_id: str) -> str:
    """
    Assembles the SAST scan result URL.
    """
    project_id = scan_data.get('project_id')
    scan_id = scan_data.get('scan_id')
    branch = scan_data.get('branch')
    return f"https://{cx_tenant_url}/results/{scan_id}/{project_id}/sast?result-id={vuln_id}&branch={branch}"

def _assemble_csec_image_remediations(image_remediation: dict) -> dict:
    """
    Assemble CSEC image remediation details
    """
    return {
        "image_id": image_remediation.get('imageId'),
        "minor_recommended_images": image_remediation.get('minorRecommendedImages'),
        "major_recommended_images": image_remediation.get('majorRecommendedImages'),
        "alternative_recommended_images": image_remediation.get('alternativeRecommendedImages'),
        "next_recommended_images": image_remediation.get('nextRecommendedImages'),
        "not_outdated_recommended_images": image_remediation.get('notOutdatedRecommendedImages')
    }

def _assemble_sast_attack_vector_url(github_repo_url: str, params: dict) -> str:
    """
    Assemble a GitHub URL pointing to a specific line in a file.
    Example: 'https://github.com/test-devsecops/devsecops/blob/release/express-vulnerable-app/app.js#L55'
    """
    branch = params.get('branch')
    file_path = params.get('file_path')
    line_number = params.get('line_number')
    return f"{github_repo_url}/blob/{branch}{file_path}#L{line_number}"

# TODO: Change the TEST prefix to a proper variable
def main():
    log = Logger("dispensation")
    access_token_manager = AccessTokenManager(logger=log)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=log)
    helper = HelperFunctions()
    cx_helper = CxHelperFunctions()

if __name__ == "__main__":
    main()
