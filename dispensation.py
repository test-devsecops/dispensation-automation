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

    # ---------------- VARIABLES FOR TESTING -------------------

    SCAN_TYPE_SAST = "SAST"
    SCAN_TYPE_SCA = "SCA"
    SCAN_TYPE_CSEC = "CSEC"

    SCA_PROJECT_NAME= "test-devsecops/devsecops"
    SCA_PACKAGE_NAME = ["multer 1.4.5-lts.2", "express 5.1.0"]
    SCA_END_DISPENSATION_DATE = "15 Days" #15 Days, 1 month, 2 months, 3 months, 6 months
    COMMENT = "This is testing"

    # ---------------- VARIABLES FOR TESTING -------------------

    log = Logger("dispensation")
    access_token_manager = AccessTokenManager(logger=log)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=log)
    helper = HelperFunctions()
    cx_helper = CxHelperFunctions()

    # packages profile

    scan_type = SCAN_TYPE_SCA

    if scan_type == SCAN_TYPE_SCA:

        cx_projects = cx_api_actions.get_checkmarx_projects(project_name=SCA_PROJECT_NAME)
        project_id = cx_projects[0].get('id')

        packages_profile = []

        for package in SCA_PACKAGE_NAME:
            package_name, package_version = cx_helper.set_package_and_version(package)
            package_details = cx_api_actions.get_sca_vuln_details_by_package_name_version(package_name, package_version)
            package = helper.get_nested(package_details, ['data', 'reportingPackages'])
            package_repository = package[0].get('packageRepository')

            package_profile = {
                "projectId": project_id,
                "packageName":package_name,
                "packageVersion": package_version,
                "packageManager":package_repository
            }

            packages_profile.append(package_profile)

        end_date = helper.get_future_date(SCA_END_DISPENSATION_DATE)
        update_package_response = cx_api_actions.post_sca_update_package_state(packages_profile, "Ignore", "Snooze", end_date, COMMENT)
        
        # Expecting None response
        if update_package_response is None:
            log.info(f"Succesffuly snoozed the packages {SCA_PACKAGE_NAME}")

if __name__ == "__main__":
    main()
