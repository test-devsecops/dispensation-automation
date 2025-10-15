from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_helper_functions import CxHelperFunctions
from utils.logger import Logger

import os
import sys
import json

LOG = Logger("dispensation")

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

def main():

    # ---------------- VARIABLES FOR TESTING -------------------

    SCAN_TYPE_SAST = "SAST"
    SCAN_TYPE_SCA = "SCA"
    SCAN_TYPE_CSEC = "CSEC"

    SCA_PROJECT_NAME= "test-devsecops/devsecops"
    SCA_PACKAGES = ["multer 1.4.5-lts.2", "express 5.1.0", "append-field 1.0.0"]
    SCA_END_DISPENSATION_DATE = "15 Days" #15 Days, 1 month, 2 months, 3 months, 6 months
    SCA_BRANCH = "release"

    CSEC_PROJECT_NAME= "csec-test-azure"
    CSEC_PACKAGES = ["perl-base:5.36.0-7+deb12u2", "perl:5.36.0-7+deb12u2", "libc-bin:2.36-9+deb12u10"]
    CSEC_END_DISPENSATION_DATE = "15 Days" #15 Days, 1 month, 2 months, 3 months, 6 months
    CSEC_BRANCH = "azure-pipelines-branch"

    COMMENT = "This is testing"

    # ---------------- VARIABLES FOR TESTING -------------------

    access_token_manager = AccessTokenManager(logger=LOG)
    access_token = access_token_manager.get_valid_token()
    cx_api_actions = CxApiActions(access_token=access_token, logger=LOG)
    helper = HelperFunctions()
    cx_helper = CxHelperFunctions()

    scan_type = SCAN_TYPE_CSEC

    if scan_type == SCAN_TYPE_SCA:

        LOG.info(f"Scan Type: {SCAN_TYPE_SCA}")

        cx_projects = cx_api_actions.get_projects(project_name=SCA_PROJECT_NAME)

        if not cx_projects:
            return
        
        project_id = cx_projects[0].get('id')
        packages_profile = []

        for package in SCA_PACKAGES:
            package_name, package_version = cx_helper.set_package_and_version(package)
            package_details = cx_api_actions.get_sca_vuln_details_by_package_name_version(package_name, package_version)
            package_info = helper.get_nested(package_details, ['data', 'reportingPackages'])

            if not package_info:
                LOG.skipped(f"Package {package} is not found. Skipping...")
                continue

            package_repository = package_info[0].get('packageRepository')

            package_profile = {
                "projectId": project_id,
                "packageName":package_name,
                "packageVersion": package_version,
                "packageManager":package_repository
            }

            packages_profile.append(package_profile)
            
        end_date = helper.get_future_date(SCA_END_DISPENSATION_DATE)

        if not end_date:
            return

        cx_api_actions.post_sca_update_package_state(packages_profile, "Ignore", "Snooze", end_date, COMMENT)
        recalculate = cx_api_actions.post_sca_recalculate(project_id, SCA_BRANCH)

        if recalculate and recalculate.get('status') == 'Running':
            LOG.success(f"Successfully triggered recalculation")

    if scan_type == SCAN_TYPE_CSEC:

        LOG.info(f"Scan Type: {SCAN_TYPE_CSEC}")

        cx_projects = cx_api_actions.get_projects(project_name=CSEC_PROJECT_NAME)

        if not cx_projects:
            return
        
        project_id = cx_projects[0].get('id')
        project_ids = [project_id]
        latest_scan = cx_api_actions.get_project_latest_scan_by_branch(project_ids, CSEC_BRANCH)

        if not latest_scan:
            raise ValueError(f"No latest scan found in branch {CSEC_BRANCH}")

        latest_scan_id = latest_scan[project_id].get('id')
        end_date = helper.get_future_date(CSEC_END_DISPENSATION_DATE)

        if not end_date:
            return
        
        images = cx_api_actions.get_image_id_graphql(latest_scan_id, project_id)

        if images is None:
            raise TypeError("CSEC image ID API returned None (CSEC details insufficient)")
        
        image = helper.get_nested(images, ['data', 'images', 'items'])
        if len(image) == 0:
            raise TypeError("CSEC image ID API returned no items (CSEC details insufficient)")
        
        image_id = image[0].get('imageId')
        
        for csec_package in  CSEC_PACKAGES:
            image_package_info = cx_api_actions.get_csec_package_id_graphql(latest_scan_id, project_id, image_id, csec_package)
            package = helper.get_nested(image_package_info, ['data', 'imagesVulnerabilities', 'items'])
            package_id = package[0].get('id')
            update_csec_package = cx_api_actions.post_csec_update_package(project_id, [package_id], "Snoozed", end_date, latest_scan_id, image_id=None, comment=None)

            if update_csec_package:
                LOG.success(f"Successfully snoozed {csec_package} for {CSEC_END_DISPENSATION_DATE}")

if __name__ == "__main__":
    main()
