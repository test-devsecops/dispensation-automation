from jira_utility.jira_api_actions import JiraApiActions
from checkmarx_utility.cx_api_actions import CxApiActions
from checkmarx_utility.cx_token_manager import AccessTokenManager
from utils.helper_functions import HelperFunctions
from checkmarx_utility.cx_helper_functions import CxHelperFunctions
from jira_utility.jira_helper_functions import JiraHelperFunctions
from utils.yml_file_utility import load_map
from utils.logger import Logger
import argparse

import os
import sys
import json

LOG = Logger("dispensation")

def main():

    try:
        parser = argparse.ArgumentParser(
            description="AppSec Dispensation Script"
        )
        parser.add_argument("jira_issue", help="Jira Issue Key e.g. ABC-123")
        parser.add_argument("scan_engine", help="Any of the three types of Scan e.g. SCA, CSEC, SAST (SAST currently unavailable)")
        # parser.add_argument("reference_num", nargs="?", default="", help="Reference Number for debugging purposes (optional, used by GitHub Actions)")
        args = parser.parse_args()
        jira_issue = args.jira_issue
        scan_engine = args.scan_engine

        print(f"Jira issue: {jira_issue}")

        jira_api_actions = JiraApiActions()
        access_token_manager = AccessTokenManager(logger=LOG)
        access_token = access_token_manager.get_valid_token()
        cx_api_actions = CxApiActions(access_token=access_token, logger=LOG)
        helper = HelperFunctions()
        cx_helper = CxHelperFunctions()
        jira_helper = JiraHelperFunctions()

        try:
            jira_issue_data = jira_api_actions.get_issue(jira_issue)
            jira_issue_fields = jira_issue_data.get("fields")
            jira_issue_fields = JiraHelperFunctions.remove_all_null_key_values(jira_issue_fields)
        except Exception as e:
            LOG.error(f"Failed to fetch or process Jira issue data: {e}")
            jira_api_actions.update_exception_comment_issue(jira_issue, LOG, "Failed to fetch Jira issue data")
            return 1

        field_map = load_map('config/field_mapping.yml',parent_field='fields')

        # Extracting data to be readable
        parent_data = {}
        for key, value in jira_issue_fields.items():
            for field_key, field_value in field_map.items():
                if field_value == key:
                    parent_data[field_key] = value


        # SCAN_TYPE_SAST = "SAST"
        SCAN_TYPE_SCA = "SCA"
        SCAN_TYPE_CSEC = "CSEC"

        COMMENT = parent_data.get('comment')
        # scan_type = SCAN_TYPE_CSEC
        scan_type = scan_engine

        if scan_type == SCAN_TYPE_SCA:
            SCA_PROJECT_NAME = parent_data.get('project_name')
            SCA_PACKAGES = jira_helper.parse_sca_input(parent_data.get('package_name_or_versions'))
            SCA_END_DISPENSATION_DATE = parent_data.get('dispensation_duration',{}).get('value',None)
            SCA_BRANCH = parent_data.get('branch_name')

            LOG.info(f"Scan Type: {SCAN_TYPE_SCA}")

            cx_projects = cx_api_actions.get_projects(project_name=SCA_PROJECT_NAME)

            if not cx_projects:
                raise ValueError(f"Project {SCA_PROJECT_NAME} not found")
            
            project_id = cx_projects[0].get('id')
            packages_profile = []

            for package in SCA_PACKAGES:
                package_name, package_version = cx_helper.set_package_and_version(package)
                if not package_name or not package_version:
                    raise ValueError(f"{package} is an invalid input. Please use a space between the package name and version (e.g. urllib3 1.23)")

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
                raise ValueError("End date not speicified")

            cx_api_actions.post_sca_update_package_state(packages_profile, "Ignore", "Snooze", end_date, COMMENT)
            recalculate = cx_api_actions.post_sca_recalculate(project_id, SCA_BRANCH)

            if recalculate and recalculate.get('status') == 'Running':
                LOG.success(f"Successfully triggered recalculation")


        elif scan_type == SCAN_TYPE_CSEC:

            CSEC_PROJECT_NAME= parent_data.get('project_name')
            CSEC_PACKAGES = jira_helper.parse_csec_input(parent_data.get('package_name_or_versions', None))
            CSEC_END_DISPENSATION_DATE =  parent_data.get('dispensation_duration',{}).get('value',None)
            CSEC_BRANCH = parent_data.get('branch_name')

            LOG.info(f"Scan Type: {SCAN_TYPE_CSEC}")

            cx_projects = cx_api_actions.get_projects(project_name=CSEC_PROJECT_NAME)

            if not cx_projects:
                raise ValueError(f"Project {CSEC_PROJECT_NAME} not found")
            
            project_id = cx_projects[0].get('id')
            project_ids = [project_id]
            latest_scan = cx_api_actions.get_project_latest_scan_by_branch(project_ids, CSEC_BRANCH)

            if not latest_scan:
                raise ValueError(f"No latest scan found in branch {CSEC_BRANCH}")

            latest_scan_id = latest_scan[project_id].get('id')
            end_date = helper.get_future_date(CSEC_END_DISPENSATION_DATE)

            if not end_date:
                raise ValueError("End date not specified")
            
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
                if len(package) == 0:
                    raise ValueError("Packages not found")
                package_id = package[0].get('id')
                update_csec_package = cx_api_actions.post_csec_update_package(project_id, [package_id], "Snoozed", end_date, latest_scan_id, image_id=None, comment=None)

                if update_csec_package:
                    LOG.success(f"Successfully snoozed {csec_package} for {CSEC_END_DISPENSATION_DATE}")
        else:
            raise ValueError(f"The {scan_engine} Scan type is not supported by this workflow automation.")

        jira_api_actions.update_successful_comment_issue(jira_issue,LOG)
        return 0

    except ValueError as value_error:
        jira_api_actions.update_exception_comment_issue(jira_issue, LOG, value_error)
        LOG.error(f"Value error: {value_error}")
        LOG.error("Dispensation Update failed.")
        return 1

    except Exception as e:
        jira_api_actions.update_exception_comment_issue(jira_issue, LOG, "Unexpected Error, Please check logs")
        LOG.error(f"Unexpected error: {e}")
        LOG.error(
        "Dispensation Update failed."
        "[DEBUG GUIDE] If the issue persists, check config/field_mapping.yml for incorrect mappings "
        "between JIRA and the local configuration."
        )
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
