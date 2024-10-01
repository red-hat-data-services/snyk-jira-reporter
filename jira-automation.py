import logging
import os
import sys
import argparse
import time
from utils.utils import *
from models.models import *

DEFAULT_ALLOWED_DEPS = ["pip", "gomodules", "npm", "yarn", "poetry", "maven"]
total_issue_count = 0


def list_snyk_vulnerabilities(
    vulnerabilities: List[Any],
    project_branch: str,
    project_name: str,
    file_name: str,
    jira_client: JiraClient,
    allowed_severity_list,
) -> List[VulnerabilityData]:
    filtered_vulnerabilities = []
    for vulnerability in vulnerabilities:
        if vulnerability.issueData.severity in allowed_severity_list:
            jira_snyk_id = f"{jira_client.get_jira_label_prefix()}{project_name}:{file_name}:{project_branch}:{vulnerability.id}"
            component_mapping = jira_client.get_component_mapping()
            component = (
                component_mapping[project_name]
                if project_name in component_mapping
                else ""
            )
            vulnerability_obj = VulnerabilityData(
                snyk_id=vulnerability.id,
                jira_snyk_id=jira_snyk_id,
                title=vulnerability.issueData.title,
                url=vulnerability.issueData.url,
                package_name=vulnerability.pkgName,
                package_version=vulnerability.pkgVersions,
                fixed_in=vulnerability.fixInfo.fixedIn,
                project_name=project_name,
                project_branch=project_branch,
                file_name=file_name,
                component=component,
                cvss_score=vulnerability.issueData.cvssScore,
                identifiers=vulnerability.issueData.identifiers,
                severity=vulnerability.issueData.severity,
                issue_type=vulnerability.issueType,
            )
            filtered_vulnerabilities.append(vulnerability_obj)
    return filtered_vulnerabilities


def process_vulnerabilities(
    jira_client: JiraClient,
    vulnerabilities_to_compare_list,
    jira_to_compare_list,
    project_id: str,
    snyk_org_slug: str,
):
    issues_to_cleanup, new_vulnerabilities = segregate_issues(
        vulnerabilities_to_compare_list, jira_to_compare_list
    )
    cleanup_non_existing_issues(jira_client, issues_to_cleanup)

    if len(vulnerabilities_to_compare_list) > 0:
        global total_issue_count
        total_issue_count += jira_client.create_jira_issues(
            new_vulnerabilities,
            jira_client.get_project_id(),
            project_id,
            snyk_org_slug,
        )
        # Creating a delay as jira api server throttles and misses out creating jiras
        time.sleep(10)


def segregate_issues(vulnerabilities: List[VulnerabilityData], jira_issues):
    issues_to_remove = []
    existing_issues_uid = []
    new_vulnerabilities = []
    jira_snyk_id_list = []
    for vulnerability in vulnerabilities:
        jira_snyk_id_list.append(vulnerability.get_jira_snyk_id())
    for jira in jira_issues:
        description_list = jira["fields"]["description"].replace("\r", "").split("\n")
        uid = description_list[
            description_list.index("##Do not edit this section below##") + 2
        ].replace("##snyk-jira-uid##", "")
        if uid.strip() not in jira_snyk_id_list:
            if jira["fields"]["status"]["name"] not in ["Resolved", "Closed"]:
                issues_to_remove.append(jira)
        else:
            existing_issues_uid.append(uid.strip())
    for vulnerability in vulnerabilities:
        if vulnerability.get_jira_snyk_id() not in existing_issues_uid:
            new_vulnerabilities.append(vulnerability)
    return issues_to_remove, new_vulnerabilities


def cleanup_non_existing_issues(jira_client: JiraClient, issues_to_cleanup):
    for issue in issues_to_cleanup:
        logging.info(
            "The following issues will be closed in jira as they dont exist in snyk"
        )
        logging.info(issue["key"])
        if not jira_client.is_dry_run():
            try:
                jira_client.__client.add_comment(
                    issue=issue,
                    body="Closing this issue as it is no longer reported in snyk",
                )
                jira_client.__client.transition_issue(issue, "Closed")
            except SystemError:
                logging.error("Failed to close the jira")
                sys.exit(1)


def process_projects(
    jira_client: JiraClient,
    snyk_org_id: str,
    snyk_api_token: str,
    projects: [],
    exclude_files: dict,
    snyk_api_result_limit,
    snyk_rest_api_version,
    disable_dep_analysis,
    allowed_severity_list,
):

    for project in projects:
        if project.isMonitored:
            project_name = parse_project_name(project.name, project.branch)
            file_name = parse_file_name(project.name)

            excluded_files = exclude_files.get(project_name, None)
            if excluded_files and exclude_file(file_name, excluded_files):
                logging.info(
                    f"skipping file {file_name}, because of the record in exclude_file.json"
                )
                continue
            issue_set = project.issueset_aggregated.all()
            issues_to_process = []
            if project.type == "sast":
                code_analysis_list = get_code_analysis_results(
                    project.id,
                    snyk_org_id,
                    snyk_api_token,
                    snyk_api_result_limit,
                    snyk_rest_api_version,
                )
                processed_list = format_code_analysis_results(
                    code_analysis_list, project.id
                )
                issues_to_process += processed_list
            if project.type in DEFAULT_ALLOWED_DEPS and (not disable_dep_analysis):
                issues_to_process += issue_set.issues
            if issues_to_process:
                logging.info(
                    f"looking for vulnerabilities in: {project_name}, file: {file_name}, branch: {project.branch}"
                )
                vulnerabilities_to_compare_list = list_snyk_vulnerabilities(
                    issues_to_process,
                    project.branch,
                    project_name,
                    file_name,
                    jira_client,
                    allowed_severity_list,
                )
                jiras_to_compare_list = jira_client.get_existing_jira_for_project(
                    project_name, file_name, project.branch
                )
                process_vulnerabilities(
                    jira_client,
                    vulnerabilities_to_compare_list,
                    jiras_to_compare_list,
                    project.id,
                    project.organization.slug,
                )
    logging.info(f"Total number of issues created is: {total_issue_count}")


def main(args):
    logging.basicConfig(level=logging.INFO)

    jira_component_mapping_file_path = (
        os.environ.get("COMPONENT_MAPPING_FILE_PATH")
        if os.environ.get("COMPONENT_MAPPING_FILE_PATH")
        else "./config/jira_components_mapping.json"
    )
    components_mapping = load_mapping(jira_component_mapping_file_path)

    exclude_files_file_path = (
        os.environ.get("EXCLUDE_FILES_FILE_PATH")
        if os.environ.get("EXCLUDE_FILES_FILE_PATH")
        else "./config/exclude_files.json"
    )
    exclude_files_mapping = load_mapping(exclude_files_file_path)

    snyk_org_id = os.environ.get("SNYK_ORG_ID")
    if not snyk_org_id:
        logging.error("SNYK_ORG_ID env variable not defined")
        sys.exit(2)
    snyk_api_token = os.environ.get("SNYK_API_TOKEN")
    if not snyk_api_token:
        logging.error("SNYK_API_TOKEN env variable not defined")
        sys.exit(2)
    jira_server = os.environ.get("JIRA_SERVER")
    if not jira_server:
        logging.error("JIRA_SERVER env variable not defined")
        sys.exit(2)
    jira_api_token = os.environ.get("JIRA_API_TOKEN")
    if not jira_api_token:
        logging.error("JIRA_API_TOKEN env variable not defined")
        sys.exit(2)
    jira_project_id = os.environ.get("JIRA_PROJECT_ID")
    if not jira_project_id:
        logging.error("JIRA_PROJECT_ID env variable not defined")
        sys.exit(2)

    jira_label_prefix = (
        os.environ.get("JIRA_LABEL_PREFIX")
        if os.environ.get("JIRA_LABEL_PREFIX")
        else "snyk-jira-integration:"
    )
    allowed_severity_list = [x.strip() for x in args.allowed_severity.split(",")]
    dry_run = os.environ.get("DRY_RUN")
    if dry_run == "true":
        logging.info("DRY_RUN is enabled")
        dry_run = True
    else:
        dry_run = False

    snyk_client = SnykClient(snyk_api_token)
    snyk_org = snyk_client.get_organization(snyk_org_id)
    projects = snyk_org.projects.all()
    jira_client = JiraClient(
        jira_server,
        jira_api_token,
        jira_label_prefix,
        jira_project_id,
        components_mapping,
        dry_run,
    )
    process_projects(
        jira_client,
        snyk_org_id,
        snyk_api_token,
        projects,
        exclude_files_mapping,
        args.limit,
        args.version,
        args.disable_dep_analysis,
        allowed_severity_list,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Snyk to Jira automation script")
    parser.add_argument(
        "-l",
        "--limit",
        type=str,
        help="The number of results to be returned by the snyk scan",
        nargs="?",
        default="100",
    )
    parser.add_argument(
        "-v",
        "--version",
        type=str,
        help="The rest api version of snyk",
        nargs="?",
        default="2024-01-23",
    )
    parser.add_argument(
        "-s",
        "--allowed-severity",
        type=str,
        help="A comma seperated list of severities of the vulnerabilities to record. eg: critical,high",
        nargs="?",
        default="critical,high",
    )
    parser.add_argument(
        "--disable-dep-analysis", action="store_true", dest="disable_dep_analysis"
    )
    args = parser.parse_args()
    main(args)
