import json
import logging
import os
import sys
import argparse

from utils.utils import *
from models.models import *

VULNERABILITY_SEVERITIES = ["critical", "high", "medium"]
ALLOWED_DEPS = ["pip", "gomodules", "npm", "yarn", "poetry", "maven"]


def compare_jira_snyk(
    vulnerabilities: [], jira_issues: [], jira_label_prefix: str
) -> []:
    jira_issue_labels = set()
    for issue in jira_issues or []:
        for label in issue["fields"]["labels"]:
            if label.startswith(jira_label_prefix):
                jira_issue_labels.add(label)
    return [v for v in vulnerabilities if v.get_jira_snyk_id() not in jira_issue_labels]


def list_snyk_vulnerabilities(
    vulnerabilities: [],
    project_branch: str,
    project_name: str,
    file_name: str,
    jira_client: JiraClient,
) -> ([], str):
    patchable_vulnerabilities = []
    jira_query = f"project={jira_client.get_project_id()} AND ("
    jira_query_list = []
    label_counter = 0
    for vulnerability in vulnerabilities:
        if vulnerability.issueData.severity in VULNERABILITY_SEVERITIES:
            # split logic if the request header it too big
            if label_counter > 20:
                label_counter = 0
                # remove last OR operand from query
                jira_query = jira_query[:-2] + ")"
                jira_query_list.append(jira_query)
                jira_query = f"project={jira_client.get_project_id()} AND ("
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
            )
            patchable_vulnerabilities.append(vulnerability_obj)

            jira_query += f' labels="{jira_snyk_id}" OR'
            label_counter += 1
    if not jira_query.endswith("AND ("):
        # remove last OR operand from query
        jira_query = jira_query[:-2] + ")"
        jira_query_list.append(jira_query)
    return patchable_vulnerabilities, jira_query_list


def process_vulnerabilities(
    jira_client: JiraClient,
    vulnerabilities_to_compare_list: [],
    jira_query_list: [str],
    project_id: str,
    snyk_org_slug: str,
):
    load_more = True
    start_at = 0
    max_results = 50
    while load_more:
        # TODO fix paging functions
        jira_issues, load_more = jira_client.list_existing_jira_issues(
            jira_query_list, start_at, max_results
        )
        vulnerabilities_to_create_list = compare_jira_snyk(
            vulnerabilities_to_compare_list,
            jira_issues,
            jira_client.get_jira_label_prefix(),
        )
        if vulnerabilities_to_create_list:
            jira_client.create_jira_issues(
                vulnerabilities_to_create_list,
                jira_client.get_project_id(),
                project_id,
                snyk_org_slug,
            )
            start_at += max_results


def process_projects(
    jira_client: JiraClient,
    snyk_org_id: str,
    snyk_api_token: str,
    projects: [],
    exclude_files: dict,
    snyk_api_result_limit,
    snyk_rest_api_version,
    disable_dep_analysis,
):
    for project in projects:
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
        if project.type in ALLOWED_DEPS and (not disable_dep_analysis):
            issues_to_process += issue_set.issues
        if issues_to_process:
            logging.info(
                f"looking for vulnerabilities in: {project_name}, file: {file_name}, branch: {project.branch}"
            )
            vulnerabilities_to_compare_list, jira_query_list = (
                list_snyk_vulnerabilities(
                    issues_to_process,
                    project.branch,
                    project_name,
                    file_name,
                    jira_client,
                )
            )
            if vulnerabilities_to_compare_list:
                process_vulnerabilities(
                    jira_client,
                    vulnerabilities_to_compare_list,
                    jira_query_list,
                    project.id,
                    project.organization.slug,
                )


def load_mapping(file_path: str) -> {}:
    try:
        dirname = os.path.dirname(__file__)
        rel_file_path = os.path.join(dirname, file_path)
        os.path.isfile(rel_file_path)
    except SystemError:
        logging.error("the file does not exists")
        sys.exit(1)

    component_maping = {}
    try:
        with open(rel_file_path) as f:
            data = f.read()
            component_maping = json.loads(data)
    except SystemError:
        logging.error("failed to load file")
        sys.exit(1)
    return component_maping


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

    dry_run = os.environ.get("DRY_RUN")
    if dry_run == "true":
        logging.info("DRY_RUN is enabled")
        dry_run = True
    else:
        dry_run = False

    snyk_client = SnykClient(snyk_api_token)
    snyk_org = snyk_client.get_organization(snyk_org_id)
    projects = snyk_org.projects.get("570fd96f-09ad-488b-bb37-f822c34c973f")
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
        [projects],
        exclude_files_mapping,
        args.limit,
        args.version,
        args.disable_dep_analysis,
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
        "--disable-dep-analysis", action="store_true", dest="disable_dep_analysis"
    )
    args = parser.parse_args()
    main(args)
