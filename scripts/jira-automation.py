import json
import logging
import os
import re
import snyk
import sys
import requests

from jira import JIRA
from dataclasses import dataclass
from datetime import datetime, timedelta
from models import AggregatedIssue, IssueData, FixInfo

VULNERABILITY_SEVERITIES = ["critical", "high", "medium"]
ALLOWED_DEPS = ["pip", "gomodules", "npm", "yarn", "poetry", "maven"]

class SnykClient:
    __client: snyk.SnykClient

    def __init__(self, snyk_api_token: str):
        try:
            self.__client = snyk.SnykClient(snyk_api_token, tries=2, delay=1, backoff=2)
        except SystemError:
            logging.error("failed to create snyk client")
            sys.exit(1)

    def get_organization(self, org_id: str) -> {}:
        """
        returns snyk org object

        :param org_id: snyk organization id
        :return: snyk organization object
        """
        return self.__client.organizations.get(org_id)

    def get_code_analysis_results(
        self, project_id: str, snyk_org_id: str, snyk_api_token: str
    ):
        results = []
        headers = {
            "authorization": f"token {snyk_api_token}",
            "accept": "application/vnd.api+json",
        }

        params = {
            "version": "2024-01-23",
            "limit": "100",
            "scan_item.id": project_id,
            "scan_item.type": "project",
            "type": "code",
            "status": "open",
            "ignored": False,
        }
        api_url = self.__client.REST_API_URL + f"/orgs/{snyk_org_id}/issues"
        while True:
            try:
                response = requests.get(api_url, params=params, headers=headers).json()
                if response and response.get("data"):
                    results += response.get("data")
                if (
                    response
                    and response.get("links")
                    and "next" in response.get("links").keys()
                ):
                    api_url = self.__client.REST_API_URL[:-5] + response.get("links").get("next")
                    params = {}
                else:
                    break
            except requests.exceptions.RequestException as e:
                raise SystemExit(e)

        return results

    def format_code_analysis_results(self, code_analysis_list, project_id):
        formatted_list = []
        for analysis_result in code_analysis_list:
            for cwe in analysis_result["attributes"]["classes"]:
                cwe_identifiers = []
                cwe_identifiers.append(cwe["id"])
            aggegrate_issue = AggregatedIssue(
                analysis_result["id"],
                analysis_result["attributes"]["type"],
                "",
                "",
                IssueData(
                    analysis_result["id"],
                    analysis_result["attributes"]["title"],
                    analysis_result["attributes"]["effective_severity_level"],
                    f"https://app.snyk.io/org/red-hat-openshift-data-science-rhods/project/{project_id}/#issue-{analysis_result['attributes']['key']}",
                    "",
                    "",
                    {"CWE": cwe_identifiers, "CVE": []},
                    "",
                    "",
                    "",
                    analysis_result["attributes"]["created_at"],
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                ),
                "",
                "",
                FixInfo(False, False, False, False, False, False, []),
                "",
                "",
                "",
                "",
            )
            formatted_list.append(aggegrate_issue)
        return formatted_list


class JiraClient:
    __client: JIRA
    __jira_label_prefix: str
    __jira_project_id: str
    __component_mapping: {}
    __dry_run: bool

    def __init__(
        self,
        jira_server: str,
        jira_api_token: str,
        jira_label_prefix: str,
        jira_project_id: str,
        component_mapping: {},
        dry_run: bool,
    ):
        try:
            self.__component_mapping = component_mapping
            self.__jira_label_prefix = jira_label_prefix
            self.__jira_project_id = jira_project_id
            self.__dry_run = dry_run
            self.__client = JIRA(
                options={"server": jira_server, "verify": True},
                token_auth=jira_api_token,
            )
        except SystemError:
            logging.error("failed to create jira client")
            sys.exit(1)

    def is_dry_run(self) -> bool:
        """
        returns if it is dry run. Jira issues will not be created if true

        :return: dry run
        """
        return self.__dry_run

    def get_project_id(self) -> str:
        """
        returns jira project id. In this project all bugs will be created

        :return: jira project id
        """
        return self.__jira_project_id

    def get_component_mapping(self) -> {}:
        """
        returns dict with mapping between github repositories and jira components

        :return: mapping between github repositories and jira components
        """
        return self.__component_mapping

    def get_jira_label_prefix(self) -> str:
        """
        returns jira label prefix. All created bugs have special label created by this script,
        so this script can identify, which bugs it should load.

        :return: jira label prefix
        """
        return self.__jira_label_prefix

    def create_labels(self, vulnerability):
        labels = [vulnerability.get_jira_snyk_id(), "snyk", "security"]
        identifiers = vulnerability.get_identifiers()
        if "CVE" in identifiers and len(identifiers["CVE"]) > 0:
            labels.append("cve")
            labels += vulnerability.get_identifiers().get("CVE")
        if "CWE" in identifiers and len(identifiers["CWE"]) > 0:
            labels.append("cwe")
            labels += vulnerability.get_identifiers().get("CWE")
        return labels

    def create_jira_issues(
        self,
        vulnerabilities_to_create: [],
        jira_project_id: str,
        snyk_project_id: str,
        snyk_org_slug: str,
    ):
        """
        creates new jira bugs from given list of vulnerabilities

        :param vulnerabilities_to_create: list of vulnerabilities to create
        :param jira_project_id: jira project id where all bugs will be created
        :param snyk_project_id: id of snyk project
        :param snyk_org_slug: name of snyk organization (e.g. red-hat-openshift-virtualisation)
        """
        jira_issues_to_create = []
        for vulnerability in vulnerabilities_to_create:
            labels = self.create_labels(vulnerability)
            jira_issue = (
                {
                    "project": jira_project_id,
                    "summary": vulnerability.get_jira_summary(),
                    "description": vulnerability.get_jira_description(
                        snyk_org_slug, snyk_project_id
                    ),
                    "components": [{"name": vulnerability.get_component()}],
                    "duedate": vulnerability.calculate_due_date(),
                    "issuetype": {"name": "Bug"},
                    "securitylevel": {"name": "Red Hat Employee"},
                    "labels": labels,
                },
            )

            jira_issues_to_create.append(jira_issue)
        if not self.is_dry_run():
            try:
                created_jira_issues = self.__client.create_issues(jira_issues_to_create)
                for issue in created_jira_issues:
                    logging.info(f"Created JIRA issue key: {issue['issue']}")
            except SystemError:
                logging.error("failed to create jira issues")
        else:
            print(
                f"dry run. No issues created. ({len(jira_issues_to_create)} issues would be created)"
            )

    def list_existing_jira_issues(
        self, jira_query_list: [str], start_at: int, max_results: int
    ) -> ([], bool):
        """
        list all jira bugs with given JQL query

        :param jira_query: JQL query, which loads already existing jira bugs
        :param start_at: position, where jira should start looking for new issues - used for pagination
        :param max_results: number of results jira should return
        :return: list of jira bugs, boolean, if there are any more results
        """
        issues = {}
        for query in jira_query_list or []:
            issues.update(
                self.__client.search_issues(
                    jql_str=query, startAt=start_at, maxResults=max_results
                )
            )
        return issues, False


@dataclass
class VulnerabilityData:
    __id: str
    __jira_snyk_id: str
    __title: str
    __url: str
    __project_branch: str
    __package_name: str
    __package_version: []
    __fixed_in: []
    __project_name: str
    __file_path: str
    __component: str
    __severity: str
    __cvss_score: float
    __identifiers: {}

    def __init__(
        self,
        snyk_id: str,
        jira_snyk_id: str,
        title: str,
        url: str,
        project_branch: str,
        package_name: str,
        package_version: [],
        fixed_in: [],
        project_name: str,
        file_name: str,
        component: str,
        cvss_score: float,
        identifiers: {},
        severity: str,
    ):
        self.__id = snyk_id
        self.__jira_snyk_id = jira_snyk_id
        self.__title = title
        self.__url = url
        self.__project_branch = project_branch
        self.__package_name = package_name
        self.__package_version = package_version
        self.__fixed_in = fixed_in
        self.__project_name = project_name
        self.__file_path = file_name
        self.__component = component
        self.__cvss_score = cvss_score
        self.__identifiers = identifiers
        self.__severity = severity

    def get_id(self):
        """
        returns snyk ID of vulnerability e.g. SNYK-UBUNTU1404-OPENSSL-2426359

        :return: snyk ID
        """
        return self.__id

    def get_jira_snyk_id(self):
        """
        returns jira ID, in format: snyk-jira-integration:<gh org>/<gh repo name>:<file path>:<branch name>:<snyk ID>
        e.g. snyk-jira-integration:kubevirt/kubevirt-tekton-tasks:modules/generate-ssh-keys/vendor/golang.org/x/net/http2/Dockerfile:main:SNYK-UBUNTU1404-OPENSSL-2426359
        The ID is so long, because snyk does not provide any unique ID for vulnerability - so e.g. 2 projects
        can have vulnerability with the same id. To be able to map vulnerabilities to snyk, we need to capture
        multiple information like GH project name, file path, branch name, snyk id ...
        possible optimalization - create hash from this long string id

        :return: jira-snyk id
        """

        return self.__jira_snyk_id

    def get_title(self) -> str:
        """
        returns jira bug title

        :return: jira bug title
        """

        return self.__title

    def get_url(self) -> str:
        """
        returns url to snyk system which describes vulnerability

        :return: url to snyk system
        """

        return self.__url

    def get_package_name(self) -> str:
        """
        returns golang package name where vulnerability is

        :return: golang package name
        """

        return self.__package_name

    def get_identifiers(self) -> {}:
        """
        returns CVE, CWE identifiers

        :return: dict identifiers
        """

        return self.__identifiers

    def get_cvss_score(self) -> float:
        """
        returns cvss score

        :return: cvss score
        """

        return self.__cvss_score

    def get_package_version(self) -> []:
        """
        returns versions which are affected by vulnerability

        :return: package version
        """

        return self.__package_version

    def get_fixed_in(self) -> []:
        """
        returns versions in which vulnerability is fixed

        :return: package version
        """

        return self.__fixed_in

    def get_project_name(self) -> str:
        """
        returns <gh org name>/<project name> name, where snyk found vulnerability

        :return: returns project name
        """

        return self.__project_name

    def get_file_path(self) -> str:
        """
        returns file path, where snyk found vulnerability

        :return: returns file path
        """

        return self.__file_path

    def get_component(self) -> str:
        """
        returns jira component

        :return: returns jira component
        """

        return self.__component

    def get_severity(self) -> str:
        """
        returns severity of vulnerability

        :return: returns severity of vulnerability
        """

        return self.__severity

    def get_project_branch(self) -> str:
        """
        returns branch name where the vulnerability was found

        :return: returns branch name
        """

        return self.__project_branch

    def get_jira_description(self, snyk_org_slug: str, snyk_project_id: str) -> str:
        """
        returns jira description of the bug

        :param snyk_project_id: id of snyk project
        :param snyk_org_slug: name of snyk organization (e.g. red-hat-openshift-virtualisation)
        :return: returns jira description of bug
        """
        cve = self.get_identifiers().get("CVE")
        cwe = self.get_identifiers().get("CWE")
        return (
            f"Found vulnerability in *{self.get_project_name()}* project, in file *{self.get_file_path()}*, "
            f"in branch *{self.get_project_branch()}*. \n\n"
            f"Severity: {self.get_severity()}. \n\n"
            f"Package name: {self.get_package_name()} \n\n"
            f"Package version: {self.get_package_version()} \n\n"
            f"Fixed in: {self.get_fixed_in()} \n\n"
            f"Vulnerability URL: {self.get_url()}. \n\n"
            f"CSSV score: {self.get_cvss_score()}. \n\n"
            f"CVE Identifier: {cve}. \n\n"
            f"CWE Identifier: {cwe}. \n\n"
            f"More info can be found in https://app.snyk.io/org/{snyk_org_slug}/project/{snyk_project_id}#issue-{self.get_id()}. \n"
        )

    def get_jira_summary(self) -> str:
        cve = self.get_identifiers().get("CVE")
        cwe = self.get_identifiers().get("CWE")
        summary = "Snyk - "
        if cve:
            summary += f"[{cve[0]}] - "
        if cwe:
            summary += f"[{cwe[0]}] - "
        return (
            summary
            + f"[{self.get_severity()}] - [{self.get_project_branch()}] - {self.get_project_name()} - "
            f"{self.get_file_path()} - {self.get_title()}"
        )

    def calculate_due_date(self) -> str:
        number_of_days = 30
        if self.get_severity() == "critical":
            number_of_days = 7
        return (datetime.today() + timedelta(days=number_of_days)).strftime("%Y-%m-%d")


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


def compare_jira_snyk(
    vulnerabilities: [], jira_issues: {}, jira_label_prefix: str
) -> []:
    jira_issue_labels = set()
    for issue in jira_issues or {}:
        if issue:
            for label in issue.fields.labels:
                if label.startswith(jira_label_prefix):
                    jira_issue_labels.add(label)
    return [v for v in vulnerabilities if v.get_jira_snyk_id() not in jira_issue_labels]


def parse_project_name(project_name: str, branch_name: str) -> str:
    return project_name.partition(":")[0].removesuffix(f"({branch_name})")


def parse_file_name(project_name: str) -> str:
    return project_name.partition(":")[2]


def exclude_file(file_name: str, excluded_files: dict) -> bool:
    for excluded_file in excluded_files:
        if re.search(excluded_file, file_name):
            return True
    return False


def process_projects(
    jira_client: JiraClient,
    snyk_client: SnykClient,
    snyk_org_id: str,
    snyk_api_token: str,
    projects: [],
    exclude_files: dict,
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
            code_analysis_list = snyk_client.get_code_analysis_results(
                project.id, snyk_org_id, snyk_api_token
            )
            processed_list = snyk_client.format_code_analysis_results(
                code_analysis_list, project.id
            )
            issues_to_process += processed_list
        if project.type in ALLOWED_DEPS:
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


def main():
    logging.basicConfig(level=logging.INFO)

    jira_component_mapping_file_path = (
        os.environ.get("COMPONENT_MAPPING_FILE_PATH")
        if os.environ.get("COMPONENT_MAPPING_FILE_PATH")
        else "../config/jira_components_mapping.json"
    )
    components_mapping = load_mapping(jira_component_mapping_file_path)

    exclude_files_file_path = (
        os.environ.get("EXCLUDE_FILES_FILE_PATH")
        if os.environ.get("EXCLUDE_FILES_FILE_PATH")
        else "../config/exclude_files.json"
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
    if dry_run:
        logging.info("DRY_RUN is enabled")

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
        snyk_client,
        snyk_org_id,
        snyk_api_token,
        projects,
        exclude_files_mapping,
    )


if __name__ == "__main__":
    main()
