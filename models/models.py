from dataclasses import dataclass
from datetime import datetime, timedelta
import sys
from typing import Any, List, Optional
import snyk
import logging
from jira import JIRA
import time

import utils.utils as utils


@dataclass
class IssueData:
    id: str
    title: str
    severity: str
    url: str
    exploitMaturity: str
    description: Optional[str] = None
    identifiers: Optional[Any] = None
    credit: Optional[List[str]] = None
    semver: Optional[Any] = None
    publicationTime: Optional[str] = None
    disclosureTime: Optional[str] = None
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = None
    cvssDetails: Optional[List[Any]] = None
    language: Optional[str] = None
    patches: Optional[Any] = None
    nearestFixedInVersion: Optional[str] = None
    ignoreReasons: Optional[List[Any]] = None


@dataclass
class FixInfo:
    isUpgradable: bool
    isPinnable: bool
    isPatchable: bool
    isFixable: bool
    isPartiallyFixable: bool
    nearestFixedInVersion: str
    fixedIn: Optional[List[str]] = None


@dataclass
class AggregatedIssue:
    id: str
    issueType: str
    pkgName: str
    pkgVersions: List[str]
    issueData: IssueData
    isPatched: bool
    isIgnored: bool
    fixInfo: FixInfo
    introducedThrough: Optional[List[Any]] = None
    ignoreReasons: Optional[List[Any]] = None
    priorityScore: Optional[int] = None
    priority: Optional[Any] = None


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
        number_of_days = 0
        if self.get_severity() == "critical":
            number_of_days = 30
        elif self.get_severity() == "high":
            number_of_days = 60
        elif self.get_severity() == "medium":
            number_of_days = 90
        return (datetime.today() + timedelta(days=number_of_days)).strftime("%Y-%m-%d")


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
            labels = utils.create_labels(vulnerability)
            jira_issues_to_create.append(
                {
                    "project": jira_project_id,
                    "summary": vulnerability.get_jira_summary(),
                    "description": vulnerability.get_jira_description(
                        snyk_org_slug, snyk_project_id
                    ),
                    "issuetype": {"name": "Bug"},
                    "components": [{"name": vulnerability.get_component()}],
                    "duedate": vulnerability.calculate_due_date(),
                    "security": {"id": "11697"},
                    "labels": labels,
                    "priority": {"name": "Critical"},
                }
            )
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
            for jira in jira_issues_to_create:
                print(jira[0]["summary"])

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
        issues = []
        for query in jira_query_list or []:
            issue = self.__client.search_issues(
                jql_str=query,
                startAt=start_at,
                maxResults=max_results,
                json_result=True,
            )
            issues.append(issue["issues"])
            time.sleep(10)
        return [item for issue in issues for item in issue], False
