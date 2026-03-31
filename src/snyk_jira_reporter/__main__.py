"""Entry point for snyk-jira-reporter CLI."""

import argparse
import logging
import sys

from pydantic import ValidationError

from snyk_jira_reporter.clients.jira_client import JiraClient
from snyk_jira_reporter.clients.snyk_client import SnykClient
from snyk_jira_reporter.config.constants import (
    DEFAULT_SNYK_REST_API_VERSION,
    DEFAULT_SNYK_RESULT_LIMIT,
    SEVERITY_PRIORITY_MAP,
)
from snyk_jira_reporter.config.settings import AppSettings
from snyk_jira_reporter.exceptions.exceptions import SnykJiraReporterError
from snyk_jira_reporter.services.vulnerability_service import process_projects
from snyk_jira_reporter.utils.file_loader import load_component_mapping, load_mapping


def main() -> None:
    """Main entry point for the Snyk to Jira automation script."""
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description="Snyk to Jira automation script")
    parser.add_argument(
        "-l",
        "--limit",
        type=str,
        help="The number of results to be returned by the snyk scan",
        nargs="?",
        default=DEFAULT_SNYK_RESULT_LIMIT,
    )
    parser.add_argument(
        "-v",
        "--version",
        type=str,
        help="The rest api version of snyk",
        nargs="?",
        default=DEFAULT_SNYK_REST_API_VERSION,
    )
    parser.add_argument(
        "-s",
        "--allowed-severity",
        type=str,
        help="A comma separated list of severities of the vulnerabilities to record. eg: critical,high",
        nargs="?",
        default="critical,high",
    )
    parser.add_argument("--disable-dep-analysis", action="store_true", dest="disable_dep_analysis")
    args = parser.parse_args()

    try:
        settings = AppSettings()  # type: ignore[call-arg]
    except ValidationError as e:
        logging.error("Missing required environment variables:\n%s", e)
        sys.exit(2)

    try:
        components_mapping = load_component_mapping(settings.component_mapping_file_path)
        exclude_files_mapping = load_mapping(settings.exclude_files_file_path)

        allowed_severity_list = [x.strip() for x in args.allowed_severity.split(",")]
        invalid_severities = [s for s in allowed_severity_list if s not in SEVERITY_PRIORITY_MAP]
        if invalid_severities:
            logging.error(
                "Invalid severity level(s): %s. Valid values: %s",
                ", ".join(invalid_severities),
                ", ".join(SEVERITY_PRIORITY_MAP),
            )
            sys.exit(2)

        if settings.dry_run:
            logging.info("DRY_RUN is enabled")

        snyk_client = SnykClient(
            api_token=settings.snyk_api_token,
            api_version=args.version,
            result_limit=args.limit,
        )
        projects = snyk_client.list_projects(settings.snyk_org_id)

        jira_client = JiraClient(
            jira_server=settings.jira_server,
            jira_email=settings.jira_email,
            jira_api_token=settings.jira_api_token,
            jira_label_prefix=settings.jira_label_prefix,
            jira_project_id=settings.jira_project_id,
            jira_project_key=settings.jira_project_key,
            component_mapping=components_mapping,
            dry_run=settings.dry_run,
        )

        process_projects(
            jira_client,
            snyk_client,
            settings.snyk_org_id,
            projects,
            exclude_files_mapping,
            args.disable_dep_analysis,
            allowed_severity_list,
        )
    except SnykJiraReporterError as e:
        logging.error("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
