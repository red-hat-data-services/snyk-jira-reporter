"""Application coordinator for snyk-jira-reporter."""

import logging
from typing import Any

from snyk_jira_reporter.cli.args import CliArguments
from snyk_jira_reporter.clients.jira_client import JiraClient
from snyk_jira_reporter.clients.snyk_client import SnykClient
from snyk_jira_reporter.config.settings import AppSettings
from snyk_jira_reporter.exceptions.exceptions import SnykJiraReporterError
from snyk_jira_reporter.services.component_resolver import generate_component_report, resolve_unmapped_issues
from snyk_jira_reporter.services.vulnerability_service import process_projects


class SnykJiraReporterApp:
    """Coordinates the complete snyk-jira-reporter workflow."""

    def __init__(
        self,
        settings: AppSettings,
        cli_args: CliArguments,
        components_mapping: dict[str, str],
        exclude_files_mapping: dict[str, Any],
    ):
        """Initialize the application coordinator.

        Args:
            settings: Application settings from environment variables.
            cli_args: Validated CLI arguments.
            components_mapping: Repository to component mapping.
            exclude_files_mapping: File exclusion patterns.
        """
        self.settings = settings
        self.cli_args = cli_args
        self.components_mapping = components_mapping
        self.exclude_files_mapping = exclude_files_mapping

        self._snyk_client: SnykClient | None = None
        self._jira_client: JiraClient | None = None
        self._logger = logging.getLogger(__name__)

    def _initialize_clients(self) -> tuple[SnykClient, JiraClient]:
        """Initialize and return Snyk and Jira clients.

        Returns:
            Tuple of (snyk_client, jira_client).

        Raises:
            SnykJiraReporterError: If client initialization fails.
        """
        try:
            self._logger.info("Initializing API clients...")

            snyk_client = SnykClient(
                api_token=self.settings.snyk_api_token,
                api_version=self.cli_args.api_version,
                result_limit=self.cli_args.limit,
            )

            jira_client = JiraClient(
                jira_server=self.settings.jira_server,
                jira_email=self.settings.jira_email,
                jira_api_token=self.settings.jira_api_token,
                jira_label_prefix=self.settings.jira_label_prefix,
                jira_project_id=self.settings.jira_project_id,
                jira_project_key=self.settings.jira_project_key,
                component_mapping=self.components_mapping,
                dry_run=self.settings.dry_run,
            )

            self._snyk_client = snyk_client
            self._jira_client = jira_client
            self._logger.info("API clients initialized successfully")

            return snyk_client, jira_client

        except Exception as e:
            raise SnykJiraReporterError(f"Failed to initialize clients: {e}") from e

    def _execute_vulnerability_processing(self, snyk_client: SnykClient, jira_client: JiraClient) -> None:
        """Execute the main vulnerability processing workflow.

        Args:
            snyk_client: Initialized Snyk client.
            jira_client: Initialized Jira client.

        Raises:
            SnykJiraReporterError: If vulnerability processing fails.
        """
        try:
            self._logger.info("Starting vulnerability processing...")

            projects = snyk_client.list_projects(self.settings.snyk_org_id)
            self._logger.info("Found %d projects to process", len(projects))

            process_projects(
                jira_client,
                snyk_client,
                self.settings.snyk_org_id,
                projects,
                self.exclude_files_mapping,
                self.cli_args.disable_dep_analysis,
                self.cli_args.allowed_severities,
            )

            self._logger.info("Vulnerability processing completed successfully")

        except Exception as e:
            raise SnykJiraReporterError(f"Vulnerability processing failed: {e}") from e

    def _resolve_unmapped_issues(self, jira_client: JiraClient) -> int:
        """Resolve previously unmapped issues.

        Args:
            jira_client: Initialized Jira client.

        Returns:
            Number of resolved issues (0 if dry-run).

        Raises:
            SnykJiraReporterError: If unmapped issue resolution fails.
        """
        try:
            self._logger.info("Checking for unmapped issues...")

            if self.settings.dry_run:
                unmapped_issues = jira_client.search_issues_by_label("unmapped-repo")
                count = len(unmapped_issues)
                self._logger.info("DRY_RUN: Found %d unmapped repository issues", count)
                return 0
            else:
                resolved_count = resolve_unmapped_issues(jira_client)
                self._logger.info("Resolved %d previously unmapped issues", resolved_count)
                return resolved_count

        except Exception as e:
            # Log error but don't fail entire process for unmapped resolution
            self._logger.error("Failed to check/resolve unmapped issues: %s", e)
            return 0

    def _generate_reports(self, jira_client: JiraClient) -> None:
        """Generate component mapping reports.

        Args:
            jira_client: Initialized Jira client.

        Raises:
            SnykJiraReporterError: If report generation fails critically.
        """
        try:
            self._logger.info("Generating component reports...")
            generate_component_report(jira_client, self.components_mapping)
            self._logger.info("Component reports generated successfully")

        except Exception as e:
            # Log error but don't fail entire process for report generation
            self._logger.error("Report generation failed: %s", e)

    def execute(self) -> int:
        """Execute the complete workflow.

        Returns:
            Exit code (0 for success, 1 for fatal error).
        """
        try:
            # Phase 1: Initialize clients
            self._logger.info("Phase 1/4: Initializing clients...")
            snyk_client, jira_client = self._initialize_clients()

            # Phase 2: Process vulnerabilities
            self._logger.info("Phase 2/4: Processing vulnerabilities...")
            self._execute_vulnerability_processing(snyk_client, jira_client)

            # Phase 3: Resolve unmapped issues
            self._logger.info("Phase 3/4: Resolving unmapped issues...")
            resolved_count = self._resolve_unmapped_issues(jira_client)

            # Phase 4: Generate reports
            self._logger.info("Phase 4/4: Generating reports...")
            self._generate_reports(jira_client)

            self._logger.info("Workflow completed successfully (resolved %d unmapped issues)", resolved_count)
            return 0

        except SnykJiraReporterError as e:
            self._logger.error("Fatal error: %s", e)
            return 1
        except Exception as e:
            self._logger.exception("Unexpected error: %s", e)
            return 1
