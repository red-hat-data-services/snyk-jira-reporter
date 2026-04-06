"""Jira API client wrapper."""

import logging
from typing import Any

import requests
from jira import JIRA

from snyk_jira_reporter.config.constants import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    JIRA_BUG_ISSUE_TYPE,
    JIRA_CLOSE_COMMENT,
    JIRA_CLOSE_TRANSITION,
    JIRA_SECURITY_FIELD_ID,
    UID_REGEX,
)
from snyk_jira_reporter.exceptions.exceptions import JiraClientError
from snyk_jira_reporter.models.vulnerability import VulnerabilityData
from snyk_jira_reporter.utils.labels import create_labels, get_jira_priority

logger = logging.getLogger(__name__)


class JiraClient:
    """Client for creating and managing Jira issues from Snyk vulnerabilities.

    Args:
        jira_server: Jira server URL.
        jira_email: Jira user email for basic authentication.
        jira_api_token: Jira API authentication token.
        jira_label_prefix: Prefix for labels created by this tool.
        jira_project_id: Jira project ID for issue creation.
        jira_project_key: Jira project key for JQL queries.
        component_mapping: Mapping of repository names to Jira component names.
        dry_run: If True, no Jira issues will be created or modified.
    """

    def __init__(
        self,
        jira_server: str,
        jira_email: str,
        jira_api_token: str,
        jira_label_prefix: str,
        jira_project_id: str,
        jira_project_key: str,
        component_mapping: dict[str, str],
        dry_run: bool,
    ) -> None:
        self.jira_label_prefix = jira_label_prefix
        self.jira_project_id = jira_project_id
        self.jira_project_key = jira_project_key
        self.component_mapping = component_mapping
        self.dry_run = dry_run
        self.jira_server = jira_server.rstrip("/")  # Remove trailing slash
        self.auth = (jira_email, jira_api_token)

        # Initialize JIRA library client for basic operations
        # Use basic_auth for Jira Cloud API token authentication
        self.jira = JIRA(server=self.jira_server, basic_auth=(jira_email, jira_api_token), options={"verify": True})

    def create_jira_issues(
        self,
        vulnerabilities_to_create: list[VulnerabilityData],
        jira_project_id: str,
        snyk_project_id: str,
        snyk_org_slug: str,
    ) -> int:
        """Create Jira bug issues from a list of vulnerabilities.

        Args:
            vulnerabilities_to_create: Vulnerabilities to create Jira issues for.
            jira_project_id: Jira project ID for issue creation.
            snyk_project_id: Snyk project ID for description links.
            snyk_org_slug: Snyk organization slug for description links.

        Returns:
            Number of issues actually created, or would-be-created count in dry-run mode.
        """
        if self.dry_run:
            logger.info("DRY RUN: %d issue(s) would be created", len(vulnerabilities_to_create))
            for vulnerability in vulnerabilities_to_create:
                logger.info("  Would create: %s", vulnerability.jira_summary())
            return len(vulnerabilities_to_create)

        created_count = 0
        for vulnerability in vulnerabilities_to_create:
            try:
                has_component = bool(vulnerability.component)
                labels = create_labels(vulnerability, has_component_mapping=has_component)

                # Prepare issue fields for jira library
                issue_fields = {
                    "project": {"key": jira_project_id},
                    "summary": vulnerability.jira_summary(),
                    "issuetype": {"name": JIRA_BUG_ISSUE_TYPE},
                    "security": {"id": JIRA_SECURITY_FIELD_ID},
                    "labels": labels,
                    "priority": get_jira_priority(vulnerability.severity),
                }

                # Only add components if we have a valid component name
                if vulnerability.component:
                    issue_fields["components"] = [{"name": vulnerability.component}]  # type: ignore[list-item]

                # Create issue using jira library
                new_issue = self.jira.create_issue(fields=issue_fields)
                logger.info("Created JIRA issue key: %s", new_issue.key)

                # Update the description with ADF format using direct API call
                # The jira library doesn't handle ADF conversion automatically
                description_adf = self._convert_description_to_adf(
                    vulnerability.jira_description(snyk_org_slug, snyk_project_id)
                )
                self._update_issue_description_v3(new_issue.key, description_adf)

                created_count += 1

            except Exception as e:
                logger.error("Failed to create Jira issue for vulnerability %s: %s", vulnerability.title, e)

        return created_count

    def get_existing_jira_for_project(
        self, project_name: str, file_name: str, project_branch: str
    ) -> list[dict[str, Any]]:
        """List all Jira bugs matching a specific Snyk project/file/branch combination.

        Handles both old and new UID formats to ensure proper stale issue detection.
        Old format: prefix:project:file:master:snyk-id
        New format: prefix:project:file:branch:issue-id

        Args:
            project_name: GitHub repository name (e.g. 'red-hat-data-services/kserve').
            file_name: File path captured by Snyk.
            project_branch: Branch where Snyk scans.

        Returns:
            List of matching Jira issue dicts.

        Raises:
            JiraClientError: If the Jira search fails.
        """
        component = self.component_mapping.get(project_name, "")
        component_str = f'component = "{component}" AND ' if component else ""

        # Create broader search to find both old and new format issues
        # Search for any issues with this project and file combination
        project_file_pattern = f"{self.jira_label_prefix}{project_name}:{file_name}:"

        # Handle branch variations: search for both current branch and master/main variations
        branches_to_search = [project_branch]
        if project_branch == "main":
            branches_to_search.append("master")  # Also search for old master branch issues
        elif project_branch == "master":
            branches_to_search.append("main")  # Also search for new main branch issues

        # Create a broader JQL query to find related issues
        jira_query = (
            f"project = {self.jira_project_key} AND {component_str}"
            f'description ~ "{project_file_pattern}" AND description ~ "snyk-jira-uid"'
        )

        logger.info("Fetching jiras using jql: %s", jira_query)
        logger.debug("Searching for project: %s, file: %s, branches: %s", project_name, file_name, branches_to_search)

        try:
            # Use JIRA library for automatic pagination and robust error handling
            raw_issues = self.jira.search_issues(
                jira_query,
                maxResults=0,  # 0 means unlimited results, library handles pagination
                fields="key,summary,description,status,components,labels",
            )

            # Convert JIRA library objects to dicts and filter results
            filtered_issues = []
            for issue in raw_issues:
                # Convert JIRA issue object to dict format
                issue_dict: dict[str, Any] = {
                    "key": issue.key,
                    "fields": {
                        "summary": getattr(issue.fields, "summary", ""),
                        "description": getattr(issue.fields, "description", ""),
                        "status": {"name": getattr(issue.fields.status, "name", "")} if issue.fields.status else {},
                        "components": [{"name": c.name} for c in getattr(issue.fields, "components", [])],
                        "labels": getattr(issue.fields, "labels", []),
                    },
                }

                # Check if this issue matches our project/file/branch criteria
                description = issue_dict["fields"].get("description", "") or ""
                if self._issue_matches_criteria(description, project_name, file_name, branches_to_search):
                    filtered_issues.append(issue_dict)
                    logger.debug("  Found matching issue: %s", issue.key)

            logger.debug("Total filtered issues found: %d", len(filtered_issues))
            return filtered_issues

        except Exception as e:
            raise JiraClientError(f"Failed to fetch existing Jira issues: {e}") from e

    def _issue_matches_criteria(self, description: Any, project_name: str, file_name: str, branches: list[str]) -> bool:
        """Check if a Jira issue description matches the project/file/branch criteria.

        Handles both old and new UID formats.
        """
        import re

        # Handle ADF format (description can be a dict in Jira Cloud)
        description_text = ""
        if isinstance(description, dict):
            # Extract text from ADF format
            description_text = self._extract_text_from_adf(description)
        elif isinstance(description, str):
            description_text = description
        else:
            description_text = str(description) if description else ""

        # Extract UID from description
        match = re.search(UID_REGEX, description_text)
        if not match:
            return False

        uid = match.group(1).strip()
        uid_parts = uid.split(":")

        if len(uid_parts) < 4:
            return False

        # Parse UID: prefix:project:file:branch[:optional-id]
        uid_project = uid_parts[1]
        uid_file = uid_parts[2]
        uid_branch = uid_parts[3]

        # Check if project and file match
        if uid_project != project_name or uid_file != file_name:
            return False

        # Check if branch matches any of the acceptable branches
        return uid_branch in branches

    def _extract_text_from_adf(self, adf_content: dict[str, Any]) -> str:
        """Extract plain text from Atlassian Document Format content."""

        def extract_text_recursive(node: Any) -> str:
            if isinstance(node, dict):
                text = ""
                if "text" in node:
                    text += node["text"]
                if "content" in node:
                    for child in node["content"]:
                        text += extract_text_recursive(child)
                return text
            elif isinstance(node, list):
                return "".join(extract_text_recursive(item) for item in node)
            return str(node)

        return extract_text_recursive(adf_content)

    def _strip_wiki_markup(self, text: str) -> str:
        """Strip common Jira wiki markup patterns to prevent ADF rendering issues.

        Args:
            text: Text that may contain wiki markup.

        Returns:
            Clean text with wiki markup removed.
        """
        import re

        # Remove bold/italic markup: *text* -> text
        text = re.sub(r"\*([^*]+)\*", r"\1", text)
        # Remove extra newlines that were meant for wiki formatting
        text = re.sub(r" \n\n", "\n\n", text)
        # Clean up multiple consecutive newlines
        text = re.sub(r"\n{3,}", "\n\n", text)

        return text.strip()

    def _convert_description_to_adf(self, text: str) -> dict[str, Any]:
        """Convert plain text description to Atlassian Document Format.

        Args:
            text: Plain text description.

        Returns:
            ADF formatted description dict.
        """
        # Strip wiki markup to prevent rendering issues in Jira Cloud
        clean_text = self._strip_wiki_markup(text)
        return {
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": clean_text}]}],
        }

    def _update_issue_description_v3(self, issue_key: str, description_adf: dict[str, Any]) -> None:
        """Update issue description using API v3 with ADF format.

        Args:
            issue_key: Issue key (e.g. 'PROJ-123').
            description_adf: Description in ADF format.

        Raises:
            JiraClientError: If the API call fails.
        """
        url = f"{self.jira_server}/rest/api/3/issue/{issue_key}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        payload = {"fields": {"description": description_adf}}

        try:
            logger.debug("Updating description for issue %s", issue_key)
            response = requests.put(
                url,
                json=payload,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )

            logger.debug("Update description response status: %d", response.status_code)
            if response.status_code not in [200, 204]:
                logger.error("Update description response text: %s", response.text)

            response.raise_for_status()
        except requests.RequestException as e:
            logger.error("Failed to update issue description: %s", e)
            raise JiraClientError(f"Failed to update issue description via API v3: {e}") from e

    def _add_comment_v3(self, issue_key: str, comment_body: str) -> None:
        """Add comment to issue using API v3.

        Args:
            issue_key: Issue key (e.g. 'PROJ-123').
            comment_body: Comment text.

        Raises:
            JiraClientError: If the API call fails.
        """
        url = f"{self.jira_server}/rest/api/3/issue/{issue_key}/comment"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        # Use simple Atlassian Document Format (ADF) for comments
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": comment_body}]}],
            }
        }

        try:
            logger.debug("Adding comment to issue %s", issue_key)
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )

            logger.debug("Comment response status: %d", response.status_code)
            if response.status_code not in [200, 201]:
                logger.error("Comment response text: %s", response.text)

            response.raise_for_status()
        except requests.RequestException as e:
            logger.error("Failed to add comment: %s", e)
            raise JiraClientError(f"Failed to add comment via API v3: {e}") from e

    def _transition_issue_v3(self, issue_key: str, transition_name: str) -> None:
        """Transition issue using API v3.

        Args:
            issue_key: Issue key (e.g. 'PROJ-123').
            transition_name: Name of transition (e.g. 'Closed').

        Raises:
            JiraClientError: If the API call fails.
        """
        try:
            # First get available transitions
            transitions_url = f"{self.jira_server}/rest/api/3/issue/{issue_key}/transitions"
            headers = {"Accept": "application/json"}

            logger.debug("Getting transitions for issue %s", issue_key)
            response = requests.get(
                transitions_url,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            transitions_data = response.json()

            # Find transition by name
            transition_id = None
            available_transitions = []
            for transition in transitions_data.get("transitions", []):
                available_transitions.append(transition["name"])
                if transition["name"].lower() == transition_name.lower():
                    transition_id = transition["id"]
                    break

            if transition_id is None:
                logger.warning(
                    "Transition '%s' not found for issue %s. Available transitions: %s",
                    transition_name,
                    issue_key,
                    available_transitions,
                )
                return

            # Execute transition
            logger.debug("Executing transition '%s' (ID: %s) for issue %s", transition_name, transition_id, issue_key)
            transition_url = f"{self.jira_server}/rest/api/3/issue/{issue_key}/transitions"
            headers = {"Accept": "application/json", "Content-Type": "application/json"}
            payload = {"transition": {"id": transition_id}}

            response = requests.post(
                transition_url,
                json=payload,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )

            logger.debug("Transition response status: %d", response.status_code)
            if response.status_code not in [200, 204]:
                logger.error("Transition response text: %s", response.text)

            response.raise_for_status()

        except requests.RequestException as e:
            logger.error("Failed to transition issue: %s", e)
            raise JiraClientError(f"Failed to transition issue via API v3: {e}") from e

    def add_jira_comment(self, issue: dict[str, Any]) -> None:
        """Add a closing comment and transition a Jira issue to Closed.

        Args:
            issue: Jira issue dict containing at minimum a 'key' field.

        Raises:
            JiraClientError: If commenting or transitioning fails.
        """
        jira_id = issue["key"]
        self._add_comment_v3(jira_id, JIRA_CLOSE_COMMENT)
        self._transition_issue_v3(jira_id, JIRA_CLOSE_TRANSITION)
