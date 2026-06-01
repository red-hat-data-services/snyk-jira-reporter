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
from snyk_jira_reporter.utils.adf_parser import extract_text_from_adf
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

        # Cache for project components to avoid repeated API calls
        self._project_components_cache: list[str] | None = None

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
                    "project": {"key": self.jira_project_key},
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
        # Use a broad, reliable search and filter precisely in code
        # Avoid complex text patterns in JQL that can fail with special characters
        repository_key = project_name.replace("/", "-").replace(".", "-")  # Safer for JQL

        # Handle branch variations: search for both current branch and master/main variations
        branches_to_search = [project_branch]
        if project_branch == "main":
            branches_to_search.append("master")  # Also search for old master branch issues
        elif project_branch == "master":
            branches_to_search.append("main")  # Also search for new main branch issues

        # Broad search using simple, reliable patterns - filter precisely in application code
        jira_query = (
            f"project = {self.jira_project_key} AND "
            f'description ~ "{self.jira_label_prefix}" AND '
            f'description ~ "{repository_key}" AND '
            f'description ~ "snyk-jira-uid"'
        )

        # Store the original pattern for logging and debugging
        project_file_pattern = f"{self.jira_label_prefix}{project_name}:{file_name}:"

        logger.info("Fetching jiras using jql: %s", jira_query)
        logger.debug("Searching for project: %s, file: %s, branches: %s", project_name, file_name, branches_to_search)
        logger.debug(
            "JQL safe pattern: repository_key='%s', original pattern='%s'", repository_key, project_file_pattern
        )

        try:
            # Use JIRA library for automatic pagination and robust error handling
            raw_issues = self.jira.search_issues(
                jira_query,
                maxResults=0,  # 0 means unlimited results, library handles pagination
                fields="key,summary,description,status,components,labels",
            )

            # Convert JIRA library objects to dicts and filter results
            filtered_issues = []
            logger.debug("Raw JQL search returned %d issues", len(raw_issues))

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
                status_name = issue_dict["fields"].get("status", {}).get("name", "")

                logger.debug("  Evaluating issue %s (status: %s)", issue.key, status_name)
                logger.debug("    Description length: %d chars", len(str(description)))

                if self._issue_matches_criteria(description, project_name, file_name, branches_to_search):
                    filtered_issues.append(issue_dict)
                    logger.debug("  ✓ Found matching issue: %s", issue.key)
                else:
                    logger.debug("  ❌ Issue %s doesn't match criteria", issue.key)

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
            description_text = extract_text_from_adf(description)
            logger.debug("    Extracted ADF text (%d chars): %s...", len(description_text), description_text[:100])
        elif isinstance(description, str):
            description_text = description
            logger.debug("    Plain text description (%d chars): %s...", len(description_text), description_text[:100])
        else:
            description_text = str(description) if description else ""
            logger.debug("    Converted description to text: %s", description_text)

        # Extract UID from description
        match = re.search(UID_REGEX, description_text)
        if not match:
            logger.debug("    ❌ No UID match found with regex: %s", UID_REGEX)
            logger.debug("    Description preview: %s", description_text[:200] if description_text else "EMPTY")
            return False

        uid = match.group(1).strip()
        uid_parts = uid.split(":")
        logger.debug("    ✓ Extracted UID: %s", uid)

        if len(uid_parts) < 4:
            logger.debug("    ❌ UID has insufficient parts (%d < 4): %s", len(uid_parts), uid_parts)
            return False

        # Parse UID: prefix:project:file:branch[:optional-id]
        uid_project = uid_parts[1]
        uid_file = uid_parts[2]
        uid_branch = uid_parts[3]

        logger.debug("    UID components - project: %s, file: %s, branch: %s", uid_project, uid_file, uid_branch)
        logger.debug("    Target criteria - project: %s, file: %s, branches: %s", project_name, file_name, branches)

        # Check if project and file match
        if uid_project != project_name or uid_file != file_name:
            logger.debug("    ❌ Project/file mismatch: %s/%s != %s/%s", uid_project, uid_file, project_name, file_name)
            return False

        # Check if branch matches any of the acceptable branches
        branch_match = uid_branch in branches
        if branch_match:
            logger.debug("    ✓ Branch matches: %s in %s", uid_branch, branches)
        else:
            logger.debug("    ❌ Branch mismatch: %s not in %s", uid_branch, branches)

        return branch_match

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
            ADF formatted description dict with proper paragraph structure.
        """
        # Strip wiki markup to prevent rendering issues in Jira Cloud
        clean_text = self._strip_wiki_markup(text)

        # Split on double newlines to create separate paragraphs
        paragraphs = [p.strip() for p in clean_text.split("\n\n") if p.strip()]

        content = []
        for paragraph in paragraphs:
            if "\n" in paragraph:
                # Handle single newlines within paragraphs as hard breaks
                lines = [line.strip() for line in paragraph.split("\n") if line.strip()]
                para_content = []
                for i, line in enumerate(lines):
                    para_content.append({"type": "text", "text": line})
                    if i < len(lines) - 1:
                        para_content.append({"type": "hardBreak"})
                content.append({"type": "paragraph", "content": para_content})
            else:
                content.append({"type": "paragraph", "content": [{"type": "text", "text": paragraph}]})

        return {
            "type": "doc",
            "version": 1,
            "content": content,
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
        except Exception as e:
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
        except Exception as e:
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

        except Exception as e:
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

    def list_project_components(self) -> list[str]:
        """Get all valid component names for the Jira project.

        Returns:
            List of component names available in the project.

        Raises:
            JiraClientError: If the API call fails.
        """
        if self._project_components_cache is not None:
            return self._project_components_cache

        url = f"{self.jira_server}/rest/api/3/project/{self.jira_project_key}/components"
        headers = {"Accept": "application/json"}

        try:
            logger.debug("Fetching components for project %s", self.jira_project_key)
            response = requests.get(
                url,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )

            logger.debug("Component list response status: %d", response.status_code)
            if response.status_code != 200:
                logger.error("Component list response text: %s", response.text)

            response.raise_for_status()
            components_data = response.json()

            # Extract component names from response
            component_names = [component["name"] for component in components_data]
            self._project_components_cache = component_names

            logger.info("Found %d components in project %s", len(component_names), self.jira_project_key)
            return component_names

        except Exception as e:
            logger.error("Failed to fetch project components: %s", e)
            raise JiraClientError(f"Failed to fetch project components via API v3: {e}") from e

    def validate_component_exists(self, component_name: str) -> bool:
        """Check if a component exists in the Jira project.

        Args:
            component_name: Name of the component to validate.

        Returns:
            True if component exists, False otherwise.

        Raises:
            JiraClientError: If the API call fails.
        """
        valid_components = self.list_project_components()
        return component_name in valid_components

    def get_component_creation_url(self) -> str:
        """Generate Jira URL for manual component creation.

        Returns:
            URL for creating components in Jira project administration.
        """
        # URL for project component management in Jira Cloud
        return f"{self.jira_server}/plugins/servlet/project-config/{self.jira_project_key}/administer-components"

    def search_issues_by_label(self, label: str) -> list[dict[str, Any]]:
        """Search for Jira issues with a specific label.

        Uses direct REST API v3 calls to avoid deprecated API v2 issues
        with the JIRA Python library.

        Args:
            label: Label to search for (e.g. 'unmapped-repo').

        Returns:
            List of Jira issue dicts matching the label.

        Raises:
            JiraClientError: If the Jira search fails.
        """
        jira_query = f'project = {self.jira_project_key} AND labels = "{label}"'

        logger.info("Searching for issues with label '%s' using JQL: %s", label, jira_query)

        try:
            # Use direct REST API v3 call since the JIRA library uses deprecated API v2
            url = f"{self.jira_server}/rest/api/3/search/jql"
            headers = {"Accept": "application/json", "Content-Type": "application/json"}

            # Paginated search to handle large result sets
            all_issues = []
            max_results = 100
            start_at = 0

            while True:
                params: dict[str, str | int | list[str]] = {
                    "jql": jira_query,
                    "fields": ["key", "summary", "description", "status", "components", "labels"],
                    "maxResults": max_results,
                    "startAt": start_at,
                }

                logger.debug("Making API v3 search request: startAt=%d, maxResults=%d", start_at, max_results)
                response = requests.get(
                    url, headers=headers, auth=self.auth, params=params, timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS
                )
                response.raise_for_status()

                data = response.json()
                issues = data.get("issues", [])
                all_issues.extend(issues)

                logger.debug("Retrieved %d issues in this batch", len(issues))

                # Check if we need to continue pagination
                if len(issues) < max_results or start_at + max_results >= data.get("maxResults", 0):
                    break

                start_at += max_results

            logger.info("Found %d issues with label '%s'", len(all_issues), label)
            return all_issues

        except Exception as e:
            logger.error("Failed to search for issues with label '%s': %s", label, e)
            raise JiraClientError(f"Failed to search issues by label via REST API v3: {e}") from e

    def update_issue_component(self, issue_key: str, component_name: str) -> None:
        """Update the component field of a Jira issue.

        Uses direct REST API for simple field updates, consistent with other
        field update operations and ADF format handling in this codebase.

        Args:
            issue_key: Issue key (e.g. 'PROJ-123').
            component_name: Name of the component to assign.

        Raises:
            JiraClientError: If the API call fails.
        """
        if self.dry_run:
            logger.info("DRY RUN: Would update issue %s component to '%s'", issue_key, component_name)
            return

        url = f"{self.jira_server}/rest/api/3/issue/{issue_key}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        payload = {"fields": {"components": [{"name": component_name}]}}

        try:
            logger.debug("Updating component for issue %s to '%s'", issue_key, component_name)
            response = requests.put(
                url,
                json=payload,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )

            logger.debug("Update component response status: %d", response.status_code)
            if response.status_code not in [200, 204]:
                logger.error("Update component response text: %s", response.text)

            response.raise_for_status()
            logger.info("Successfully updated issue %s component to '%s'", issue_key, component_name)

        except Exception as e:
            logger.error("Failed to update issue component: %s", e)
            raise JiraClientError(f"Failed to update issue component via API v3: {e}") from e

    def update_issue_labels(self, issue_key: str, labels_to_add: list[str], labels_to_remove: list[str]) -> None:
        """Update the labels of a Jira issue.

        Hybrid approach: JIRA library for safe field reading, REST API for controlled
        label manipulation. This pattern handles read-modify-write operations safely.

        Args:
            issue_key: Issue key (e.g. 'PROJ-123').
            labels_to_add: Labels to add to the issue.
            labels_to_remove: Labels to remove from the issue.

        Raises:
            JiraClientError: If the API call fails.
        """
        if self.dry_run:
            logger.info(
                "DRY RUN: Would update issue %s labels: add %s, remove %s",
                issue_key,
                labels_to_add,
                labels_to_remove,
            )
            return

        # First get current labels
        try:
            issue = self.jira.issue(issue_key, fields="labels")
            current_labels = list(getattr(issue.fields, "labels", []))
        except Exception as e:
            logger.error("Failed to fetch current labels for issue %s: %s", issue_key, e)
            raise JiraClientError(f"Failed to fetch issue labels: {e}") from e

        # Calculate new labels set
        new_labels = set(current_labels)
        new_labels.update(labels_to_add)
        new_labels.difference_update(labels_to_remove)

        url = f"{self.jira_server}/rest/api/3/issue/{issue_key}"
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        payload = {"fields": {"labels": list(new_labels)}}

        try:
            logger.debug("Updating labels for issue %s: add %s, remove %s", issue_key, labels_to_add, labels_to_remove)
            response = requests.put(
                url,
                json=payload,
                headers=headers,
                auth=self.auth,
                verify=True,
                timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
            )

            logger.debug("Update labels response status: %d", response.status_code)
            if response.status_code not in [200, 204]:
                logger.error("Update labels response text: %s", response.text)

            response.raise_for_status()
            logger.info("Successfully updated issue %s labels", issue_key)

        except Exception as e:
            logger.error("Failed to update issue labels: %s", e)
            raise JiraClientError(f"Failed to update issue labels via API v3: {e}") from e
