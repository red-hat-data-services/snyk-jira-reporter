"""Jira API client wrapper."""

import logging
from typing import Any

import requests
from jira import JIRA
from jira.exceptions import JIRAError

from snyk_jira_reporter.config.constants import (
    JIRA_BUG_ISSUE_TYPE,
    JIRA_CLOSE_COMMENT,
    JIRA_CLOSE_TRANSITION,
    JIRA_MAX_SEARCH_PAGES,
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
        try:
            # Force API v3 for Jira Cloud compatibility
            options = {"server": jira_server, "rest_path": "api", "rest_api_version": "3", "verify": True}
            self.client = JIRA(
                options=options,
                basic_auth=(jira_email, jira_api_token),
            )
        except JIRAError as e:
            raise JiraClientError(f"Failed to create Jira client: {e}") from e

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
        jira_issues_to_create = []
        for vulnerability in vulnerabilities_to_create:
            has_component = bool(vulnerability.component)
            labels = create_labels(vulnerability, has_component_mapping=has_component)
            jira_issues_to_create.append(
                {
                    "project": jira_project_id,
                    "summary": vulnerability.jira_summary(),
                    "description": vulnerability.jira_description(snyk_org_slug, snyk_project_id),
                    "issuetype": {"name": JIRA_BUG_ISSUE_TYPE},
                    "components": [{"name": vulnerability.component}],
                    "security": {"id": JIRA_SECURITY_FIELD_ID},
                    "labels": labels,
                    "priority": get_jira_priority(vulnerability.severity),
                }
            )
        if self.dry_run:
            logger.info("DRY RUN: %d issue(s) would be created", len(jira_issues_to_create))
            for jira_issue in jira_issues_to_create:
                logger.info("  Would create: %s", jira_issue["summary"])
            return len(jira_issues_to_create)

        try:
            results = self._create_issues_v3(jira_issues_to_create)
        except JIRAError as e:
            logger.error("Failed to create Jira issues: %s", e)
            return 0

        created_count = 0
        for result in results:
            if "issue" in result:
                logger.info("Created JIRA issue key: %s", result["issue"])
                created_count += 1
            elif "error" in result:
                logger.error("Failed to create Jira issue: %s", result["error"])
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
        issues: list[dict[str, Any]] = []
        start = 0
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

        for _ in range(JIRA_MAX_SEARCH_PAGES):
            try:
                # Always use direct API call since jira library has issues with Cloud
                search_result = self._search_issues_v3(jira_query, start_at=start, max_results=50)
                next_page: list[dict[str, Any]] = search_result["issues"]

                # Filter results to match our specific project/file/branch combination
                filtered_page = []
                for issue in next_page:
                    fields = issue.get("fields", {})
                    description = fields.get("description", "") or ""

                    # Check if this issue matches our project/file/branch criteria
                    if self._issue_matches_criteria(description, project_name, file_name, branches_to_search):
                        filtered_page.append(issue)
                        logger.debug("  Found matching issue: %s", issue.get("key"))

                issues.extend(filtered_page)
                start += len(next_page)
                if len(next_page) == 0:
                    break
            except Exception as e:
                raise JiraClientError(f"Failed to fetch existing Jira issues: {e}") from e
        else:
            logger.warning("Reached max page limit (%d) for JQL query: %s", JIRA_MAX_SEARCH_PAGES, jira_query)

        logger.debug("Total filtered issues found: %d", len(issues))
        return issues

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

    def _search_issues_v3(self, jql_query: str, start_at: int = 0, max_results: int = 50) -> dict[str, Any]:
        """Search issues using the Jira Cloud search/jql API.

        Uses GET method with query parameters as required by Jira Cloud migration.

        Args:
            jql_query: JQL query string.
            start_at: Starting index for pagination.
            max_results: Maximum results per page.

        Returns:
            API response dict containing issues.

        Raises:
            JiraClientError: If the API call fails.
        """
        # Use the new search/jql endpoint with GET method as mandated by Jira Cloud
        url = f"{self.jira_server}/rest/api/3/search/jql"
        headers = {"Accept": "application/json"}

        params: dict[str, str | int] = {
            "jql": jql_query,
            "startAt": start_at,
            "maxResults": max_results,
            "fields": "key,summary,description,status,components,labels",
        }

        try:
            logger.debug("Making Jira search/jql request to: %s", url)
            logger.debug("JQL: %s", jql_query)
            logger.debug("Params: %s", params)

            response = requests.get(url, headers=headers, params=params, auth=self.auth, verify=True, timeout=30)

            logger.debug("Response status: %d", response.status_code)

            if response.status_code == 200:
                result: dict[str, Any] = response.json()
                logger.debug("Search succeeded, found %d issues", len(result.get("issues", [])))

                # Debug: Show the structure of the first issue to understand the format
                if result.get("issues") and len(result["issues"]) > 0:
                    first_issue = result["issues"][0]
                    logger.debug("First issue structure: keys = %s", list(first_issue.keys()))
                    if "fields" in first_issue:
                        logger.debug("Fields structure: %s", list(first_issue["fields"].keys()))
                    else:
                        logger.warning("No 'fields' key found. Full issue: %s", first_issue)

                return result
            else:
                logger.error("Search failed with status %d: %s", response.status_code, response.text[:200])

                # Provide specific error guidance
                if response.status_code == 400:
                    logger.error("Bad Request - Check JQL syntax: %s", jql_query)
                elif response.status_code == 401:
                    logger.error("Authentication failed - check JIRA_EMAIL and JIRA_API_TOKEN")
                elif response.status_code == 403:
                    logger.error("Permission denied - check if user has access to project %s", self.jira_project_key)

                raise JiraClientError(f"Jira search failed (HTTP {response.status_code}): {response.text}")

        except requests.RequestException as e:
            logger.error("Request exception during Jira search: %s", e)
            raise JiraClientError(f"Jira search request failed: {e}") from e

    def _create_issues_v3(self, issues_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Create issues using direct API v3 calls.

        Args:
            issues_data: List of issue data dicts to create.

        Returns:
            List of results with either 'issue' key (success) or 'error' key (failure).

        Raises:
            JiraClientError: If the API call fails.
        """
        results = []
        for issue_data in issues_data:
            try:
                url = f"{self.jira_server}/rest/api/3/issue"
                headers = {"Accept": "application/json", "Content-Type": "application/json"}
                # Convert the issue data to the correct format for Jira Cloud
                payload = {"fields": self._convert_issue_fields_for_cloud(issue_data)}

                logger.debug("Creating Jira issue with payload: %s", payload)

                response = requests.post(url, json=payload, headers=headers, auth=self.auth, verify=True, timeout=30)

                logger.debug("Create issue response status: %d", response.status_code)
                if response.status_code not in [200, 201]:
                    logger.error("Create issue response text: %s", response.text)

                if response.status_code in [200, 201]:
                    issue_response = response.json()
                    results.append({"issue": issue_response["key"]})
                else:
                    error_msg = response.text
                    results.append({"error": f"HTTP {response.status_code}: {error_msg}"})

            except requests.RequestException as e:
                logger.error("Failed to create issue: %s", e)
                results.append({"error": str(e)})

        return results

    def _convert_issue_fields_for_cloud(self, issue_data: dict[str, Any]) -> dict[str, Any]:
        """Convert issue fields to Jira Cloud format.

        Args:
            issue_data: Issue data dict.

        Returns:
            Converted fields dict for Jira Cloud.
        """
        # Convert project ID to proper format
        converted: dict[str, Any] = {}
        for field, value in issue_data.items():
            if field == "project":
                converted[field] = {"key": str(value)}
            elif field == "issuetype" or field == "priority":
                converted[field] = {"name": value["name"]}
            elif field == "components":
                converted[field] = [{"name": comp["name"]} for comp in value]
            elif field == "security":
                converted[field] = {"id": str(value["id"])}
            elif field == "description":
                # Convert plain text description to Atlassian Document Format (ADF)
                converted[field] = {
                    "type": "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(value)}]}],
                }
            else:
                converted[field] = value
        return converted

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
            response = requests.post(url, json=payload, headers=headers, auth=self.auth, verify=True, timeout=30)

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
            response = requests.get(transitions_url, headers=headers, auth=self.auth, verify=True, timeout=30)
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
                transition_url, json=payload, headers=headers, auth=self.auth, verify=True, timeout=30
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
        try:
            jira_id = issue["key"]
            self._add_comment_v3(jira_id, JIRA_CLOSE_COMMENT)
            self._transition_issue_v3(jira_id, JIRA_CLOSE_TRANSITION)
        except JIRAError as e:
            raise JiraClientError(f"Error while closing issue {issue.get('key')}: {e}") from e
