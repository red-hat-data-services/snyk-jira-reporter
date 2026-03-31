"""Snyk REST API client."""

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from snyk_jira_reporter.config.constants import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    HTTP_RETRY_BACKOFF_FACTOR,
    HTTP_RETRY_STATUS_CODES,
    HTTP_RETRY_TOTAL,
    SNYK_API_BASE_URL,
    SNYK_MAX_PAGES,
    SNYK_REST_API_BASE_URL,
)
from snyk_jira_reporter.exceptions.exceptions import SnykClientError
from snyk_jira_reporter.models.snyk_models import SnykIssue, SnykProject

logger = logging.getLogger(__name__)


def _create_session(headers: dict[str, str]) -> requests.Session:
    """Create a requests session with retry logic for transient failures.

    Retries on 429 (rate limited) and 5xx errors with exponential backoff.
    """
    session = requests.Session()
    session.headers.update(headers)
    retry = Retry(
        total=HTTP_RETRY_TOTAL,
        backoff_factor=HTTP_RETRY_BACKOFF_FACTOR,
        status_forcelist=list(HTTP_RETRY_STATUS_CODES),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class SnykClient:
    """Client for the Snyk REST API.

    Replaces pysnyk with direct REST API calls, providing a unified
    interface for fetching both projects and issues (dependency + SAST).

    Args:
        api_token: Snyk API authentication token.
        api_version: Snyk REST API version string.
        result_limit: Maximum results per page.
    """

    def __init__(self, api_token: str, api_version: str, result_limit: str) -> None:
        self.api_version = api_version
        self.result_limit = result_limit
        self.session = _create_session(
            {
                "authorization": f"token {api_token}",
                "accept": "application/vnd.api+json",
            }
        )

    def _paginate(self, url: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Fetch all pages from a paginated Snyk REST API endpoint.

        Args:
            url: Initial API URL.
            params: Query parameters for the first request.

        Returns:
            Combined list of all data items across all pages.

        Raises:
            SnykClientError: If any request fails.
        """
        results: list[dict[str, Any]] = []
        for _page in range(SNYK_MAX_PAGES):
            try:
                http_response = self.session.get(url, params=params, timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS)
                http_response.raise_for_status()
                response = http_response.json()
            except requests.exceptions.RequestException as e:
                raise SnykClientError(f"Snyk API request failed: {e}") from e
            except ValueError as e:
                raise SnykClientError(f"Snyk API returned invalid JSON: {e}") from e

            if response and response.get("data"):
                results += response["data"]

            next_link = response.get("links", {}).get("next") if response else None
            if next_link:
                url = SNYK_API_BASE_URL + next_link
                params = {}
            else:
                break
        else:
            logger.warning("Reached max page limit (%d) during pagination", SNYK_MAX_PAGES)

        return results

    def get_org_slug(self, org_id: str) -> str:
        """Get the organization slug for a given org ID.

        Args:
            org_id: Snyk organization ID.

        Returns:
            Organization slug string.

        Raises:
            SnykClientError: If the org cannot be retrieved.
        """
        url = f"{SNYK_REST_API_BASE_URL}/orgs/{org_id}"
        params = {"version": self.api_version}
        try:
            http_response = self.session.get(url, params=params, timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS)
            http_response.raise_for_status()
            response = http_response.json()
            return response["data"]["attributes"]["slug"]  # type: ignore[no-any-return]
        except (requests.exceptions.RequestException, ValueError, KeyError) as e:
            raise SnykClientError(f"Failed to get org slug for {org_id}: {e}") from e

    def list_projects(self, org_id: str) -> list[SnykProject]:
        """List all projects for an organization.

        Args:
            org_id: Snyk organization ID.

        Returns:
            List of SnykProject models.

        Raises:
            SnykClientError: If the request fails.
        """
        url = f"{SNYK_REST_API_BASE_URL}/orgs/{org_id}/projects"
        params: dict[str, Any] = {
            "version": self.api_version,
            "limit": self.result_limit,
        }
        raw_projects = self._paginate(url, params)

        org_slug = self.get_org_slug(org_id)
        projects = []
        for item in raw_projects:
            attrs = item.get("attributes", {})
            projects.append(
                SnykProject(
                    id=item["id"],
                    name=attrs.get("name", ""),
                    type=attrs.get("type", ""),
                    status=attrs.get("status", "inactive"),
                    target_reference=attrs.get("target_reference"),
                    org_slug=org_slug,
                )
            )
        return projects

    def get_issues(
        self,
        org_id: str,
        project_id: str,
        issue_type: str,
    ) -> list[SnykIssue]:
        """Fetch issues for a project from the Snyk REST API.

        Supports both 'code' (SAST) and 'package_vulnerability' (dependency) types
        via the same unified endpoint.

        Args:
            org_id: Snyk organization ID.
            project_id: Snyk project ID.
            issue_type: Issue type filter ('code' or 'package_vulnerability').

        Returns:
            List of SnykIssue models.

        Raises:
            SnykClientError: If the request fails.
        """
        url = f"{SNYK_REST_API_BASE_URL}/orgs/{org_id}/issues"
        params: dict[str, Any] = {
            "version": self.api_version,
            "limit": self.result_limit,
            "scan_item.id": project_id,
            "scan_item.type": "project",
            "type": issue_type,
            "status": "open",
            "ignored": False,
        }
        raw_issues = self._paginate(url, params)
        return self._parse_issues(raw_issues, issue_type)

    def _parse_issues(self, raw_issues: list[dict[str, Any]], issue_type: str) -> list[SnykIssue]:
        """Parse raw REST API issue data into SnykIssue models.

        Args:
            raw_issues: Raw issue dicts from the API.
            issue_type: The issue type that was queried.

        Returns:
            List of parsed SnykIssue models.
        """
        issues = []
        for item in raw_issues:
            attrs = item.get("attributes", {})

            if issue_type == "code":
                cwe_identifiers = [cwe["id"] for cwe in attrs.get("classes", [])]
                identifiers = {"CWE": cwe_identifiers, "CVE": []}

                source_file = ""
                source_line = None
                for coord in attrs.get("coordinates", []):
                    for repr_item in coord.get("representations", []):
                        src_loc = repr_item.get("sourceLocation", {})
                        if src_loc.get("file"):
                            source_file = src_loc["file"]
                            region = src_loc.get("region", {})
                            start = region.get("start", {})
                            if start.get("line") is not None:
                                source_line = start["line"]
                            break
                    if source_file:
                        break

                issues.append(
                    SnykIssue(
                        id=item["id"],
                        type=issue_type,
                        title=attrs.get("title", ""),
                        severity=attrs.get("effective_severity_level", ""),
                        url="",
                        identifiers=identifiers,
                        issue_type="code",
                        key=attrs.get("key", ""),
                        source_file=source_file,
                        source_line=source_line,
                    )
                )
            else:
                # package_vulnerability
                problems = attrs.get("problems", [])
                cve_ids = []
                cwe_ids = []
                for problem in problems:
                    source = problem.get("source", "")
                    pid = problem.get("id", "")
                    if source == "CVE":
                        cve_ids.append(pid)
                    elif source == "CWE":
                        cwe_ids.append(pid)
                identifiers = {"CVE": cve_ids, "CWE": cwe_ids}

                coordinates = attrs.get("coordinates", [])
                package_versions: list[str] = []
                fixed_in: list[str] = []
                for coord in coordinates:
                    for repr_item in coord.get("representations", []):
                        dep = repr_item.get("dependency", {})
                        ver = dep.get("version", "")
                        if ver:
                            package_versions.append(ver)
                    for remedy in coord.get("remedies", []):
                        details = remedy.get("details", {})
                        upgrade_to = details.get("upgrade_package", "")
                        if upgrade_to:
                            fixed_in.append(upgrade_to)

                severities = attrs.get("severities", [])
                cvss_score = severities[0].get("score") if severities else None

                issues.append(
                    SnykIssue(
                        id=item["id"],
                        type=issue_type,
                        title=attrs.get("title", ""),
                        severity=attrs.get("effective_severity_level", ""),
                        url=attrs.get("url", ""),
                        package_name=attrs.get("name", ""),
                        package_version=package_versions,
                        fixed_in=fixed_in or None,
                        identifiers=identifiers,
                        cvss_score=cvss_score,
                        issue_type="vuln",
                        key=attrs.get("key", item["id"]),
                    )
                )
        return issues
