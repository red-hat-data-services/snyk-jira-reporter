"""Pydantic models for Snyk REST API data structures."""

from pydantic import BaseModel


class SnykProject(BaseModel):
    """A Snyk project from the REST API.

    Maps from the REST API response format:
    - name: project name (e.g. 'org/repo(branch):path/to/file')
    - type: project type (e.g. 'pip', 'npm', 'sast', 'maven')
    - status: 'active' or 'inactive' (replaces V1 isMonitored)
    - target_reference: branch name (replaces V1 branch)
    """

    id: str
    name: str
    type: str
    status: str
    target_reference: str | None = None
    org_slug: str = ""

    @property
    def is_monitored(self) -> bool:
        """Check if the project is actively monitored."""
        return self.status == "active"

    @property
    def branch(self) -> str:
        """Get the branch name (target_reference)."""
        return self.target_reference or ""


class SnykIssue(BaseModel):
    """A vulnerability issue from the Snyk REST API.

    Represents both package_vulnerability and code issue types
    from GET /rest/orgs/{org_id}/issues.
    """

    id: str
    type: str
    title: str
    severity: str
    url: str = ""
    package_name: str = ""
    package_version: list[str] | str = ""
    fixed_in: list[str] | None = None
    identifiers: dict[str, list[str]] = {}  # noqa: RUF012
    cvss_score: float | str | None = None
    issue_type: str = ""
    key: str = ""
    source_file: str = ""
    source_line: int | None = None
