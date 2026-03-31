"""Jira label and priority utilities."""

from typing import Any

from snyk_jira_reporter.config.constants import SEVERITY_PRIORITY_MAP
from snyk_jira_reporter.models.vulnerability import VulnerabilityData


def create_labels(vulnerability: VulnerabilityData, has_component_mapping: bool = True) -> list[str]:
    """Create Jira labels for a vulnerability.

    Generates a list of labels including security identifiers (CVE, CWE)
    and the issue type (code-analysis or dependency).

    Args:
        vulnerability: The vulnerability to create labels for.
        has_component_mapping: Whether the repo has a component mapping.

    Returns:
        List of label strings.
    """
    labels = ["snyk", "security"]

    # Add label for repos without component mapping
    if not has_component_mapping:
        labels.append("unmapped-repo")
    identifiers = vulnerability.identifiers
    if "CVE" in identifiers and len(identifiers["CVE"]) > 0:
        labels.append("cve")
        labels += identifiers["CVE"]
    if "CWE" in identifiers and len(identifiers["CWE"]) > 0:
        labels.append("cwe")
        labels += identifiers["CWE"]
    if not len(identifiers.get("CVE", [])) and not len(identifiers.get("CWE", [])):
        labels.append("vuln")
    if vulnerability.issue_type == "code":
        labels.append("code-analysis")
    if vulnerability.issue_type == "vuln":
        labels.append("dependency")
    return labels


def get_jira_priority(severity: str) -> dict[str, Any]:
    """Map a vulnerability severity to a Jira priority.

    Args:
        severity: Severity level (critical, high, medium, low).

    Returns:
        Dict with Jira priority name, e.g. {"name": "Critical"}.
    """
    priority_name = SEVERITY_PRIORITY_MAP.get(severity, "Minor")
    return {"name": priority_name}
