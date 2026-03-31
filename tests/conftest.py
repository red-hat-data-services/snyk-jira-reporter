"""Shared test fixtures for snyk-jira-reporter tests."""

from unittest.mock import MagicMock

import pytest

from snyk_jira_reporter.models.snyk_models import SnykIssue, SnykProject
from snyk_jira_reporter.models.vulnerability import VulnerabilityData


@pytest.fixture
def sample_vulnerability():
    """Create a sample VulnerabilityData instance for testing."""
    return VulnerabilityData(
        id="SNYK-PYTHON-REQUESTS-123456",
        jira_snyk_id="snyk-jira-integration:red-hat-data-services/kserve:Dockerfile:main:SNYK-PYTHON-REQUESTS-123456",
        title="Remote Code Execution in requests",
        url="https://snyk.io/vuln/SNYK-PYTHON-REQUESTS-123456",
        project_branch="main",
        package_name="requests",
        package_version=["2.28.0"],
        fixed_in=["2.31.0"],
        project_name="red-hat-data-services/kserve",
        file_path="Dockerfile",
        component="Model Serving",
        severity="critical",
        cvss_score=9.8,
        identifiers={"CVE": ["CVE-2023-12345"], "CWE": ["CWE-94"]},
        issue_type="vuln",
    )


@pytest.fixture
def sample_vulnerability_no_cve():
    """Create a VulnerabilityData instance without CVE/CWE identifiers."""
    return VulnerabilityData(
        id="SNYK-CODE-123",
        jira_snyk_id="snyk-jira-integration:red-hat-data-services/kserve:app.py:main:SNYK-CODE-123",
        title="SQL Injection",
        url="https://snyk.io/vuln/SNYK-CODE-123",
        project_branch="main",
        package_name="",
        package_version="",
        fixed_in=[],
        project_name="red-hat-data-services/kserve",
        file_path="app.py",
        component="Model Serving",
        severity="high",
        cvss_score=7.5,
        identifiers={"CVE": [], "CWE": []},
        issue_type="code",
    )


@pytest.fixture
def sample_snyk_project():
    """Create a sample SnykProject for testing."""
    return SnykProject(
        id="proj-123",
        name="red-hat-data-services/kserve(main):Dockerfile",
        type="pip",
        status="active",
        target_reference="main",
        org_slug="test-org",
    )


@pytest.fixture
def sample_snyk_issue():
    """Create a sample SnykIssue for testing (package_vulnerability type)."""
    return SnykIssue(
        id="SNYK-PYTHON-REQUESTS-123456",
        type="package_vulnerability",
        title="Remote Code Execution in requests",
        severity="critical",
        url="https://snyk.io/vuln/SNYK-PYTHON-REQUESTS-123456",
        package_name="requests",
        package_version=["2.28.0"],
        fixed_in=["2.31.0"],
        identifiers={"CVE": ["CVE-2023-12345"], "CWE": ["CWE-94"]},
        cvss_score=9.8,
        issue_type="vuln",
        key="SNYK-PYTHON-REQUESTS-123456",
    )


@pytest.fixture
def sample_snyk_code_issue():
    """Create a sample SnykIssue for testing (code/SAST type)."""
    return SnykIssue(
        id="code-issue-1",
        type="code",
        title="SQL Injection",
        severity="high",
        url="",
        identifiers={"CWE": ["CWE-89"], "CVE": []},
        issue_type="code",
        key="issue-key-1",
    )


@pytest.fixture
def sample_jira_issue():
    """Create a sample Jira issue dict with UID section."""
    uid = "snyk-jira-integration:red-hat-data-services/kserve:Dockerfile:main:SNYK-PYTHON-REQUESTS-123456"
    return {
        "key": "RHOAIENG-12345",
        "fields": {
            "description": (
                "##Do not edit this section below##\n"
                "\n"
                f"##snyk-jira-uid##{uid} \n"
                "\n"
                "##Do not edit this section above##\n"
                "\n"
                "Found vulnerability in *red-hat-data-services/kserve* project"
            ),
            "status": {"name": "Open"},
        },
    }


@pytest.fixture
def sample_jira_issue_closed():
    """Create a sample closed Jira issue dict."""
    uid = "snyk-jira-integration:red-hat-data-services/old-project:file.py:main:SNYK-OLD-123"
    return {
        "key": "RHOAIENG-99999",
        "fields": {
            "description": (
                f"##Do not edit this section below##\n\n##snyk-jira-uid##{uid} \n\n##Do not edit this section above##\n"
            ),
            "status": {"name": "Closed"},
        },
    }


@pytest.fixture
def mock_jira_client():
    """Create a mocked JiraClient for testing."""
    client = MagicMock()
    client.jira_label_prefix = "snyk-jira-integration:"
    client.jira_project_id = "12340620"
    client.jira_project_key = "RHOAIENG"
    client.component_mapping = {
        "red-hat-data-services/kserve": "Model Serving",
        "red-hat-data-services/odh-dashboard": "Dashboard",
    }
    client.dry_run = False
    return client
