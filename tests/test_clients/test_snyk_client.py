"""Tests for SnykClient."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from snyk_jira_reporter.clients.snyk_client import SnykClient
from snyk_jira_reporter.exceptions.exceptions import SnykClientError


@pytest.fixture
def snyk_client():
    """Create a SnykClient instance with a mocked session for testing."""
    with patch("snyk_jira_reporter.clients.snyk_client._create_session") as mock_create:
        mock_session = MagicMock()
        mock_create.return_value = mock_session
        client = SnykClient(api_token="test-token", api_version="2024-01-23", result_limit="100")
    return client


class TestPaginate:
    """Tests for _paginate method."""

    def test_single_page(self, snyk_client):
        """Test fetching results with a single page response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": [{"id": "item-1"}, {"id": "item-2"}],
            "links": {},
        }
        snyk_client.session.get.return_value = mock_response

        results = snyk_client._paginate("https://api.snyk.io/rest/test", {"version": "2024-01-23"})
        assert len(results) == 2
        assert results[0]["id"] == "item-1"

    def test_multiple_pages(self, snyk_client):
        """Test fetching results across multiple pages."""
        page1 = MagicMock()
        page1.json.return_value = {
            "data": [{"id": "item-1"}],
            "links": {"next": "/rest/orgs/org-id/issues?page=2"},
        }
        page2 = MagicMock()
        page2.json.return_value = {
            "data": [{"id": "item-2"}],
            "links": {},
        }
        snyk_client.session.get.side_effect = [page1, page2]

        results = snyk_client._paginate("https://api.snyk.io/rest/test", {"version": "2024-01-23"})
        assert len(results) == 2
        assert results[0]["id"] == "item-1"
        assert results[1]["id"] == "item-2"

    def test_empty_response(self, snyk_client):
        """Test handling empty API response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": None, "links": {}}
        snyk_client.session.get.return_value = mock_response

        results = snyk_client._paginate("https://api.snyk.io/rest/test", {})
        assert len(results) == 0

    def test_includes_timeout(self, snyk_client):
        """Test that requests include a timeout parameter."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": [], "links": {}}
        snyk_client.session.get.return_value = mock_response

        snyk_client._paginate("https://api.snyk.io/rest/test", {})
        _, kwargs = snyk_client.session.get.call_args
        assert "timeout" in kwargs

    def test_raises_on_http_error(self, snyk_client):
        """Test that HTTP errors are raised as SnykClientError."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
        snyk_client.session.get.return_value = mock_response

        with pytest.raises(SnykClientError, match="Snyk API request failed"):
            snyk_client._paginate("https://api.snyk.io/rest/test", {})

    def test_raises_on_invalid_json(self, snyk_client):
        """Test that non-JSON responses are raised as SnykClientError."""
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("No JSON")
        snyk_client.session.get.return_value = mock_response

        with pytest.raises(SnykClientError, match="invalid JSON"):
            snyk_client._paginate("https://api.snyk.io/rest/test", {})

    def test_next_link_url_construction(self, snyk_client):
        """Test that next link is correctly joined with base URL."""
        page1 = MagicMock()
        page1.json.return_value = {
            "data": [{"id": "1"}],
            "links": {"next": "/rest/orgs/org-id/issues?starting_after=abc"},
        }
        page2 = MagicMock()
        page2.json.return_value = {"data": [{"id": "2"}], "links": {}}
        snyk_client.session.get.side_effect = [page1, page2]

        snyk_client._paginate("https://api.snyk.io/rest/test", {})
        second_call_url = snyk_client.session.get.call_args_list[1][0][0]
        assert second_call_url == "https://api.snyk.io/rest/orgs/org-id/issues?starting_after=abc"


class TestGetOrgSlug:
    """Tests for get_org_slug method."""

    def test_returns_slug(self, snyk_client):
        """Test successful org slug retrieval."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {"attributes": {"slug": "my-org"}}
        }
        snyk_client.session.get.return_value = mock_response

        slug = snyk_client.get_org_slug("org-123")
        assert slug == "my-org"

    def test_raises_on_failure(self, snyk_client):
        """Test SnykClientError on API failure."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {}}
        snyk_client.session.get.return_value = mock_response

        with pytest.raises(SnykClientError):
            snyk_client.get_org_slug("org-123")


class TestListProjects:
    """Tests for list_projects method."""

    @patch.object(SnykClient, "get_org_slug", return_value="test-org")
    @patch.object(SnykClient, "_paginate")
    def test_returns_snyk_projects(self, mock_paginate, mock_slug, snyk_client):
        """Test that list_projects returns SnykProject models."""
        mock_paginate.return_value = [
            {
                "id": "proj-1",
                "attributes": {
                    "name": "org/repo(main):Dockerfile",
                    "type": "pip",
                    "status": "active",
                    "target_reference": "main",
                },
            }
        ]

        projects = snyk_client.list_projects("org-123")
        assert len(projects) == 1
        assert projects[0].id == "proj-1"
        assert projects[0].name == "org/repo(main):Dockerfile"
        assert projects[0].type == "pip"
        assert projects[0].is_monitored is True
        assert projects[0].branch == "main"
        assert projects[0].org_slug == "test-org"

    @patch.object(SnykClient, "get_org_slug", return_value="test-org")
    @patch.object(SnykClient, "_paginate", return_value=[])
    def test_empty_projects(self, mock_paginate, mock_slug, snyk_client):
        """Test list_projects with no projects."""
        projects = snyk_client.list_projects("org-123")
        assert len(projects) == 0


class TestGetIssues:
    """Tests for get_issues method."""

    @patch.object(SnykClient, "_paginate")
    def test_package_vulnerability_issues(self, mock_paginate, snyk_client):
        """Test parsing package_vulnerability issues."""
        mock_paginate.return_value = [
            {
                "id": "SNYK-PYTHON-REQUESTS-123",
                "attributes": {
                    "title": "RCE in requests",
                    "effective_severity_level": "critical",
                    "url": "https://snyk.io/vuln/SNYK-PYTHON-REQUESTS-123",
                    "name": "requests",
                    "key": "SNYK-PYTHON-REQUESTS-123",
                    "problems": [
                        {"source": "CVE", "id": "CVE-2023-1"},
                        {"source": "CWE", "id": "CWE-94"},
                    ],
                    "coordinates": [
                        {
                            "representations": [{"dependency": {"version": "2.28.0"}}],
                            "remedies": [{"details": {"upgrade_package": "requests@2.31.0"}}],
                        }
                    ],
                    "severities": [{"score": 9.8}],
                },
            }
        ]

        issues = snyk_client.get_issues("org-1", "proj-1", "package_vulnerability")
        assert len(issues) == 1
        issue = issues[0]
        assert issue.id == "SNYK-PYTHON-REQUESTS-123"
        assert issue.title == "RCE in requests"
        assert issue.severity == "critical"
        assert issue.package_name == "requests"
        assert issue.package_version == ["2.28.0"]
        assert issue.fixed_in == ["requests@2.31.0"]
        assert issue.cvss_score == 9.8
        assert issue.identifiers == {"CVE": ["CVE-2023-1"], "CWE": ["CWE-94"]}
        assert issue.issue_type == "vuln"

    @patch.object(SnykClient, "_paginate")
    def test_code_issues(self, mock_paginate, snyk_client):
        """Test parsing code (SAST) issues with source location."""
        mock_paginate.return_value = [
            {
                "id": "code-1",
                "attributes": {
                    "title": "SQL Injection",
                    "effective_severity_level": "high",
                    "key": "sql-key",
                    "classes": [{"id": "CWE-89"}],
                    "coordinates": [
                        {
                            "representations": [
                                {
                                    "sourceLocation": {
                                        "file": "src/db/queries.py",
                                        "region": {
                                            "start": {"line": 42, "column": 5},
                                            "end": {"line": 42, "column": 30},
                                        },
                                    }
                                }
                            ]
                        }
                    ],
                },
            }
        ]

        issues = snyk_client.get_issues("org-1", "proj-1", "code")
        assert len(issues) == 1
        issue = issues[0]
        assert issue.id == "code-1"
        assert issue.title == "SQL Injection"
        assert issue.severity == "high"
        assert issue.issue_type == "code"
        assert issue.identifiers == {"CWE": ["CWE-89"], "CVE": []}
        assert issue.key == "sql-key"
        assert issue.source_file == "src/db/queries.py"
        assert issue.source_line == 42

    @patch.object(SnykClient, "_paginate")
    def test_code_issues_without_coordinates(self, mock_paginate, snyk_client):
        """Test parsing code issues when coordinates are missing."""
        mock_paginate.return_value = [
            {
                "id": "code-2",
                "attributes": {
                    "title": "XSS",
                    "effective_severity_level": "medium",
                    "key": "xss-key",
                    "classes": [{"id": "CWE-79"}],
                },
            }
        ]

        issues = snyk_client.get_issues("org-1", "proj-1", "code")
        assert len(issues) == 1
        assert issues[0].source_file == ""
        assert issues[0].source_line is None

    @patch.object(SnykClient, "_paginate", return_value=[])
    def test_empty_issues(self, mock_paginate, snyk_client):
        """Test get_issues with no results."""
        issues = snyk_client.get_issues("org-1", "proj-1", "package_vulnerability")
        assert len(issues) == 0

    @patch.object(SnykClient, "_paginate")
    def test_package_vulnerability_no_remedies(self, mock_paginate, snyk_client):
        """Test parsing package vulnerability without remedies."""
        mock_paginate.return_value = [
            {
                "id": "SNYK-1",
                "attributes": {
                    "title": "Bug",
                    "effective_severity_level": "medium",
                    "url": "https://snyk.io/vuln/1",
                    "name": "pkg",
                    "key": "SNYK-1",
                    "problems": [],
                    "coordinates": [],
                    "severities": [],
                },
            }
        ]

        issues = snyk_client.get_issues("org-1", "proj-1", "package_vulnerability")
        assert len(issues) == 1
        assert issues[0].fixed_in is None
        assert issues[0].cvss_score is None
        assert issues[0].identifiers == {"CVE": [], "CWE": []}


class TestCreateSession:
    """Tests for _create_session and retry configuration."""

    def test_session_has_retry_adapter(self):
        """Test that the session is configured with retry logic."""
        with patch("snyk_jira_reporter.clients.snyk_client._create_session") as mock_create:
            mock_create.return_value = MagicMock()
            client = SnykClient(api_token="token", api_version="2024-01-23", result_limit="100")
            assert client.session is not None

    def test_real_session_has_retry(self):
        """Test that a real session has retry adapters mounted."""
        from snyk_jira_reporter.clients.snyk_client import _create_session

        session = _create_session({"authorization": "token test"})
        adapter = session.get_adapter("https://api.snyk.io")
        assert adapter.max_retries.total == 3
        assert adapter.max_retries.backoff_factor == 1.0
        assert 429 in adapter.max_retries.status_forcelist
        assert 503 in adapter.max_retries.status_forcelist
        assert adapter.max_retries.respect_retry_after_header is True
