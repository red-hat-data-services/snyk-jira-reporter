"""Tests for JiraClient component validation functionality."""

from unittest.mock import Mock, patch

import pytest

from snyk_jira_reporter.clients.jira_client import JiraClient
from snyk_jira_reporter.exceptions.exceptions import JiraClientError


class TestJiraClientComponentValidation:
    """Tests for JiraClient component validation methods."""

    @pytest.fixture
    def jira_client(self):
        """Create a JiraClient for testing."""
        with patch("snyk_jira_reporter.clients.jira_client.JIRA"):
            return JiraClient(
                jira_server="https://jira.test.com",
                jira_email="test@example.com",
                jira_api_token="token",
                jira_label_prefix="snyk-jira-integration:",
                jira_project_id="12345",
                jira_project_key="TEST",
                component_mapping={},
                dry_run=False,
            )

    @pytest.fixture
    def mock_components_response(self):
        """Mock Jira components API response."""
        return [
            {"name": "AI Evaluations", "id": "10001"},
            {"name": "Model Serving", "id": "10002"},
            {"name": "Data Pipelines", "id": "10003"},
        ]

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_list_project_components_success(self, mock_requests, jira_client, mock_components_response):
        """Test successful fetching of project components."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_components_response
        mock_requests.get.return_value = mock_response

        components = jira_client.list_project_components()

        assert components == ["AI Evaluations", "Model Serving", "Data Pipelines"]
        mock_requests.get.assert_called_once()

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_list_project_components_caching(self, mock_requests, jira_client, mock_components_response):
        """Test that component list is cached after first call."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_components_response
        mock_requests.get.return_value = mock_response

        # First call
        components1 = jira_client.list_project_components()
        # Second call
        components2 = jira_client.list_project_components()

        assert components1 == components2
        # API should only be called once due to caching
        mock_requests.get.assert_called_once()

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_list_project_components_api_failure(self, mock_requests, jira_client):
        """Test handling of API failure when fetching components."""
        # Mock failed API response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.raise_for_status.side_effect = Exception("API Error")
        mock_requests.get.return_value = mock_response

        with pytest.raises(JiraClientError, match="Failed to fetch project components via API v3"):
            jira_client.list_project_components()

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_validate_component_exists_valid(self, mock_requests, jira_client, mock_components_response):
        """Test validation of existing component."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_components_response
        mock_requests.get.return_value = mock_response

        assert jira_client.validate_component_exists("Model Serving") is True
        assert jira_client.validate_component_exists("Invalid Component") is False

    def test_get_component_creation_url(self, jira_client):
        """Test generation of component creation URL."""
        url = jira_client.get_component_creation_url()
        expected = "https://jira.test.com/plugins/servlet/project-config/TEST/administer-components"
        assert url == expected


class TestJiraClientIssueOperations:
    """Tests for JiraClient issue search and update methods."""

    @pytest.fixture
    def jira_client(self):
        """Create a JiraClient for testing."""
        with patch("snyk_jira_reporter.clients.jira_client.JIRA"):
            return JiraClient(
                jira_server="https://jira.test.com",
                jira_email="test@example.com",
                jira_api_token="token",
                jira_label_prefix="snyk-jira-integration:",
                jira_project_id="12345",
                jira_project_key="TEST",
                component_mapping={},
                dry_run=False,
            )

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_search_issues_by_label_success(self, mock_requests, jira_client):
        """Test successful search for issues by label."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "issues": [
                {
                    "key": "TEST-1",
                    "fields": {
                        "summary": "Test Issue 1",
                        "description": "Description 1",
                        "status": {"name": "Open"},
                        "components": [],
                        "labels": ["unmapped-repo", "snyk"],
                    },
                },
                {
                    "key": "TEST-2",
                    "fields": {
                        "summary": "Test Issue 2",
                        "description": "Description 2",
                        "status": {"name": "Closed"},
                        "components": [],
                        "labels": ["unmapped-repo", "security"],
                    },
                },
            ],
            "total": 2,
        }
        mock_requests.get.return_value = mock_response

        issues = jira_client.search_issues_by_label("unmapped-repo")

        assert len(issues) == 2
        assert issues[0]["key"] == "TEST-1"
        assert issues[1]["key"] == "TEST-2"
        assert "unmapped-repo" in issues[0]["fields"]["labels"]

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_search_issues_by_label_empty_result(self, mock_requests, jira_client):
        """Test search for issues by label with no results."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issues": [], "total": 0}
        mock_requests.get.return_value = mock_response

        issues = jira_client.search_issues_by_label("nonexistent-label")

        assert len(issues) == 0

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_search_issues_by_label_api_failure(self, mock_requests, jira_client):
        """Test handling of API failure during issue search."""
        mock_requests.get.side_effect = Exception("Search API Error")

        with pytest.raises(JiraClientError, match="Failed to search issues by label via REST API v3"):
            jira_client.search_issues_by_label("unmapped-repo")

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_update_issue_component_success(self, mock_requests, jira_client):
        """Test successful component update."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 204
        mock_requests.put.return_value = mock_response

        jira_client.update_issue_component("TEST-1", "Model Serving")

        mock_requests.put.assert_called_once()
        call_args = mock_requests.put.call_args
        assert "TEST-1" in call_args[0][0]  # URL is first positional argument
        assert call_args[1]["json"]["fields"]["components"] == [{"name": "Model Serving"}]

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_update_issue_component_dry_run(self, mock_requests, jira_client):
        """Test component update in dry run mode."""
        jira_client.dry_run = True

        jira_client.update_issue_component("TEST-1", "Model Serving")

        # No API calls should be made in dry run mode
        mock_requests.put.assert_not_called()

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_update_issue_component_api_failure(self, mock_requests, jira_client):
        """Test handling of API failure during component update."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_response.raise_for_status.side_effect = Exception("Update failed")
        mock_requests.put.return_value = mock_response

        with pytest.raises(JiraClientError, match="Failed to update issue component via API v3"):
            jira_client.update_issue_component("TEST-1", "Model Serving")

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_update_issue_labels_success(self, mock_requests, jira_client):
        """Test successful label update."""
        # Mock current issue state
        mock_issue = Mock()
        mock_issue.fields.labels = ["snyk", "unmapped-repo", "security"]
        jira_client.jira.issue.return_value = mock_issue

        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 204
        mock_requests.put.return_value = mock_response

        jira_client.update_issue_labels("TEST-1", ["new-label"], ["unmapped-repo"])

        mock_requests.put.assert_called_once()
        call_args = mock_requests.put.call_args

        # Check that labels were updated correctly
        updated_labels = call_args[1]["json"]["fields"]["labels"]
        assert "new-label" in updated_labels
        assert "unmapped-repo" not in updated_labels
        assert "snyk" in updated_labels
        assert "security" in updated_labels

    def test_update_issue_labels_dry_run(self, jira_client):
        """Test label update in dry run mode."""
        jira_client.dry_run = True

        jira_client.update_issue_labels("TEST-1", ["new-label"], ["old-label"])

        # No API calls should be made in dry run mode
        jira_client.jira.issue.assert_not_called()
