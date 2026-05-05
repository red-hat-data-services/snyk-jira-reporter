"""Tests for component resolver service."""

from unittest.mock import Mock

import pytest

from snyk_jira_reporter.exceptions.exceptions import JiraClientError
from snyk_jira_reporter.services.component_resolver import (
    _extract_project_from_uid,
    _extract_uid_from_description,
    resolve_unmapped_issues,
)


class TestComponentResolver:
    """Tests for component resolution functions."""

    @pytest.fixture
    def mock_jira_client(self):
        """Create a mock JiraClient for testing."""
        client = Mock()
        client.component_mapping = {
            "red-hat-data-services/kserve": "Model Serving",
            "red-hat-data-services/dashboard": "Dashboard",
            "red-hat-data-services/unmapped-repo": "",  # Unmapped repository
        }
        client.dry_run = False
        return client

    @pytest.fixture
    def mock_unmapped_issues(self):
        """Mock unmapped issues for testing."""
        return [
            {
                "key": "TEST-1",
                "fields": {
                    "description": (
                        "Issue description\n##snyk-jira-uid##snyk-jira-integration:"
                        "red-hat-data-services/kserve:package.json:main:issue-123\nMore text"
                    )
                },
            },
            {
                "key": "TEST-2",
                "fields": {
                    "description": (
                        "Issue description\n##snyk-jira-uid##snyk-jira-integration:"
                        "red-hat-data-services/dashboard:src/main.py:develop:issue-456\nMore text"
                    )
                },
            },
            {"key": "TEST-3", "fields": {"description": "Issue without UID"}},
        ]

    def test_extract_uid_from_description_success(self):
        """Test successful UID extraction from description."""
        description = "Issue description\n##snyk-jira-uid##snyk-jira-integration:project:file:branch:id\nMore text"
        uid = _extract_uid_from_description(description)
        assert uid == "snyk-jira-integration:project:file:branch:id"

    def test_extract_uid_from_description_no_uid(self):
        """Test UID extraction when no UID is present."""
        description = "Issue description without UID"
        uid = _extract_uid_from_description(description)
        assert uid is None

    def test_extract_uid_from_description_empty(self):
        """Test UID extraction with empty description."""
        uid = _extract_uid_from_description("")
        assert uid is None

    def test_extract_project_from_uid_success(self):
        """Test successful project extraction from UID."""
        uid = "snyk-jira-integration:red-hat-data-services/kserve:package.json:main:issue-123"
        project = _extract_project_from_uid(uid)
        assert project == "red-hat-data-services/kserve"

    def test_extract_project_from_uid_invalid(self):
        """Test project extraction from invalid UID."""
        uid = "invalid-uid"
        project = _extract_project_from_uid(uid)
        assert project is None

    def test_resolve_unmapped_issues_success(self, mock_jira_client, mock_unmapped_issues):
        """Test successful resolution of unmapped issues."""
        # Mock search results
        mock_jira_client.search_issues_by_label.return_value = mock_unmapped_issues[:2]  # Exclude invalid UID issue

        # Component validation happens via component_mapping lookup (no separate method)

        # Mock successful updates
        mock_jira_client.update_issue_component.return_value = None
        mock_jira_client.update_issue_labels.return_value = None

        resolved_count = resolve_unmapped_issues(mock_jira_client)

        assert resolved_count == 2
        mock_jira_client.update_issue_component.assert_any_call("TEST-1", "Model Serving")
        mock_jira_client.update_issue_component.assert_any_call("TEST-2", "Dashboard")
        mock_jira_client.update_issue_labels.assert_any_call("TEST-1", [], ["unmapped-repo"])
        mock_jira_client.update_issue_labels.assert_any_call("TEST-2", [], ["unmapped-repo"])

    def test_resolve_unmapped_issues_no_issues(self, mock_jira_client):
        """Test resolution when no unmapped issues exist."""
        mock_jira_client.search_issues_by_label.return_value = []

        resolved_count = resolve_unmapped_issues(mock_jira_client)

        assert resolved_count == 0
        mock_jira_client.update_issue_component.assert_not_called()

    def test_resolve_unmapped_issues_no_mapping(self, mock_jira_client, mock_unmapped_issues):
        """Test resolution when no component mapping exists for repository."""
        # Set up client with no mapping for the repository
        mock_jira_client.component_mapping = {}  # Empty mapping
        mock_jira_client.search_issues_by_label.return_value = mock_unmapped_issues[:1]

        resolved_count = resolve_unmapped_issues(mock_jira_client)

        assert resolved_count == 0
        mock_jira_client.update_issue_component.assert_not_called()

    def test_resolve_unmapped_issues_search_failure(self, mock_jira_client):
        """Test handling of search failure."""
        mock_jira_client.search_issues_by_label.side_effect = JiraClientError("Search failed")

        with pytest.raises(JiraClientError):
            resolve_unmapped_issues(mock_jira_client)

    def test_resolve_unmapped_issues_update_failure(self, mock_jira_client, mock_unmapped_issues):
        """Test handling of update failure."""
        mock_jira_client.search_issues_by_label.return_value = mock_unmapped_issues[:1]

        # Mock update failure
        mock_jira_client.update_issue_component.side_effect = JiraClientError("Update failed")

        resolved_count = resolve_unmapped_issues(mock_jira_client)

        assert resolved_count == 0  # No issues successfully resolved
