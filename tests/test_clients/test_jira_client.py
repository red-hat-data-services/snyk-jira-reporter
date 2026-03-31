"""Tests for JiraClient."""

from unittest.mock import patch

from snyk_jira_reporter.clients.jira_client import JiraClient


class TestJiraClientCreateIssues:
    """Tests for JiraClient.create_jira_issues."""

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_dry_run_returns_count(self, mock_jira_class, sample_vulnerability):
        """Test that dry run mode returns count without creating issues."""
        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=True,
        )
        count = client.create_jira_issues([sample_vulnerability], "12345", "proj-1", "org-slug")
        assert count == 1
        mock_jira_class.return_value.create_issues.assert_not_called()

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_creates_issues_with_correct_fields(self, mock_jira_class, sample_vulnerability):
        """Test that Jira issues are created with correct field structure."""
        mock_client = mock_jira_class.return_value
        mock_client.create_issues.return_value = [{"issue": "TEST-1"}]

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )
        count = client.create_jira_issues([sample_vulnerability], "12345", "proj-1", "org-slug")

        call_args = mock_client.create_issues.call_args[0][0]
        assert len(call_args) == 1
        issue = call_args[0]
        assert issue["issuetype"] == {"name": "Bug"}
        assert issue["security"] == {"id": "11697"}
        assert "snyk" in issue["labels"]
        assert count == 1

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_partial_batch_failure(self, mock_jira_class, sample_vulnerability, sample_vulnerability_no_cve):
        """Test that partial batch failures return only successful count."""
        mock_client = mock_jira_class.return_value
        mock_client.create_issues.return_value = [
            {"issue": "TEST-1"},
            {"error": "Summary field too long"},
        ]

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )
        count = client.create_jira_issues(
            [sample_vulnerability, sample_vulnerability_no_cve], "12345", "proj-1", "org-slug"
        )
        assert count == 1


class TestJiraClientGetExisting:
    """Tests for JiraClient.get_existing_jira_for_project."""

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_builds_jql_with_project_key(self, mock_jira_class):
        """Test that JQL uses configurable project key."""
        mock_client = mock_jira_class.return_value
        mock_client.search_issues.return_value = {"issues": []}

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="MYPROJECT",
            component_mapping={"org/repo": "Component"},
            dry_run=False,
        )
        client.get_existing_jira_for_project("org/repo", "file.py", "main")

        jql = mock_client.search_issues.call_args[0][0]
        assert "project = MYPROJECT" in jql
        assert 'component = "Component"' in jql

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_jql_without_component(self, mock_jira_class):
        """Test JQL when project has no component mapping."""
        mock_client = mock_jira_class.return_value
        mock_client.search_issues.return_value = {"issues": []}

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )
        client.get_existing_jira_for_project("unknown/repo", "file.py", "main")

        jql = mock_client.search_issues.call_args[0][0]
        assert "component" not in jql
