"""Tests for JiraClient."""

from unittest.mock import Mock, patch

from snyk_jira_reporter.clients.jira_client import JiraClient


class TestJiraClientCreateIssues:
    """Tests for JiraClient.create_jira_issues."""

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_dry_run_returns_count(self, mock_jira_class, sample_vulnerability) -> None:
        """Test that dry run mode returns count without creating issues."""
        # Mock JIRA library
        mock_jira_instance = Mock()
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=True,
        )
        count = client.create_jira_issues([sample_vulnerability], "12345", "proj-1", "org-slug")
        assert count == 1
        # In dry run mode, no API calls should be made
        assert not mock_jira_instance.create_issue.called

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_creates_issues_with_correct_fields(self, mock_requests, mock_jira_class, sample_vulnerability) -> None:
        """Test that Jira issues are created with correct field structure."""
        # Mock JIRA library
        mock_jira_instance = Mock()
        mock_issue = Mock()
        mock_issue.key = "TEST-1"
        mock_jira_instance.create_issue.return_value = mock_issue
        mock_jira_class.return_value = mock_jira_instance

        # Mock successful response for description update
        mock_response = Mock()
        mock_response.status_code = 204
        mock_requests.put.return_value = mock_response

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )
        count = client.create_jira_issues([sample_vulnerability], "12345", "proj-1", "org-slug")

        # Verify the JIRA library create_issue was called
        assert mock_jira_instance.create_issue.called
        call_args = mock_jira_instance.create_issue.call_args
        fields = call_args[1]["fields"]
        assert fields["issuetype"]["name"] == "Bug"
        assert fields["security"]["id"] == "10034"
        assert "snyk" in fields["labels"]

        # Verify description update API call was made
        assert mock_requests.put.called

        assert count == 1

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    @patch("snyk_jira_reporter.clients.jira_client.requests")
    def test_partial_batch_failure(
        self, mock_requests, mock_jira_class, sample_vulnerability, sample_vulnerability_no_cve
    ) -> None:
        """Test that partial batch failures return only successful count."""
        # Mock JIRA library - one success and one failure
        mock_jira_instance = Mock()
        mock_issue = Mock()
        mock_issue.key = "TEST-1"

        # First call succeeds, second call fails
        mock_jira_instance.create_issue.side_effect = [mock_issue, Exception("Summary field too long")]
        mock_jira_class.return_value = mock_jira_instance

        # Mock successful response for description update (only for successful issue)
        mock_response = Mock()
        mock_response.status_code = 204
        mock_requests.put.return_value = mock_response

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
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
    def test_builds_jql_with_project_key(self, mock_jira_class) -> None:
        """Test that JQL uses configurable project key."""
        # Mock JIRA library search
        mock_jira_instance = Mock()
        mock_jira_instance.search_issues.return_value = []
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="MYPROJECT",
            component_mapping={"org/repo": "Component"},
            dry_run=False,
        )
        client.get_existing_jira_for_project("org/repo", "file.py", "main")

        # Check that the JQL query was constructed correctly
        assert mock_jira_instance.search_issues.called
        call_args = mock_jira_instance.search_issues.call_args
        jql_query = call_args[0][0]  # First positional argument
        assert "project = MYPROJECT" in jql_query
        # Component filtering is disabled to prevent missing unmapped issues
        assert "component" not in jql_query

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_jql_without_component(self, mock_jira_class) -> None:
        """Test JQL when project has no component mapping."""
        # Mock JIRA library search
        mock_jira_instance = Mock()
        mock_jira_instance.search_issues.return_value = []
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )
        client.get_existing_jira_for_project("unknown/repo", "file.py", "main")

        # Check that component filtering is disabled
        assert mock_jira_instance.search_issues.called
        call_args = mock_jira_instance.search_issues.call_args
        jql_query = call_args[0][0]  # First positional argument
        assert "component" not in jql_query

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_includes_all_issue_statuses(self, mock_jira_class) -> None:
        """Test that JQL includes all issue statuses to avoid missing unmapped issues."""
        # Mock JIRA library search
        mock_jira_instance = Mock()
        mock_jira_instance.search_issues.return_value = []
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )
        client.get_existing_jira_for_project("test/repo", "file.py", "main")

        # Check that the JQL query does not filter by status
        assert mock_jira_instance.search_issues.called
        call_args = mock_jira_instance.search_issues.call_args
        jql_query = call_args[0][0]  # First positional argument
        assert "status" not in jql_query

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_filters_issues_by_uid_match(self, mock_jira_class) -> None:
        """Test that only issues matching UID criteria are returned."""
        # Mock JIRA issue objects
        mock_issue_matching = Mock()
        mock_issue_matching.key = "TEST-1"
        mock_issue_matching.fields.summary = "Test Issue 1"
        mock_issue_matching.fields.description = (
            "##snyk-jira-uid##snyk-jira-integration:test/repo:file.py:main:123-456-789"
        )
        mock_issue_matching.fields.status.name = "Open"
        mock_issue_matching.fields.components = []
        mock_issue_matching.fields.labels = []

        mock_issue_non_matching = Mock()
        mock_issue_non_matching.key = "TEST-2"
        mock_issue_non_matching.fields.summary = "Test Issue 2"
        mock_issue_non_matching.fields.description = (
            "##snyk-jira-uid##snyk-jira-integration:other/repo:other.py:main:987-654-321"
        )
        mock_issue_non_matching.fields.status.name = "Open"
        mock_issue_non_matching.fields.components = []
        mock_issue_non_matching.fields.labels = []

        # Mock JIRA library search
        mock_jira_instance = Mock()
        mock_jira_instance.search_issues.return_value = [mock_issue_matching, mock_issue_non_matching]
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )

        result = client.get_existing_jira_for_project("test/repo", "file.py", "main")

        # Should return only the matching issue
        assert len(result) == 1
        assert result[0]["key"] == "TEST-1"

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_handles_master_main_branch_normalization(self, mock_jira_class) -> None:
        """Test that master/main branch variations are handled correctly."""
        # Mock JIRA issue created for master branch
        mock_issue = Mock()
        mock_issue.key = "TEST-1"
        mock_issue.fields.summary = "Test Issue"
        mock_issue.fields.description = "##snyk-jira-uid##snyk-jira-integration:test/repo:file.py:master:123-456-789"
        mock_issue.fields.status.name = "Open"
        mock_issue.fields.components = []
        mock_issue.fields.labels = []

        # Mock JIRA library search
        mock_jira_instance = Mock()
        mock_jira_instance.search_issues.return_value = [mock_issue]
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={},
            dry_run=False,
        )

        # Search for main branch should find master branch issue
        result = client.get_existing_jira_for_project("test/repo", "file.py", "main")

        # Should find the master branch issue when searching for main
        assert len(result) == 1
        assert result[0]["key"] == "TEST-1"

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_finds_issues_without_component_when_mapping_exists(self, mock_jira_class) -> None:
        """Test that issues created before component mapping was added are still found.

        This is the regression test for the root cause of duplicate issues:
        when a component mapping is added for a previously unmapped repo,
        the search must still find old issues that have no component set.
        """
        mock_issue_no_component = Mock()
        mock_issue_no_component.key = "TEST-1"
        mock_issue_no_component.fields.summary = "Old issue without component"
        mock_issue_no_component.fields.description = (
            "##snyk-jira-uid##snyk-jira-integration:test/repo:Dockerfile:main:vuln-123"
        )
        mock_issue_no_component.fields.status.name = "Open"
        mock_issue_no_component.fields.components = []
        mock_issue_no_component.fields.labels = []

        mock_jira_instance = Mock()
        mock_jira_instance.search_issues.return_value = [mock_issue_no_component]
        mock_jira_class.return_value = mock_jira_instance

        client = JiraClient(
            jira_server="https://jira.test.com",
            jira_email="test@example.com",
            jira_api_token="token",
            jira_label_prefix="snyk-jira-integration:",
            jira_project_id="12345",
            jira_project_key="TEST",
            component_mapping={"test/repo": "Model Serving"},
            dry_run=False,
        )

        result = client.get_existing_jira_for_project("test/repo", "Dockerfile", "main")

        assert len(result) == 1
        assert result[0]["key"] == "TEST-1"
