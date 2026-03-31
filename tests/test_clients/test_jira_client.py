"""Tests for JiraClient."""

from unittest.mock import Mock, patch

from snyk_jira_reporter.clients.jira_client import JiraClient


class TestJiraClientCreateIssues:
    """Tests for JiraClient.create_jira_issues."""

    @patch("snyk_jira_reporter.clients.jira_client.JIRA")
    def test_dry_run_returns_count(self, mock_jira_class, sample_vulnerability) -> None:
        """Test that dry run mode returns count without creating issues."""
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
        mock_jira_class.assert_called_once()

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    @patch("snyk_jira_reporter.clients.jira_client.JIRA")  # Still need this to prevent JIRA constructor errors
    def test_creates_issues_with_correct_fields(self, _mock_jira_class, mock_requests, sample_vulnerability) -> None:
        """Test that Jira issues are created with correct field structure."""
        # Mock successful response for issue creation
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"key": "TEST-1"}
        mock_requests.post.return_value = mock_response

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

        # Verify the API call was made correctly
        assert mock_requests.post.called
        call_args = mock_requests.post.call_args
        assert "https://jira.test.com/rest/api/3/issue" in call_args[0][0]

        # Check payload structure
        payload = call_args[1]["json"]
        fields = payload["fields"]
        assert fields["issuetype"]["name"] == "Bug"
        assert fields["security"]["id"] == "10034"
        assert "snyk" in fields["labels"]
        assert count == 1

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    @patch("snyk_jira_reporter.clients.jira_client.JIRA")  # Still need this to prevent JIRA constructor errors
    def test_partial_batch_failure(
        self, _mock_jira_class, mock_requests, sample_vulnerability, sample_vulnerability_no_cve
    ) -> None:
        """Test that partial batch failures return only successful count."""
        # Mock one success and one failure
        mock_success = Mock()
        mock_success.status_code = 201
        mock_success.json.return_value = {"key": "TEST-1"}

        mock_failure = Mock()
        mock_failure.status_code = 400
        mock_failure.text = "Summary field too long"

        mock_requests.post.side_effect = [mock_success, mock_failure]

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

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    @patch("snyk_jira_reporter.clients.jira_client.JIRA")  # Still need this to prevent JIRA constructor errors
    def test_builds_jql_with_project_key(self, _mock_jira_class, mock_requests) -> None:
        """Test that JQL uses configurable project key."""
        # Mock the search response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issues": []}
        mock_requests.get.return_value = mock_response

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
        assert mock_requests.get.called
        call_args = mock_requests.get.call_args

        # The JQL should be passed as a parameter
        params = call_args[1]["params"]
        jql_query = params["jql"]
        assert "project = MYPROJECT" in jql_query
        assert 'component = "Component"' in jql_query

    @patch("snyk_jira_reporter.clients.jira_client.requests")
    @patch("snyk_jira_reporter.clients.jira_client.JIRA")  # Still need this to prevent JIRA constructor errors
    def test_jql_without_component(self, _mock_jira_class, mock_requests) -> None:
        """Test JQL when project has no component mapping."""
        # Mock the search response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"issues": []}
        mock_requests.get.return_value = mock_response

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

        # Check that component is not in the JQL query
        assert mock_requests.get.called
        call_args = mock_requests.get.call_args

        # The JQL should be passed as a parameter without component
        params = call_args[1]["params"]
        jql_query = params["jql"]
        assert "component" not in jql_query
