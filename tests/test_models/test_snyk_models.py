"""Tests for Snyk data models."""

from snyk_jira_reporter.models.snyk_models import SnykIssue, SnykProject


class TestSnykProject:
    """Tests for SnykProject model."""

    def test_construction(self):
        """Test SnykProject construction with all fields."""
        project = SnykProject(
            id="proj-1",
            name="org/repo(main):Dockerfile",
            type="pip",
            status="active",
            target_reference="main",
            org_slug="my-org",
        )
        assert project.id == "proj-1"
        assert project.name == "org/repo(main):Dockerfile"
        assert project.type == "pip"
        assert project.org_slug == "my-org"

    def test_is_monitored_active(self):
        """Test is_monitored returns True for active projects."""
        project = SnykProject(id="1", name="test", type="pip", status="active")
        assert project.is_monitored is True

    def test_is_monitored_inactive(self):
        """Test is_monitored returns False for inactive projects."""
        project = SnykProject(id="1", name="test", type="pip", status="inactive")
        assert project.is_monitored is False

    def test_branch_from_target_reference(self):
        """Test branch property returns target_reference."""
        project = SnykProject(id="1", name="test", type="pip", status="active", target_reference="develop")
        assert project.branch == "develop"

    def test_branch_defaults_to_empty_string(self):
        """Test branch returns empty string when target_reference is None."""
        project = SnykProject(id="1", name="test", type="pip", status="active")
        assert project.branch == ""

    def test_default_org_slug(self):
        """Test org_slug defaults to empty string."""
        project = SnykProject(id="1", name="test", type="pip", status="active")
        assert project.org_slug == ""


class TestSnykIssue:
    """Tests for SnykIssue model."""

    def test_construction_with_required_fields(self):
        """Test SnykIssue with only required fields."""
        issue = SnykIssue(
            id="SNYK-123",
            type="package_vulnerability",
            title="Test Vulnerability",
            severity="high",
        )
        assert issue.id == "SNYK-123"
        assert issue.severity == "high"
        assert issue.url == ""
        assert issue.package_name == ""
        assert issue.fixed_in is None
        assert issue.cvss_score is None

    def test_construction_with_all_fields(self, sample_snyk_issue):
        """Test SnykIssue construction with all fields."""
        assert sample_snyk_issue.id == "SNYK-PYTHON-REQUESTS-123456"
        assert sample_snyk_issue.type == "package_vulnerability"
        assert sample_snyk_issue.title == "Remote Code Execution in requests"
        assert sample_snyk_issue.severity == "critical"
        assert sample_snyk_issue.package_name == "requests"
        assert sample_snyk_issue.package_version == ["2.28.0"]
        assert sample_snyk_issue.fixed_in == ["2.31.0"]
        assert sample_snyk_issue.cvss_score == 9.8
        assert sample_snyk_issue.identifiers == {"CVE": ["CVE-2023-12345"], "CWE": ["CWE-94"]}
        assert sample_snyk_issue.issue_type == "vuln"

    def test_code_issue(self, sample_snyk_code_issue):
        """Test SnykIssue for code/SAST type."""
        assert sample_snyk_code_issue.type == "code"
        assert sample_snyk_code_issue.issue_type == "code"
        assert sample_snyk_code_issue.url == ""
        assert sample_snyk_code_issue.key == "issue-key-1"
        assert sample_snyk_code_issue.identifiers == {"CWE": ["CWE-89"], "CVE": []}

    def test_default_identifiers(self):
        """Test SnykIssue defaults identifiers to empty dict."""
        issue = SnykIssue(id="1", type="code", title="test", severity="low")
        assert issue.identifiers == {}
