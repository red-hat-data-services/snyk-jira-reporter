"""Tests for label and priority utilities."""

from snyk_jira_reporter.utils.labels import create_labels, get_jira_priority


class TestCreateLabels:
    """Tests for create_labels function."""

    def test_labels_with_cve_and_cwe(self, sample_vulnerability):
        """Test labels include CVE and CWE identifiers."""
        labels = create_labels(sample_vulnerability)
        assert "snyk" in labels
        assert "security" in labels
        assert "cve" in labels
        assert "CVE-2023-12345" in labels
        assert "cwe" in labels
        assert "CWE-94" in labels

    def test_labels_vuln_issue_type(self, sample_vulnerability):
        """Test labels include 'dependency' for vuln type."""
        labels = create_labels(sample_vulnerability)
        assert "dependency" in labels
        assert "code-analysis" not in labels

    def test_labels_code_issue_type(self, sample_vulnerability_no_cve):
        """Test labels include 'code-analysis' for code type."""
        labels = create_labels(sample_vulnerability_no_cve)
        assert "code-analysis" in labels
        assert "dependency" not in labels

    def test_labels_no_identifiers(self, sample_vulnerability_no_cve):
        """Test labels include 'vuln' when no CVE/CWE identifiers."""
        labels = create_labels(sample_vulnerability_no_cve)
        assert "vuln" in labels
        assert "cve" not in labels
        assert "cwe" not in labels


class TestGetJiraPriority:
    """Tests for get_jira_priority function."""

    def test_critical(self):
        assert get_jira_priority("critical") == {"name": "Critical"}

    def test_high(self):
        assert get_jira_priority("high") == {"name": "Major"}

    def test_medium(self):
        assert get_jira_priority("medium") == {"name": "Normal"}

    def test_low(self):
        assert get_jira_priority("low") == {"name": "Minor"}

    def test_unknown_defaults_to_minor(self):
        assert get_jira_priority("unknown") == {"name": "Minor"}
