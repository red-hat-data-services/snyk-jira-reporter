"""Tests for parsing utilities."""

from snyk_jira_reporter.utils.parsing import exclude_file, parse_file_name, parse_project_name


class TestParseProjectName:
    """Tests for parse_project_name function."""

    def test_standard_project_name(self):
        """Test parsing a standard Snyk project name."""
        result = parse_project_name("red-hat-data-services/kserve(main):Dockerfile", "main")
        assert result == "red-hat-data-services/kserve"

    def test_project_name_without_branch_suffix(self):
        """Test parsing when branch suffix is not present."""
        result = parse_project_name("red-hat-data-services/kserve:Dockerfile", "main")
        assert result == "red-hat-data-services/kserve"

    def test_project_name_with_different_branch(self):
        """Test parsing with a non-main branch."""
        result = parse_project_name("org/repo(release-1.0):path/file.py", "release-1.0")
        assert result == "org/repo"


class TestParseFileName:
    """Tests for parse_file_name function."""

    def test_standard_file_name(self):
        """Test extracting file path from project name."""
        result = parse_file_name("red-hat-data-services/kserve(main):Dockerfile")
        assert result == "Dockerfile"

    def test_nested_file_path(self):
        """Test extracting a nested file path."""
        result = parse_file_name("org/repo:path/to/requirements.txt")
        assert result == "path/to/requirements.txt"

    def test_no_colon(self):
        """Test when there's no colon separator."""
        result = parse_file_name("org/repo")
        assert result == ""


class TestExcludeFile:
    """Tests for exclude_file function."""

    def test_matching_pattern(self):
        """Test file matches an exclusion pattern."""
        assert exclude_file("vendor/golang.org/x/net", [r"^vendor/"]) is True

    def test_no_matching_pattern(self):
        """Test file does not match any pattern."""
        assert exclude_file("main.go", [r"^vendor/", r"^tests/"]) is False

    def test_regex_pattern(self):
        """Test complex regex pattern matching."""
        assert exclude_file("modules/ssh/vendor/lib.go", [r"^modules/.*/vendor"]) is True

    def test_empty_exclusion_list(self):
        """Test with no exclusion patterns."""
        assert exclude_file("any/file.py", []) is False
