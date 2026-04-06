"""Tests for file loading utilities."""

import json
import os

import pytest

from snyk_jira_reporter.exceptions.exceptions import FileLoadError
from snyk_jira_reporter.utils.file_loader import load_component_mapping, load_mapping


class TestLoadMapping:
    """Tests for load_mapping function."""

    def test_load_valid_json(self, tmp_path):
        """Test loading a valid JSON file."""
        data = {"key": "value", "nested": {"a": 1}}
        json_file = tmp_path / "test.json"
        json_file.write_text(json.dumps(data))

        result = load_mapping(str(json_file))
        assert result == data

    def test_file_not_found_raises_error(self):
        """Test that a missing file raises FileLoadError."""
        with pytest.raises(FileLoadError, match="not found"):
            load_mapping("/nonexistent/path/file.json")

    def test_invalid_json_raises_error(self, tmp_path):
        """Test that invalid JSON raises FileLoadError."""
        json_file = tmp_path / "bad.json"
        json_file.write_text("{ invalid json }")

        with pytest.raises(FileLoadError, match="Invalid JSON"):
            load_mapping(str(json_file))

    def test_load_actual_config_files(self):
        """Test loading the actual project config files."""
        # This test verifies the real config files are valid JSON
        config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "config")
        mapping_path = os.path.join(config_dir, "jira_components_mapping.json")
        if os.path.exists(mapping_path):
            result = load_mapping(mapping_path)
            assert isinstance(result, dict)
            assert len(result) > 0


class TestLoadComponentMapping:
    """Tests for load_component_mapping function."""

    def test_inverts_grouped_format(self, tmp_path):
        """Test that grouped format is inverted to repo -> component."""
        data = {
            "Model Serving": ["org/repo1", "org/repo2"],
            "AI Pipelines": ["org/repo3"],
        }
        json_file = tmp_path / "mapping.json"
        json_file.write_text(json.dumps(data))

        result = load_component_mapping(str(json_file))
        assert result == {
            "org/repo1": "Model Serving",
            "org/repo2": "Model Serving",
            "org/repo3": "AI Pipelines",
        }

    def test_detects_duplicate_repos(self, tmp_path):
        """Test that duplicate repos across components raise FileLoadError."""
        data = {
            "Component A": ["org/repo1"],
            "Component B": ["org/repo1"],
        }
        json_file = tmp_path / "mapping.json"
        json_file.write_text(json.dumps(data))

        with pytest.raises(FileLoadError, match="Duplicate repo"):
            load_component_mapping(str(json_file))

    def test_rejects_non_list_values(self, tmp_path):
        """Test that non-list values raise FileLoadError."""
        data = {"Component A": "org/repo1"}
        json_file = tmp_path / "mapping.json"
        json_file.write_text(json.dumps(data))

        with pytest.raises(FileLoadError, match="Expected a list"):
            load_component_mapping(str(json_file))

    def test_load_actual_component_mapping(self):
        """Test loading the actual grouped component mapping file."""
        config_dir = os.path.join(os.path.dirname(__file__), "..", "..", "config")
        mapping_path = os.path.join(config_dir, "jira_components_mapping.json")
        if os.path.exists(mapping_path):
            result = load_component_mapping(mapping_path)
            assert isinstance(result, dict)
            assert "red-hat-data-services/kserve" in result
            assert result["red-hat-data-services/kserve"] == "Model Serving"
