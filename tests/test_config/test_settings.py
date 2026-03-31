"""Tests for AppSettings configuration."""

import pytest
from pydantic import ValidationError

from snyk_jira_reporter.config.settings import AppSettings


class TestAppSettings:
    """Tests for AppSettings Pydantic model."""

    def test_loads_from_env_vars(self, monkeypatch):
        """Test that settings load from environment variables."""
        monkeypatch.setenv("SNYK_ORG_ID", "test-org-id")
        monkeypatch.setenv("SNYK_API_TOKEN", "test-snyk-token")
        monkeypatch.setenv("JIRA_SERVER", "https://jira.example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test-jira-token")
        monkeypatch.setenv("JIRA_PROJECT_ID", "12345")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.snyk_org_id == "test-org-id"
        assert settings.jira_server == "https://jira.example.com"

    def test_raises_on_missing_required(self, monkeypatch):
        """Test that missing required env vars raise ValidationError."""
        # Clear all relevant env vars
        for key in ["SNYK_ORG_ID", "SNYK_API_TOKEN", "JIRA_SERVER", "JIRA_API_TOKEN", "JIRA_PROJECT_ID"]:
            monkeypatch.delenv(key, raising=False)

        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]

    def test_default_values(self, monkeypatch):
        """Test default values for optional fields."""
        monkeypatch.setenv("SNYK_ORG_ID", "test")
        monkeypatch.setenv("SNYK_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_SERVER", "https://test.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_PROJECT_ID", "123")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.jira_project_key == "RHOAIENG"
        assert settings.jira_label_prefix == "snyk-jira-integration:"
        assert settings.dry_run is False
        assert settings.component_mapping_file_path == "./config/jira_components_mapping.json"
        assert settings.exclude_files_file_path == "./config/exclude_files.json"

    def test_dry_run_from_env(self, monkeypatch):
        """Test that DRY_RUN env var is parsed as boolean."""
        monkeypatch.setenv("SNYK_ORG_ID", "test")
        monkeypatch.setenv("SNYK_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_SERVER", "https://test.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_PROJECT_ID", "123")
        monkeypatch.setenv("DRY_RUN", "true")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.dry_run is True

    def test_custom_project_key(self, monkeypatch):
        """Test that JIRA_PROJECT_KEY can be customized."""
        monkeypatch.setenv("SNYK_ORG_ID", "test")
        monkeypatch.setenv("SNYK_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_SERVER", "https://test.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_PROJECT_ID", "123")
        monkeypatch.setenv("JIRA_PROJECT_KEY", "MYPROJECT")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.jira_project_key == "MYPROJECT"
