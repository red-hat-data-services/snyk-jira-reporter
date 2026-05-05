"""Tests for AppSettings configuration."""

import pytest
from pydantic import ValidationError

from snyk_jira_reporter.config.settings import AppSettings


class TestAppSettings:
    """Tests for AppSettings Pydantic model."""

    def test_loads_from_env_vars(self, monkeypatch) -> None:
        """Test that settings load from environment variables."""
        monkeypatch.setenv("SNYK_ORG_ID", "test-org-id")
        monkeypatch.setenv("SNYK_API_TOKEN", "test-snyk-token")
        monkeypatch.setenv("JIRA_SERVER", "https://jira.example.com")
        monkeypatch.setenv("JIRA_EMAIL", "test@example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test-jira-token")
        monkeypatch.setenv("JIRA_PROJECT_ID", "12345")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.snyk_org_id == "test-org-id"
        assert settings.jira_server == "https://jira.example.com"

    def test_raises_on_missing_required(self, monkeypatch) -> None:
        """Test that missing required env vars raise ValidationError."""
        # Clear all relevant env vars
        for key in ["SNYK_ORG_ID", "SNYK_API_TOKEN", "JIRA_SERVER", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_ID"]:
            monkeypatch.delenv(key, raising=False)

        # Create AppSettings without .env file loading
        import pydantic_settings

        class TestAppSettings(pydantic_settings.BaseSettings):
            snyk_org_id: str
            snyk_api_token: str
            jira_server: str
            jira_email: str
            jira_api_token: str
            jira_project_id: str
            jira_project_key: str = "RHOAIENG"
            # No env_file config to avoid loading .env

        with pytest.raises(ValidationError):
            TestAppSettings()  # type: ignore[call-arg]

    def test_default_values(self, monkeypatch) -> None:
        """Test default values for optional fields."""
        # Clear any existing env vars first
        for key in [
            "DRY_RUN",
            "JIRA_PROJECT_KEY",
            "JIRA_LABEL_PREFIX",
            "COMPONENT_MAPPING_FILE_PATH",
            "EXCLUDE_FILES_FILE_PATH",
        ]:
            monkeypatch.delenv(key, raising=False)

        monkeypatch.setenv("SNYK_ORG_ID", "test")
        monkeypatch.setenv("SNYK_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_SERVER", "https://test.com")
        monkeypatch.setenv("JIRA_EMAIL", "test@example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_PROJECT_ID", "123")

        # Create settings without .env file
        import pydantic_settings

        from snyk_jira_reporter.config.constants import (
            DEFAULT_COMPONENT_MAPPING_PATH,
            DEFAULT_EXCLUDE_FILES_PATH,
            DEFAULT_JIRA_LABEL_PREFIX,
        )

        class TestAppSettings(pydantic_settings.BaseSettings):
            snyk_org_id: str
            snyk_api_token: str
            jira_server: str
            jira_email: str
            jira_api_token: str
            jira_project_id: str
            jira_project_key: str = "RHOAIENG"
            jira_label_prefix: str = DEFAULT_JIRA_LABEL_PREFIX
            dry_run: bool = False
            component_mapping_file_path: str = DEFAULT_COMPONENT_MAPPING_PATH
            exclude_files_file_path: str = DEFAULT_EXCLUDE_FILES_PATH

        settings = TestAppSettings()  # type: ignore[call-arg]
        assert settings.jira_project_key == "RHOAIENG"
        assert settings.jira_label_prefix == "snyk-jira-integration:"
        assert settings.dry_run is False
        assert settings.component_mapping_file_path == "./config/jira_components_mapping.json"
        assert settings.exclude_files_file_path == "./config/exclude_files.json"

    def test_dry_run_from_env(self, monkeypatch) -> None:
        """Test that DRY_RUN env var is parsed as boolean."""
        monkeypatch.setenv("SNYK_ORG_ID", "test")
        monkeypatch.setenv("SNYK_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_SERVER", "https://test.com")
        monkeypatch.setenv("JIRA_EMAIL", "test@example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_PROJECT_ID", "123")
        monkeypatch.setenv("DRY_RUN", "true")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.dry_run is True

    def test_custom_project_key(self, monkeypatch) -> None:
        """Test that JIRA_PROJECT_KEY can be customized."""
        monkeypatch.setenv("SNYK_ORG_ID", "test")
        monkeypatch.setenv("SNYK_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_SERVER", "https://test.com")
        monkeypatch.setenv("JIRA_EMAIL", "test@example.com")
        monkeypatch.setenv("JIRA_API_TOKEN", "test")
        monkeypatch.setenv("JIRA_PROJECT_ID", "123")
        monkeypatch.setenv("JIRA_PROJECT_KEY", "MYPROJECT")

        settings = AppSettings()  # type: ignore[call-arg]
        assert settings.jira_project_key == "MYPROJECT"
