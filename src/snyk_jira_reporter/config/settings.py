"""Application settings loaded from environment variables via Pydantic."""

from pydantic_settings import BaseSettings

from snyk_jira_reporter.config.constants import (
    DEFAULT_COMPONENT_MAPPING_PATH,
    DEFAULT_EXCLUDE_FILES_PATH,
    DEFAULT_JIRA_LABEL_PREFIX,
)


class AppSettings(BaseSettings):
    """Application configuration loaded from environment variables.

    All fields map to environment variable names (case-insensitive).
    Required fields will raise a validation error if not set.
    """

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

    model_config = {"env_file": ".env"}
