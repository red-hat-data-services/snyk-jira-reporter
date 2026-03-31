"""Custom exception hierarchy for snyk-jira-reporter."""


class SnykJiraReporterError(Exception):
    """Base exception for snyk-jira-reporter."""


class SnykClientError(SnykJiraReporterError):
    """Raised when Snyk API operations fail."""


class JiraClientError(SnykJiraReporterError):
    """Raised when Jira API operations fail."""


class ConfigurationError(SnykJiraReporterError):
    """Raised when required configuration is missing or invalid."""


class FileLoadError(SnykJiraReporterError):
    """Raised when a configuration file cannot be loaded."""
