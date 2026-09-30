"""Tests for the application coordinator."""

from unittest.mock import Mock, patch

import pytest

from snyk_jira_reporter.cli.application import SnykJiraReporterApp
from snyk_jira_reporter.exceptions.exceptions import SnykJiraReporterError


def test_report_generation_failure_fails_application() -> None:
    """A missing artifact should make the scheduled run fail."""
    app = SnykJiraReporterApp(Mock(), Mock(), {}, {})

    with (
        patch("snyk_jira_reporter.cli.application.generate_component_report", return_value=1),
        pytest.raises(SnykJiraReporterError, match="Component report generation failed"),
    ):
        app._generate_reports(Mock())
