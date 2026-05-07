"""CLI argument parsing and validation for snyk-jira-reporter."""

import argparse
from dataclasses import dataclass

from snyk_jira_reporter.config.constants import (
    DEFAULT_SNYK_REST_API_VERSION,
    DEFAULT_SNYK_RESULT_LIMIT,
    SEVERITY_PRIORITY_MAP,
)
from snyk_jira_reporter.exceptions.exceptions import CLIError


@dataclass
class CliArguments:
    """Validated CLI arguments for snyk-jira-reporter."""

    limit: int
    api_version: str
    allowed_severities: list[str]
    disable_dep_analysis: bool

    @classmethod
    def from_namespace(cls, args: argparse.Namespace) -> "CliArguments":
        """Convert argparse.Namespace to validated CliArguments.

        Args:
            args: Parsed command-line arguments.

        Returns:
            Validated CliArguments instance.

        Raises:
            CLIError: If any arguments are invalid.
        """
        # Parse and validate severity levels
        allowed_severities = _validate_severity_levels(args.allowed_severity)

        return cls(
            limit=args.limit,
            api_version=args.version,
            allowed_severities=allowed_severities,
            disable_dep_analysis=args.disable_dep_analysis,
        )


def _create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(description="Snyk to Jira automation script")

    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        help="The number of results to be returned by the snyk scan",
        nargs="?",
        default=DEFAULT_SNYK_RESULT_LIMIT,
    )

    parser.add_argument(
        "-v",
        "--version",
        type=str,
        help="The rest api version of snyk",
        nargs="?",
        default=DEFAULT_SNYK_REST_API_VERSION,
    )

    parser.add_argument(
        "-s",
        "--allowed-severity",
        type=str,
        help="A comma separated list of severities of the vulnerabilities to record. eg: critical,high",
        nargs="?",
        default="critical,high",
    )

    parser.add_argument(
        "--disable-dep-analysis",
        action="store_true",
        dest="disable_dep_analysis",
        help="Disable dependency analysis (only perform SAST scanning)",
    )

    return parser


def _validate_severity_levels(severity_string: str) -> list[str]:
    """Validate that all provided severity levels are valid.

    Args:
        severity_string: Comma-separated severity levels.

    Returns:
        List of validated severity levels.

    Raises:
        CLIError: If any severity level is invalid.
    """
    severities = [s.strip() for s in severity_string.split(",")]
    invalid_severities = [s for s in severities if s not in SEVERITY_PRIORITY_MAP]

    if invalid_severities:
        raise CLIError(
            f"Invalid severity level(s): {', '.join(invalid_severities)}. "
            f"Valid values: {', '.join(SEVERITY_PRIORITY_MAP)}"
        )

    return severities


def parse_arguments(args: list[str] | None = None) -> CliArguments:
    """Parse and validate command-line arguments.

    Args:
        args: Command-line arguments. If None, uses sys.argv.

    Returns:
        Validated CliArguments instance.

    Raises:
        CLIError: If any arguments are invalid.
    """
    parser = _create_argument_parser()
    parsed_args = parser.parse_args(args)
    return CliArguments.from_namespace(parsed_args)
