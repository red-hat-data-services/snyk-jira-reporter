"""Entry point for snyk-jira-reporter CLI."""

import logging
import sys

from snyk_jira_reporter.cli.application import SnykJiraReporterApp
from snyk_jira_reporter.cli.args import parse_arguments
from snyk_jira_reporter.cli.config_loader import load_configuration, load_configuration_files
from snyk_jira_reporter.exceptions.exceptions import CLIError, ConfigurationError


def main() -> int:
    """Main entry point for the Snyk to Jira automation script.

    Returns:
        Exit code (0 for success, 1 for fatal error, 2 for configuration error).
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    logger = logging.getLogger(__name__)
    logger.info("Starting snyk-jira-reporter")

    try:
        # Load configuration and parse arguments
        settings = load_configuration()
        cli_args = parse_arguments()
        components_mapping, exclude_files_mapping = load_configuration_files(settings)

        if settings.dry_run:
            logger.info("DRY_RUN mode is enabled")

        # Execute the complete workflow
        app = SnykJiraReporterApp(
            settings=settings,
            cli_args=cli_args,
            components_mapping=components_mapping,
            exclude_files_mapping=exclude_files_mapping,
        )

        return app.execute()

    except ConfigurationError as e:
        logger.error("Configuration error: %s", e)
        return 2
    except CLIError as e:
        logger.error("Command-line error: %s", e)
        return 2
    except Exception as e:
        logger.exception("Unexpected error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
