#!/usr/bin/env python3
"""Generate unmapped repositories report and update README with link."""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from pydantic import ValidationError

    from snyk_jira_reporter.clients.jira_client import JiraClient
    from snyk_jira_reporter.config.settings import AppSettings
    from snyk_jira_reporter.exceptions.exceptions import JiraClientError
    from snyk_jira_reporter.services.component_resolver import _get_unmapped_repositories, generate_component_report
    from snyk_jira_reporter.utils.file_loader import load_component_mapping
except ImportError as e:
    print(f"Error importing application modules: {e}")
    print("Make sure to install the application dependencies: pip install -e .")
    sys.exit(1)


def main() -> int:
    """Main function."""
    parser = argparse.ArgumentParser(description="Generate unmapped repositories report and update README")
    parser.add_argument("--output-json", help="Output unmapped repositories to JSON file (optional)")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    try:
        # Load settings and create Jira client
        settings = AppSettings()

        # Validate required Jira settings early
        if not settings.jira_server or not settings.jira_email or not settings.jira_api_token:
            logging.error("Missing required Jira credentials:")
            logging.error("- JIRA_SERVER: %s", "✓ Set" if settings.jira_server else "✗ Missing")
            logging.error("- JIRA_EMAIL: %s", "✓ Set" if settings.jira_email else "✗ Missing")
            logging.error("- JIRA_API_TOKEN: %s", "✓ Set" if settings.jira_api_token else "✗ Missing")
            logging.error("Please set these environment variables to access Jira")
            return 1

        component_mapping = load_component_mapping(settings.component_mapping_file_path)

        jira_client = JiraClient(
            jira_server=settings.jira_server,
            jira_email=settings.jira_email,
            jira_api_token=settings.jira_api_token,
            jira_label_prefix=settings.jira_label_prefix,
            jira_project_id=settings.jira_project_id,
            jira_project_key=settings.jira_project_key,
            component_mapping=component_mapping,
            dry_run=True,  # Read-only operations
        )

        # Generate the report using the service function (eliminates code duplication)
        result_code = generate_component_report(jira_client, component_mapping)

        # Output to JSON if requested (extra feature of the script)
        if args.output_json:
            # Get unmapped repositories for JSON output
            unmapped_repos = _get_unmapped_repositories(jira_client)

            output_data = {
                "timestamp": datetime.now().isoformat(),
                "unmapped_repositories": unmapped_repos,
                "count": len(unmapped_repos),
            }
            with open(args.output_json, "w") as f:
                json.dump(output_data, f, indent=2)
            logging.info("Wrote unmapped repositories to %s", args.output_json)

        print("Generated component mapping report successfully")
        print("- Created UNMAPPED_REPOSITORIES.md with detailed information")
        print("- Updated README.md with link to the detailed report")
        return result_code

    except (ValidationError, JiraClientError) as e:
        logging.error("Failed to generate report: %s", e)
        return 1
    except Exception as e:
        logging.error("Unexpected error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
