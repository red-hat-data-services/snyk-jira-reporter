"""Component resolution service for unmapped Jira issues."""

import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from snyk_jira_reporter.clients.jira_client import JiraClient
from snyk_jira_reporter.config.constants import (
    JIRA_COMMENT_DELAY_SECONDS,
    UID_REGEX,
)
from snyk_jira_reporter.exceptions.exceptions import JiraClientError
from snyk_jira_reporter.utils.adf_parser import extract_text_from_adf

logger = logging.getLogger(__name__)


def _extract_uid_from_description(description: str | dict[str, Any] | None) -> str | None:
    """Extract UID from Jira issue description.

    Args:
        description: Jira issue description text or ADF dict.

    Returns:
        UID string if found, None otherwise.
    """
    if not description:
        return None

    # Handle both string and ADF dict format
    description_text = ""
    if isinstance(description, dict):
        # Extract text from ADF format (same logic as JiraClient)
        description_text = extract_text_from_adf(description)
    elif isinstance(description, str):
        description_text = description
    else:
        description_text = str(description) if description else ""

    # Look for UID pattern in description
    match = re.search(UID_REGEX, description_text)
    return match.group(1) if match else None


def _extract_project_from_uid(uid: str) -> str | None:
    """Extract project name from UID.

    Args:
        uid: UID in format 'prefix:project:file:branch:id'

    Returns:
        Project name if found, None otherwise.
    """
    # UID format: prefix:project:file:branch:id
    parts = uid.split(":")
    if len(parts) >= 2:
        return parts[1]  # project name is second part
    return None


def resolve_unmapped_issues(jira_client: JiraClient) -> int:
    """Resolve unmapped-repo issues by updating components based on current mappings.

    Args:
        jira_client: JiraClient instance with component mapping.

    Returns:
        Number of issues resolved.

    Raises:
        JiraClientError: If API operations fail.
    """
    logger.info("Starting unmapped issue resolution")

    # Find all unmapped-repo issues
    try:
        unmapped_issues = jira_client.search_issues_by_label("unmapped-repo")
    except JiraClientError as e:
        logger.error("Failed to search for unmapped issues: %s", e)
        raise

    if not unmapped_issues:
        logger.info("No unmapped issues found")
        return 0

    logger.info("Found %d unmapped issues to process", len(unmapped_issues))

    resolved_count = 0
    failed_count = 0

    for issue in unmapped_issues:
        issue_key = issue["key"]
        description = issue["fields"].get("description", "")

        logger.debug("Processing unmapped issue: %s", issue_key)

        # Extract project from issue description UID
        uid = _extract_uid_from_description(description)
        if not uid:
            logger.warning("Could not extract UID from issue %s, skipping", issue_key)
            failed_count += 1
            continue

        project_name = _extract_project_from_uid(uid)
        if not project_name:
            logger.warning("Could not extract project from UID in issue %s, skipping", issue_key)
            failed_count += 1
            continue

        # Look up component mapping for this project
        component = jira_client.component_mapping.get(project_name)
        if not component:
            logger.debug("No component mapping found for project '%s' in issue %s", project_name, issue_key)
            continue

        # Update the issue: add component and remove unmapped-repo label
        try:
            # Update component
            jira_client.update_issue_component(issue_key, component)

            # Rate limiting between operations
            time.sleep(JIRA_COMMENT_DELAY_SECONDS)

            # Update labels: remove unmapped-repo
            jira_client.update_issue_labels(issue_key, [], ["unmapped-repo"])

            # Rate limiting between issues
            time.sleep(JIRA_COMMENT_DELAY_SECONDS)

            resolved_count += 1
            logger.info("✓ Resolved issue %s: assigned to component '%s'", issue_key, component)

        except JiraClientError as e:
            logger.error("Failed to update issue %s: %s", issue_key, e)
            failed_count += 1
            continue

    logger.info("Unmapped issue resolution completed: %d resolved, %d failed", resolved_count, failed_count)
    return resolved_count


def _get_unmapped_repositories(jira_client: JiraClient) -> list[str]:
    """Get list of currently unmapped repositories from Jira issues.

    Args:
        jira_client: JiraClient instance.

    Returns:
        List of repository names that are currently unmapped.
    """
    try:
        # Find all unmapped issues
        unmapped_issues = jira_client.search_issues_by_label("unmapped-repo")
    except JiraClientError as e:
        logger.error("Failed to search for unmapped issues: %s", e)
        # Check if this looks like an authentication/access issue
        error_msg = str(e).lower()
        if "404" in error_msg or "not found" in error_msg:
            logger.error("This appears to be a Jira authentication or access issue.")
            logger.error("Please ensure you have:")
            logger.error("1. Set JIRA_SERVER, JIRA_EMAIL, JIRA_API_TOKEN environment variables")
            logger.error("2. Access to the JIRA project specified in JIRA_PROJECT_KEY")
        return []

    unmapped_repos = set()

    for issue in unmapped_issues:
        description = issue["fields"].get("description", "")

        # Extract repository from issue description UID
        uid = _extract_uid_from_description(description)
        if uid:
            project_name = _extract_project_from_uid(uid)
            if project_name:
                unmapped_repos.add(project_name)

    return sorted(list(unmapped_repos))


def _generate_unmapped_file_content(unmapped_repos: list[str], available_components: list[str]) -> str:
    """Generate content for the UNMAPPED_REPOSITORIES.md file.

    Args:
        unmapped_repos: List of unmapped repository names.
        available_components: List of available Jira components.

    Returns:
        Markdown formatted content for the unmapped repositories file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d")

    if not unmapped_repos:
        return f"""# Unmapped Repositories

*Auto-updated after each weekly scan - {timestamp}*

**All repositories are currently mapped to components!**

No repositories currently need component mapping.

---

## About This Report

This file is automatically updated by the Snyk-Jira integration to track repositories that don't have
component mappings. When new repositories are discovered that lack component assignments, they appear
here with guidance on how to add them to the appropriate component mapping.

"""

    repo_list = "\n".join(f"- `{repo}`" for repo in unmapped_repos)
    components_list = ", ".join(f"`{comp}`" for comp in sorted(available_components))

    return f"""# Unmapped Repositories

*Auto-updated after each weekly scan - {timestamp}*

**{len(unmapped_repos)} repositories need component mapping**

The following repositories were discovered in Snyk but don't have component assignments in the Jira integration:

{repo_list}

## How to Fix

Add your repository to the appropriate component in
[`config/jira_components_mapping.json`](config/jira_components_mapping.json):

```json
{{
  "Your Component Name": [
    "existing-repo-1",
    "existing-repo-2",
    "your-repo-name"  // ← Add here
  ]
}}
```

### Available Components

{components_list}

### Steps to Add Mapping

1. **Identify the right component**: Review the existing mappings to find where your repository belongs
2. **Edit the config**: Add your repository using the format `"org-name/repo-name"`
3. **Validate**: Run `python scripts/validate_config.py` to check for errors
4. **Test**: Use `DRY_RUN=true python -m snyk_jira_reporter --disable-dep-analysis` to verify
5. **Automatic resolution**: Unmapped issues are automatically resolved during the next weekly run

### Validation

The configuration includes automatic schema validation:
- ✓ Valid JSON format
- ✓ Correct repository format (`org/repo-name`)
- ✓ No duplicate repositories
- ✓ Valid component names

Run the validator locally before committing:
```bash
python scripts/validate_config.py
```

---

*This file is automatically generated. Do not edit manually.*

"""


def _generate_readme_section(unmapped_count: int) -> str:
    """Generate simple README section that links to the unmapped repositories file.

    Args:
        unmapped_count: Number of unmapped repositories.

    Returns:
        Markdown formatted README section with link.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d")

    status = "All repositories mapped" if unmapped_count == 0 else f"{unmapped_count} repositories need mapping"

    return f"""## Repository Component Mapping

*Last updated: {timestamp}*

**Status**: {status}

**[View detailed unmapped repositories report →](UNMAPPED_REPOSITORIES.md)**

---

"""


def _write_unmapped_file(content: str) -> None:
    """Write the UNMAPPED_REPOSITORIES.md file.

    Args:
        content: Markdown content for the unmapped repositories file.
    """
    # Find project root by looking for pyproject.toml
    current_path = Path(__file__).parent
    while current_path != current_path.parent:
        if (current_path / "pyproject.toml").exists():
            unmapped_path = current_path / "UNMAPPED_REPOSITORIES.md"
            break
        current_path = current_path.parent
    else:
        # Fallback - assume we're in src/snyk_jira_reporter/services
        unmapped_path = Path(__file__).parent.parent.parent.parent / "UNMAPPED_REPOSITORIES.md"

    with open(unmapped_path, "w") as f:
        f.write(content)

    logger.info("Updated UNMAPPED_REPOSITORIES.md")


def _update_readme_file(readme_section: str) -> None:
    """Update README.md file with a simple link to the unmapped repositories file.

    Args:
        readme_section: Simple markdown section with link to unmapped repositories file.
    """
    # Find project root by looking for pyproject.toml
    current_path = Path(__file__).parent
    while current_path != current_path.parent:
        if (current_path / "pyproject.toml").exists():
            readme_path = current_path / "README.md"
            break
        current_path = current_path.parent
    else:
        # Fallback - assume we're in src/snyk_jira_reporter/services
        readme_path = Path(__file__).parent.parent.parent.parent / "README.md"

    if not readme_path.exists():
        logger.warning("README.md file not found at %s", readme_path)
        return

    # Read current README
    with open(readme_path) as f:
        content = f.read()

    # Find and replace the repository component mapping section
    # Look for both old and new section markers for backward compatibility
    old_marker = "## Unmapped Repositories"
    new_marker = "## Repository Component Mapping"

    start_marker = new_marker
    start_index = content.find(new_marker)

    # If new marker not found, look for old marker
    if start_index == -1:
        start_marker = old_marker
        start_index = content.find(old_marker)

    end_marker = "\n## "  # Next section starts with ##

    if start_index == -1:
        # Section doesn't exist, append to end
        updated_content = content.rstrip() + "\n\n" + readme_section.rstrip() + "\n"
    else:
        # Find end of section
        end_search_start = start_index + len(start_marker)
        end_index = content.find(end_marker, end_search_start)

        if end_index == -1:
            # Section goes to end of file
            updated_content = content[:start_index] + readme_section
        else:
            # Replace section content
            updated_content = content[:start_index] + readme_section + content[end_index + 1 :]

    # Write updated README
    with open(readme_path, "w") as f:
        f.write(updated_content)

    logger.info("Updated README.md with link to unmapped repositories file")


def generate_component_report(jira_client: JiraClient, component_mapping: dict[str, str]) -> int:
    """Generate component mapping report and update documentation files.

    Args:
        jira_client: JiraClient instance for searching unmapped issues.
        component_mapping: Mapping from repositories to components.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        # Get unmapped repositories
        unmapped_repos = _get_unmapped_repositories(jira_client)
        logger.info("Found %d unmapped repositories", len(unmapped_repos))

        if len(unmapped_repos) == 0:
            logger.info("Note: This function finds unmapped repos by searching existing Jira issues")
            logger.info("If vulnerability processing was run in DRY_RUN mode, no actual issues exist to find")
            logger.info("Run the main vulnerability processor without DRY_RUN to create real issues first")

        # Get available components
        try:
            available_components = jira_client.list_project_components()
        except JiraClientError:
            available_components = list(set(component_mapping.values()))
            available_components = [c for c in available_components if c]  # Remove empty strings

        # Generate and write the detailed unmapped repositories file
        unmapped_content = _generate_unmapped_file_content(unmapped_repos, available_components)
        _write_unmapped_file(unmapped_content)

        # Generate and update the simple README section with link
        readme_section = _generate_readme_section(len(unmapped_repos))
        _update_readme_file(readme_section)

        print(f"Generated component mapping report: {len(unmapped_repos)} unmapped repositories")
        print("- Created UNMAPPED_REPOSITORIES.md with detailed information")
        print("- Updated README.md with link to the detailed report")
        return 0

    except (JiraClientError, Exception) as e:
        logger.error("Failed to generate component mapping report: %s", e)
        return 1
