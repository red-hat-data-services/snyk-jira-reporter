"""Project name and file path parsing utilities."""

import re


def parse_project_name(project_name: str, branch_name: str) -> str:
    """Extract the repository name from a Snyk project name.

    Snyk project names follow the format: '<org>/<repo>(<branch>):<file_path>'.
    This function extracts '<org>/<repo>' by removing the branch suffix and file path.

    Args:
        project_name: Full Snyk project name string.
        branch_name: Branch name to strip from the project name.

    Returns:
        Repository name (e.g. 'red-hat-data-services/kserve').
    """
    return project_name.partition(":")[0].removesuffix(f"({branch_name})")


def parse_file_name(project_name: str) -> str:
    """Extract the file path from a Snyk project name.

    Args:
        project_name: Full Snyk project name string in format '<repo>:<file_path>'.

    Returns:
        File path portion after the colon separator.
    """
    return project_name.partition(":")[2]


def exclude_file(file_name: str, excluded_files: list[str]) -> bool:
    """Check if a file should be excluded from vulnerability scanning.

    Args:
        file_name: The file path to check.
        excluded_files: List of regex patterns to match against.

    Returns:
        True if the file matches any exclusion pattern.
    """
    return any(re.search(pattern, file_name) for pattern in excluded_files)
