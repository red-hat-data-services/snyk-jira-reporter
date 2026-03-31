"""Configuration file loading utilities."""

import json
import logging
import os
from typing import Any

from snyk_jira_reporter.exceptions.exceptions import FileLoadError

logger = logging.getLogger(__name__)


def load_mapping(file_path: str) -> dict[str, Any]:
    """Load a JSON mapping file from the given path.

    The path is resolved relative to the current working directory.

    Args:
        file_path: Relative or absolute path to the JSON file.

    Returns:
        Parsed JSON content as a dictionary.

    Raises:
        FileLoadError: If the file does not exist or contains invalid JSON.
    """
    root_dir = os.path.abspath(os.curdir)
    resolved_path = os.path.join(root_dir, file_path)

    if not os.path.isfile(resolved_path):
        raise FileLoadError(f"Configuration file not found: {resolved_path}")

    try:
        with open(resolved_path, encoding="utf-8") as f:
            return json.loads(f.read())  # type: ignore[no-any-return]
    except json.JSONDecodeError as e:
        raise FileLoadError(f"Invalid JSON in {resolved_path}: {e}") from e
    except OSError as e:
        raise FileLoadError(f"Failed to read {resolved_path}: {e}") from e


def load_component_mapping(file_path: str) -> dict[str, str]:
    """Load a grouped component mapping and invert it to repo → component.

    The JSON file uses a grouped format where keys are Jira component names
    and values are lists of repository names:

        {"Model Serving": ["org/repo1", "org/repo2"], ...}

    This is inverted to:

        {"org/repo1": "Model Serving", "org/repo2": "Model Serving", ...}

    Args:
        file_path: Path to the component mapping JSON file.

    Returns:
        Dictionary mapping repository names to Jira component names.

    Raises:
        FileLoadError: If the file is missing, invalid, or has duplicate repos.
    """
    grouped = load_mapping(file_path)
    repo_to_component: dict[str, str] = {}
    for component, repos in grouped.items():
        if not isinstance(repos, list):
            raise FileLoadError(f"Expected a list of repos for component '{component}', got {type(repos).__name__}")
        for repo in repos:
            if repo in repo_to_component:
                raise FileLoadError(
                    f"Duplicate repo '{repo}' found in components "
                    f"'{repo_to_component[repo]}' and '{component}'"
                )
            repo_to_component[repo] = component
    return repo_to_component
