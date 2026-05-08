"""Utilities for parsing Atlassian Document Format (ADF) content."""

from typing import Any


def extract_text_from_adf(adf_content: dict[str, Any]) -> str:
    """Extract plain text from Atlassian Document Format content.

    This function recursively traverses ADF JSON structures to extract
    the plain text content, handling various node types and structures.

    Args:
        adf_content: ADF content as a dictionary structure.

    Returns:
        Plain text content extracted from the ADF structure.
    """

    def extract_text_recursive(node: Any) -> str:
        if isinstance(node, dict):
            text = ""
            if node.get("type") == "text":
                text += node.get("text", "")
            elif "content" in node:
                for child in node["content"]:
                    text += extract_text_recursive(child)
            return text
        elif isinstance(node, list):
            return "".join(extract_text_recursive(item) for item in node)
        else:
            return str(node) if node else ""

    return extract_text_recursive(adf_content)
