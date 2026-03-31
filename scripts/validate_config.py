#!/usr/bin/env python3
"""Validate configuration files against their JSON schemas."""

import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("Error: jsonschema package not installed. Run: pip install jsonschema")
    sys.exit(1)


def validate_file(config_file: Path, schema_file: Path) -> tuple[bool, str | None]:
    """Validate a JSON config file against its schema.

    Args:
        config_file: Path to the configuration file
        schema_file: Path to the JSON schema file

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Load schema
        with open(schema_file) as f:
            schema = json.load(f)

        # Load config
        with open(config_file) as f:
            config = json.load(f)

        # Validate
        jsonschema.validate(instance=config, schema=schema)
        return True, None

    except json.JSONDecodeError as e:
        return False, f"Invalid JSON format: {e}"
    except jsonschema.ValidationError as e:
        return False, f"Schema validation error: {e.message}"
    except FileNotFoundError as e:
        return False, f"File not found: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"


def main() -> int:
    """Main validation function."""
    root_dir = Path(__file__).parent.parent
    config_dir = root_dir / "config"

    # Configuration files and their schemas
    validations = [
        (
            config_dir / "jira_components_mapping.json",
            config_dir / "jira_components_mapping.schema.json",
            "Jira Components Mapping",
        ),
    ]

    all_valid = True

    print("Validating configuration files...")
    print("-" * 50)

    for config_file, schema_file, description in validations:
        if not config_file.exists():
            print(f"❌ {description}: Config file not found: {config_file}")
            all_valid = False
            continue

        if not schema_file.exists():
            print(f"⚠️  {description}: Schema file not found: {schema_file}")
            continue

        is_valid, error = validate_file(config_file, schema_file)

        if is_valid:
            print(f"✅ {description}: Valid")
        else:
            print(f"❌ {description}: {error}")
            all_valid = False

    print("-" * 50)

    if all_valid:
        print("All configuration files are valid!")
        return 0
    else:
        print("Some configuration files have validation errors.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
