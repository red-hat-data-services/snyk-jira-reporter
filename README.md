# Snyk to Jira Reporter

Automated tool that scans Snyk for security vulnerabilities and creates/manages Jira tickets. Runs as a GitHub Actions workflow on a weekly schedule to keep your Jira project synchronized with your Snyk security findings.

##What This Tool Does

1. **Scans Snyk Projects**: Fetches all monitored projects from your Snyk organization
2. **Finds Vulnerabilities**: Discovers SAST (code analysis) and dependency vulnerabilities
3. **Creates Jira Issues**: Automatically creates Jira bug tickets for new high/critical vulnerabilities
4. **Manages Issue Lifecycle**: Closes Jira tickets when vulnerabilities are resolved in Snyk
5. **Maps to Components**: Assigns Jira issues to the correct component team using configurable mappings
6. **Provides Detailed Context**: For SAST issues, shows exact source file and line number information

##Quick Start

### Prerequisites

- Python 3.10+
- Snyk API token with org access
- Jira Cloud API token with project access
- Access to RHOAIENG Jira project

### Installation

```bash
# Install the package
pip install -e .

# For development
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Run with dry-run (recommended first time)
DRY_RUN=true python -m snyk_jira_reporter --disable-dep-analysis

# Run for real (creates actual Jira issues)
python -m snyk_jira_reporter --disable-dep-analysis
```

##Step-by-Step Setup

### 1. Get Required API Tokens

**Snyk API Token:**
1. Go to [Snyk Account Settings](https://app.snyk.io/account)
2. Generate a new API token
3. Note your organization ID from the URL: `https://app.snyk.io/org/{ORG_ID}`

**Jira API Token:**
1. Go to [Atlassian API Tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
2. Create a new API token
3. Note your email address for authentication

### 2. Configure Environment Variables

Create a `.env` file (ignored by git):

```bash
# Snyk Configuration
SNYK_ORG_ID=your-snyk-org-id-here
SNYK_API_TOKEN=your-snyk-token-here

# Jira Configuration
JIRA_SERVER=https://redhat.atlassian.net
JIRA_EMAIL=your-email@redhat.com
JIRA_API_TOKEN=your-jira-token-here
JIRA_PROJECT_ID=your-jira-project-id
JIRA_PROJECT_KEY=RHOAIENG

# Optional Configuration
DRY_RUN=true
JIRA_LABEL_PREFIX=snyk-jira-integration:
COMPONENT_MAPPING_FILE_PATH=./config/jira_components_mapping.json
EXCLUDE_FILES_FILE_PATH=./config/exclude_files.json
```

### 3. Test Your Configuration

```bash
# Test with dry-run to validate setup
DRY_RUN=true python -m snyk_jira_reporter --allowed-severity critical --disable-dep-analysis
```

Look for output like:
```
INFO:root:DRY_RUN is enabled
INFO:root:Processing project: red-hat-data-services/your-repo(main)
INFO:snyk_jira_reporter.clients.jira_client:DRY RUN: X issue(s) would be created
```

##Configuration Guide

### Adding New Component Mappings

**Most Common Task: Adding a new repository to Jira component mapping**

Edit `config/jira_components_mapping.json`:

```json
{
    "Model Serving": [
        "red-hat-data-services/kserve",
        "red-hat-data-services/modelmesh-serving",
        "red-hat-data-services/your-new-repo"  ← Add here
    ],
    "Your New Component": [                   ← Or create new component
        "red-hat-data-services/another-repo"
    ]
}
```

**Steps to add a new repository:**

1. **Find the right component**: Look at the existing mappings to find where your repo belongs
2. **Add your repository**: Use the full GitHub path format `org-name/repo-name`
3. **Test the change**: Run with dry-run to verify the mapping works
4. **Commit the change**: Submit a PR with your updated mapping

**Example: Adding a new MLflow repository**

```json
{
    "MLflow": [
        "red-hat-data-services/mlflow",
        "red-hat-data-services/mlflow-operator",
        "red-hat-data-services/mlflow-ui"  ← New addition
    ]
}
```

### File Exclusions

To exclude specific files from vulnerability scanning, edit `config/exclude_files.json`:

```json
{
    "red-hat-data-services/your-repo": [
        "^vendor/",
        "^node_modules/",
        "^tests/",
        "\\.test\\.",
        "\\.spec\\."
    ]
}
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --allowed-severity` | Severities to include (critical,high,medium,low) | `critical,high` |
| `-l, --limit` | Snyk API results per page | `100` |
| `-v, --version` | Snyk REST API version | `2024-01-23` |
| `--disable-dep-analysis` | Skip dependency scanning (SAST only) | `false` |

**Examples:**

```bash
# Only critical vulnerabilities
python -m snyk_jira_reporter --allowed-severity critical

# Include medium severity
python -m snyk_jira_reporter --allowed-severity critical,high,medium

# SAST only (recommended for faster runs)
python -m snyk_jira_reporter --disable-dep-analysis
```

##Understanding SAST Source File Feature

For Static Application Security Testing (SAST) issues, this tool provides enhanced context:

**Jira Issue Title:**
```
Snyk - [CWE-23] - [high] - [main] - red-hat-data-services/odh-dashboard - packages/gen-ai/bff/internal/api/openapi_handler.go - Path Traversal
```
↑ Shows actual source file, not just project file

**Jira Issue Description:**
```
Found vulnerability in red-hat-data-services/odh-dashboard project, in file ,

Source file: packages/gen-ai/bff/internal/api/openapi_handler.go (line 42)

in branch main.
```
↑ Includes exact file path and line number

This helps developers:
- Quickly identify which file contains the vulnerability
- Jump directly to the problematic code location
- Understand the context and severity of the security issue

##Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SNYK_ORG_ID` | Yes | - | Snyk organization ID (UUID) |
| `SNYK_API_TOKEN` | Yes | - | Snyk API authentication token |
| `JIRA_SERVER` | Yes | - | Jira server URL (e.g., https://redhat.atlassian.net) |
| `JIRA_EMAIL` | Yes | - | Your email for Jira authentication |
| `JIRA_API_TOKEN` | Yes | - | Jira API token from Atlassian |
| `JIRA_PROJECT_ID` | Yes | - | Jira project ID for issue creation |
| `JIRA_PROJECT_KEY` | No | `RHOAIENG` | Jira project key for JQL queries |
| `JIRA_LABEL_PREFIX` | No | `snyk-jira-integration:` | Prefix for tracking labels |
| `DRY_RUN` | No | `false` | If `true`, shows what would happen without creating issues |
| `COMPONENT_MAPPING_FILE_PATH` | No | `./config/jira_components_mapping.json` | Component mapping config |
| `EXCLUDE_FILES_FILE_PATH` | No | `./config/exclude_files.json` | File exclusion config |

##Development Guide

### Running Tests

```bash
# Run all tests with coverage
pytest --cov=snyk_jira_reporter tests/

# Run specific test file
pytest tests/test_clients/test_jira_client.py -v

# Run tests matching pattern
pytest tests/ -k "test_source_file" -v
```

### Code Quality

```bash
# Lint code
ruff check src/ tests/

# Format code
ruff format src/ tests/

# Type checking
mypy src/
```

### Testing Your Changes

1. **Use dry-run mode**: Always test with `DRY_RUN=true` first
2. **Test with a small subset**: Filter to specific repos during development
3. **Check the logs**: Verify your changes work as expected
4. **Run the test suite**: Ensure you haven't broken existing functionality

```bash
# Test your changes
DRY_RUN=true python -m snyk_jira_reporter --allowed-severity critical
```

##Troubleshooting

### Common Issues

**"No component mapping found for repo 'org/repo'"**
- Add the repository to `config/jira_components_mapping.json`
- Verify the repository name format matches exactly

**"Authentication failed - check JIRA_EMAIL and JIRA_API_TOKEN"**
- Verify your Jira email address is correct
- Regenerate your Jira API token
- Check that you have access to the RHOAIENG project

**"Reached max page limit (100) for JQL query"**
- This is normal for large projects with many existing issues
- The tool handles this automatically and continues processing

**"Could not extract UID from Jira issue"**
- This indicates an existing Jira issue wasn't created by this tool
- These issues are safely ignored

### Getting Help

1. **Check the logs**: The tool provides detailed logging about what it's doing
2. **Use dry-run mode**: Test changes safely with `DRY_RUN=true`
3. **Validate your config**: Ensure all required environment variables are set
4. **Test API access**: Verify you can access both Snyk and Jira manually

### Debug Mode

For more detailed logging:

```bash
# Enable debug logging
PYTHONPATH=src python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from snyk_jira_reporter.__main__ import main
main()
" --disable-dep-analysis
```

##Project Structure

```
src/snyk_jira_reporter/
├── __main__.py               # CLI entry point
├── config/
│   ├── settings.py          # Pydantic settings (environment variables)
│   └── constants.py         # Named constants and defaults
├── models/
│   ├── vulnerability.py     # VulnerabilityData model (Jira issue creation)
│   └── snyk_models.py       # Snyk API response models
├── clients/
│   ├── snyk_client.py       # Snyk REST API client
│   └── jira_client.py       # Jira Cloud v3 API client
├── services/
│   └── vulnerability_service.py  # Core processing logic
├── utils/
│   ├── labels.py            # Jira label/priority utilities
│   ├── parsing.py           # Project name parsing helpers
│   └── file_loader.py       # JSON config file loading
└── exceptions/
    └── exceptions.py        # Custom exception hierarchy

config/
├── jira_components_mapping.json  # Repository → Jira component mapping
└── exclude_files.json           # File exclusion patterns

.github/workflows/
├── jira-snyk.yaml               # Weekly scheduled run
└── ci.yaml                      # Pull request validation
```

##GitHub Actions

### Weekly Scheduled Run (`.github/workflows/jira-snyk.yaml`)

- **When**: Every Monday at 5 AM UTC
- **What**: Scans all monitored Snyk projects and updates Jira
- **Environment**: Production environment with real API tokens
- **Notifications**: GitHub will notify on failures

### CI Pipeline (`.github/workflows/ci.yaml`)

- **When**: Every push and pull request
- **What**: Runs linting, type checking, and tests
- **Purpose**: Ensures code quality and prevents regressions

##API Compatibility

This tool uses:
- **Jira Cloud REST API v3** (latest, fully compatible with Jira Cloud)
- **Snyk REST API v2024-01-23** (current stable version)

All endpoints are current and supported as of 2024. The tool includes backward compatibility for existing Jira issues created with previous versions.

---

##Example Workflow: Adding a New Repository

1. **Identify the component**: Determine which Jira component your repository belongs to
2. **Update the mapping**: Add your repo to `config/jira_components_mapping.json`
3. **Test the change**: Run with `DRY_RUN=true` to verify
4. **Submit PR**: Include your mapping change in a pull request
5. **Verify production**: Check that new issues are assigned to the correct component

```bash
# Step 1: Edit the config file
vim config/jira_components_mapping.json

# Step 2: Test your change
DRY_RUN=true python -m snyk_jira_reporter --disable-dep-analysis

# Step 3: Look for your repo in the logs
# Should see: "component: Your Component Name"

# Step 4: Commit and create PR
git add config/jira_components_mapping.json
git commit -m "Add my-new-repo to Component Name mapping"
```

Need help? Check the troubleshooting section above or reach out to the team! 