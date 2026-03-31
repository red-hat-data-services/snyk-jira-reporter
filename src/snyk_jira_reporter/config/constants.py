"""Constants and default values for snyk-jira-reporter."""

# Jira
DEFAULT_JIRA_LABEL_PREFIX = "snyk-jira-integration:"
JIRA_SECURITY_FIELD_ID = "10034"
JIRA_BUG_ISSUE_TYPE = "Bug"
JIRA_NON_CLOSEABLE_STATUSES = frozenset({"Resolved", "Closed"})
JIRA_CLOSE_COMMENT = "Closing this issue as it is no longer reported in snyk"
JIRA_CLOSE_TRANSITION = "Closed"
JIRA_MAX_SEARCH_PAGES = 100
JIRA_SUMMARY_MAX_LENGTH = 255

# Snyk
SNYK_API_BASE_URL = "https://api.snyk.io"
SNYK_REST_API_BASE_URL = f"{SNYK_API_BASE_URL}/rest"
SNYK_ORG_URL_TEMPLATE = "https://app.snyk.io/org/{org_slug}/project/{project_id}#issue-{issue_id}"
DEFAULT_SNYK_REST_API_VERSION = "2024-01-23"
DEFAULT_SNYK_RESULT_LIMIT = "100"
SNYK_MAX_PAGES = 500
DEFAULT_ALLOWED_DEPS = frozenset({"pip", "gomodules", "npm", "yarn", "poetry", "maven"})
DEFAULT_CONTAINER_TYPES = frozenset({"dockerfile"})

# Severity
DEFAULT_ALLOWED_SEVERITIES = ("critical", "high")
SEVERITY_PRIORITY_MAP: dict[str, str] = {
    "critical": "Critical",
    "high": "Major",
    "medium": "Normal",
    "low": "Minor",
}

# Throttle delays (seconds)
JIRA_CREATE_DELAY_SECONDS = 10
JIRA_COMMENT_DELAY_SECONDS = 5

# UID markers in Jira descriptions
UID_SECTION_START = "##Do not edit this section below##"
UID_MARKER = "##snyk-jira-uid##"
UID_SECTION_END = "##Do not edit this section above##"
UID_REGEX = r"##snyk-jira-uid##(.+?)(?:\s|$)"

# Config file defaults
DEFAULT_COMPONENT_MAPPING_PATH = "./config/jira_components_mapping.json"
DEFAULT_EXCLUDE_FILES_PATH = "./config/exclude_files.json"

# HTTP
DEFAULT_REQUEST_TIMEOUT_SECONDS = 30
HTTP_RETRY_TOTAL = 3
HTTP_RETRY_BACKOFF_FACTOR = 1.0
HTTP_RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})
