# JIRA SNYK AUTOMATION SCRIPTS IN GITHUB ACTIONS

## Motivation
Snyk is a security tool which scans the code, finds the vulnerabilities and posts the result. In our team, we use JIRA to track all issues to tackle. Snyk doesnot provide out-of-the-box support of automatically creating JIRAs. So the purpose of this repository is to provide the capability to automatically generate JIRAs from the scan results.
## How to use it?
This is a GitHub Actions workflow that runs on all Snyk projects. It runs on a schedule(cron job) so that the scan results are periodically converted to JIRAs.

```
### NOTE:
  Please note that there are two secrets that needs to be set up for the script to work properly.

  * The `SNYK_API_TOKEN` and `JIRA_API_TOKEN` are two secrets which provide auth mechanism for the code to read and create jiras. So it is important to set this either in the repo level or org level.
  * In case you need to exclude folders, insert regex in `exclude_files.json` in format:
  ```json
  {
      "opendatahub/opendatahub-operator": ["^modules/.*/vendor"]
      "repo_name": Array<path_regex_to_ignore>
  }
  ```
  
