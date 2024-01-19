# JIRA SNYK AUTOMATION SCRIPTS IN GITHUB ACTIONS

## Motivation
Snyk is a security tool which scans the code, finds the vulnerabilities and posts the result. In our team, we use JIRA to track all issues to tackle. Snyk doesnot provide out-of-the-box support of automatically creating JIRAs. So the purpose of this repository is to provide the capability to automatically generate JIRAs from the scan results.
## How to use it?
This is a reusable GitHub Actions workflow that can be used by other teams in the orgainzation. It can be deployed to the CI and can run on a schedule(cron job) so that the scan results are periodically converted to JIRAs.

To use it, simply create a workflow file(yaml) in your `.github/workflows` and do something like the below yaml.

## Example yaml
```yaml
  name: Create Jira from Snyk
on:
  workflow_dispatch:
  schedule:
    - cron: '0 5 * * 1' # A cron job which runs at 5 AM on every Monday.
jobs:
  create-jira-bugs:
        uses: AjayJagan/jira-snyk-resuable-workflow/.github/workflows/jira-snyk.yaml@main
        with:
          jira_server: https://issues.redhat.com # org jira server
          jira_project_id: 12340620 # refers to RHOAIENG
          jira_component_names: Platform # A list of comma separated values. Eg. Platform,Dashboard
          jira_epic_id: RHOAIENG-1430 # refers to https://issues.redhat.com/browse/RHOAIENG-1430(This has to be periodically changed)
          snyk_org_id: ed870ef2-8f76-4ea1-ad4b-dacfa225eb69 # refers to the RHOAI org in Snyk
          snyk_project_id: 570fd96f-09ad-488b-bb37-f822c34c973f # refers to the red-hat-data-services/rhods-operator
          dry_run: true
          exclude_files_path: ./.github/workflows/supporting-files/exclude_files.json
        secrets: inherit
```
### NOTE:
    Please note that there are two secrets and a folder that needs to be set up for the script to work properly.

    * The `SNYK_API_TOKEN` and `JIRA_API_TOKEN` are two secrets which provide auth mechanism for the code to read and create jiras. So it is important to set this either in the repo level or org level.
    * In case you need to exclude folders, insert regex in `exclude_files.json` in format:
    ```json
    {
        "opendatahub/opendatahub-operator": {
            "^modules/.*/vendor": ""
        },
        "/": {
            "path_regex": "<empty_string>"
        }
    }
    ```
    Also note that this file has to be stored in the repo and referenced in the variable `exclude_files_path`.

## List of available variables to customise

| Key - variable                | Meaning
| :----------------: | :------: 
| jira_server        |  The url of the jira. server   | 
| jira_project_id          |   The project id of the project to create the jiras in. Refer: https://confluence.atlassian.com/jirakb/how-to-get-project-id-from-the-jira-user-interface-827341414.html   | 
| jira_component_names    |  A list of comma separated components to link to the JIRA.   | 
| jira_epic_id |  The epic id to link the created JIRAs to.   |
| snyk_org_id |  Each org in Snyk has a unique id. Can be found in the settings.   |
| snyk_project_id |  Each project in Snyk has a unique id. Can be found in the settings.   |
| dry_run |  Runs the script without really creating the JIRA.   |
| exclude_files_path |  Path which hosts the exclude_files.json   |
| jira_label_prefix |  Optional. This is used to add a prefix to the label   |

### Note:
    The secrets: inherit is important as it passes the secrets to the reusable workflows.
  
