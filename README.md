# GitHub Vulnerability Alert Notifier

Fetches a list of security vulnerabilities for repositories belonging to a
GitHub organization, using the GitHub API (v4). Designed to be used as an
[Icinga
plugin](https://icinga.com/docs/icinga2/latest/doc/05-service-monitoring/#plugin-api).

## Usage

- Obtain a personal GitHub OAuth token
- Run `security-alert-notifier <access_token> <organization_name>` and any
  vulnerabilities that haven't been dismissed will be displayed in the console.
  If there are vulnerabilties then the check will return a "Warning" status, else
  "OK".
