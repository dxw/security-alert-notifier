# GitHub Vulnerability Alert Check

Fetches a list of security vulnerabilities for repositories belonging to a
GitHub organization, using the GitHub API (v4). Designed to be used as an
[Icinga
plugin](https://icinga.com/docs/icinga2/latest/doc/05-service-monitoring/#plugin-api).

## Usage

- Obtain a [personal GitHub OAuth
  token](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line#creating-a-token),
  with the `repo` scope
- Run `security-alert-notifier --token <access_token> --organization <organization_name>` and any
  vulnerabilities that haven't been dismissed will be displayed in the console.
  If there are vulnerabilties then the check will return a "Warning" status, else
  "OK".

## Tests

Basic tests can be run with

````bash
ruby security-alert-notifier_test.rb
```
