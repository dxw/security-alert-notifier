# GitHub Vulnerability Alert Check

Fetches a list of security vulnerabilities for repositories belonging to a
GitHub organization, using the GitHub API (v4). Designed to be used as an
[Icinga
plugin](https://icinga.com/docs/icinga2/latest/doc/05-service-monitoring/#plugin-api).

## Getting started

This repository implements the [scripts to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern.

To use this code, start by cloning the repository:

```shell
$ git clone git@github.com:dxw/security-alert-notifier.git
```

Then run the relevant script to setup your environment and install dependencies:

```shell
./script/setup
```

## Usage

- Obtain a [personal GitHub OAuth
  token](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line#creating-a-token),
  with the `repo` scope
- Run `security-alert-notifier.rb --token <access_token> --organization <organization_name>` and any
  vulnerabilities that haven't been dismissed will be displayed in the console.
  If there are vulnerabilities then the check will return a "Warning" status, else
  "OK".

## Contributing to this repository

To run the standard lint ([`standardrb`](https://github.com/testdouble/standardrb)) and unit tests for this code, run:

```shell
./script/test
```

For dxw employees, please note that this code is also used downstream in our
Chef configuration, and any changes you merge in here also need to be reflected there.
If this isn't clear to you, please speak to a colleague from Ops.
