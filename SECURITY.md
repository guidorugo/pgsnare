# Security policy

pgsnare sits in front of production databases, so security reports are handled privately and with priority.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting:

**<https://github.com/guidorugo/pgsnare/security/advisories/new>**

Only the maintainers can see such a report.

Please do **not** open a public issue, discussion or pull request for a suspected vulnerability, and do not describe it in an existing one. If you are not sure whether something is a vulnerability, report it privately anyway.

A useful report says:

- what an attacker can do, and what they need in order to do it
- the commit or version you tested
- the steps, input or configuration that reproduce the problem
- any log lines or crash output, with secrets and real addresses removed

Use synthetic data in the report. Do not include real credentials, real honeytoken values or data from a production database.

## Supported versions

No version of pgsnare has been released yet. Until the first release there is no supported version, and fixes land on the `main` branch only.

This section will list the supported versions from the first release on.

## Scope

In scope is anything that lets someone:

- crash, stall or exhaust the proxy, or affect sessions other than their own
- gain access to the database that they would not have by connecting to it directly
- switch off, bypass or desynchronise inspection
- read honeytoken values, passwords, key material or configuration from the proxy, its logs, its events or its metrics
- tamper with a dependency, a build or a release without being detected

An attacker who already has root on the host that runs pgsnare is out of scope.
