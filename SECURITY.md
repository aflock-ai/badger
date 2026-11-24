# Security policy

## Reporting a vulnerability

Report vulnerabilities in Badger privately. Do not open a public issue or pull request.

- Use GitHub's private vulnerability reporting: the **Report a vulnerability** button on the
  Security tab of this repository.
- Or email security@testifysec.com.

Include the version or commit, what you did, what you expected and what happened. A proof of
concept helps. Do not include real credentials or customer data.

We aim to acknowledge a report within 3 business days and to tell you our assessment within 10.
We will credit you in the advisory if you want to be credited. We ask that you give us a
reasonable time to fix the issue before you disclose it.

## What is in scope

This repository: the managed Badger build (`--managed`) and the TestifySec components under
`testifysec/` (model gateway, admission launcher, session broker, model broker and portal,
connectors).

A report is in scope when it shows that a managed build, or one of those services, does not
enforce something these documents say it enforces. [`docs/concepts/architecture.md`](docs/concepts/architecture.md)
lists what the managed build enforces and which boundaries a deployment must supply itself.

## What is out of scope

- Issues that exist only in the unmanaged build. A build without `--managed` is plain OpenCode.
  Report those to the [OpenCode project](https://github.com/anomalyco/opencode/security).
- The permission prompt as a sandbox. Prompt approval is a usability feature. Badger does not
  confine shell commands; that is the deployment's VM or container.
- A compromised host administrator, or a model provider acting outside the gateway.
- Vulnerabilities in third-party dependencies with no demonstrated effect on Badger. Report
  those upstream; we will update the dependency.

## Supported versions

Badger has no tagged releases yet. Fixes go to the `main` branch.
