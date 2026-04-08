# Security Policy

`jwt-refresh` handles authentication-adjacent logic. Treat security reports as private until a fix is available.

## Supported versions

This repository currently targets the latest published `0.x` line.

## Reporting a vulnerability

Please do not open public issues for vulnerabilities.

Send a private report that includes:

- affected version
- attack scenario
- reproduction steps
- impact estimate

If a report is confirmed, the response process is:

1. reproduce the issue
2. prepare a fix and regression test
3. publish a patched release
4. disclose the issue with remediation guidance

## Security assumptions

- refresh tokens should be delivered through `httpOnly` cookies
- access tokens should remain short-lived
- production deployments should use HTTPS
- multi-instance deployments should use a distributed mutex implementation
