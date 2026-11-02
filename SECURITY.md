# Security policy

The Keystone SDKs run schema changes against PostgreSQL servers using
credentials you supply. Please report vulnerabilities privately.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open the repository's **Security**
tab and choose **Report a vulnerability**
(<https://github.com/dogukanturhal/keystone-sdk/security/advisories/new>).

If you cannot use GitHub, email **dogukanturhal@hexxlock.com**. Do not post
details in a public issue, discussion or chat.

Please include:

- What the issue is and which SDK (Go, Rust or .NET) and version is affected.
- A way to reproduce it: the code and SQL involved, your environment, what
  you saw and what you expected.
- Who can trigger it and what they gain.
- Whether you want to be credited.

We acknowledge reports within two business days.

## Disclosure

We follow a 90-day coordinated disclosure window from acknowledgement.

| Day | What happens |
|---|---|
| 0 | Report acknowledged, triage starts. |
| 0-7 | Severity assessed (CVSS v3.1); a CVE is requested if it applies. |
| 7-60 | Fix developed and reviewed privately. |
| ~90 | Patched release and advisory published together. |

A simple fix ships sooner. If a fix needs an API change we may agree a longer
window with you, never without telling you. If the issue is being exploited we
release immediately. Reporters are credited unless they ask not to be. There
is no bug bounty.

## Supported versions

The SDKs are pre-1.0. Only the latest release of each SDK receives security
fixes. Nothing is published to crates.io or NuGet yet; the Go module is
consumed by tag.

## Scope

In scope: the code in this repository, including SQL quoting and identifier
validation (injection through crafted identifiers or migration names), the
content-hash and tracking-table logic, credential handling in the CLIs, and
the schema-source loaders (`exec://` runs a command you give it, so reports
must show a way to make it run something the caller did not choose).

Out of scope: vulnerabilities in PostgreSQL, drivers or other dependencies
(report upstream; tell us if our use of them makes it worse), and migrations
that are themselves malicious: applying SQL you do not trust is, by design,
running it.

Dependencies are watched by Dependabot and CodeQL, and `govulncheck` runs on
every pull request.
