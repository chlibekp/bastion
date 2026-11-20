# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

Only the latest 0.1 release gets security fixes.

## Reporting a vulnerability

**Owner action required:** no security contact has been set up yet. Before the first public
release, the project owner must replace the placeholder below with a real, monitored address (or
enable GitHub private vulnerability reporting and link it here). Nobody should send reports to
the placeholder.

- Contact: `<SECURITY-CONTACT-TO-BE-FILLED-IN-BY-OWNER>`

Please do not open a public issue for a vulnerability. Include the version (`bastion --version`), the
configuration needed to reproduce, and the impact you see. We aim to acknowledge a report within
5 working days and to agree a disclosure date with you; 90 days is the default.

## Scope

In scope: the `bastion` binary, its default configuration, the packages and container image built
from this repository. Out of scope: vulnerabilities in the pinned third-party libraries
(`deps/versions.env`), which should go to their upstream projects, unless Bastion uses them
unsafely.

## Security design

- Threat model, accepted risks: [docs/threat-model.md](docs/threat-model.md)
- Static analysis, hand audit, seccomp allowlist review: [docs/security.md](docs/security.md)

Bastion has had automated review only. An independent human security audit is recommended before
any internet-facing production use.
