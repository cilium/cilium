# Security Policy

## Supported Versions

| Version  | Supported          |
|----------| ------------------ |
| main     | :white_check_mark: |
| 1.19.x   | :white_check_mark: |
| 1.18.x   | :white_check_mark: |
| 1.17.x   | :white_check_mark: |
| < 1.17.0 | :x:                |

## Reporting a Vulnerability

We strongly encourage you to report security vulnerabilities to
our private security mailing list: security@cilium.io - first, before
disclosing them in any public forums.

This is a private mailing list where members of Cilium's
[Security Team](https://github.com/cilium/community/blob/main/roles/Security-Team.md)
are subscribed to, and is treated as top priority.

### Scope

A threat model for Cilium and recommendations for running Cilium in production
environments can be found [here][threat-model]. Please ensure that you have
taken this threat model into consideration before making a report, including
considering the feasibility of an attack against a correctly secured
environment.

#### Issues with Cilium's CI or GitHub workflows

The project does not consider issues affecting Cilium's CI to be in
scope if they only show CI infrastructure being used to build contributor code
and push build artifacts to Cilium's development artifact repositories (any
repository matching the pattern `quay.io/cilium/*-ci`). Artifacts in these
repositories are not treated as trusted by the Cilium project and should not be
trusted by Cilium users.

CI issues are in typically in scope if they can be shown to lead to the compromise
of Cilium release artifacts or release infrastructure. Some examples of such
issues are:

- Issues that lead to the compromise of credentials that can then be used to modify
  release artifacts
- Issues that would allow an attacker to bypass required functional or security
  testing, with the aim of introducing unstable or malicious code in stable Cilium
  releases
- Issues that demonstrate compromise of Cilium's container signing workflow

### Disclosure

The project aims to acknowledge all contributors for valid reports of security
issues. For reports that affect stable features in Cilium, the project will
release a GitHub security advisory with an associated CVE ID; reporters will be
credited by name/GitHub handle in the advisory. Disclosure will typically be
made at or shortly after the release of patched versions of Cilium.

The security team will decide whether a report meets the requirements for a GitHub
advisory and CVE ID on a case-by-case basis.

Some reports may lead to changes in the Cilium codebase even if they do not result
in an associated advisory. Examples of reports that may fall into this category
include (but are not limited to):

- Reports of issues in unstable functionality, including beta features
- Reports of issues where there is no evidence that a stable release of Cilium
  is affected by the issue

In such cases, the project aims to credit reporters with an acknowledgement in
the relevant fix commit via a `Reported-by:` trailer in the commit message.

[threat-model]: https://docs.cilium.io/en/latest/security/threat-model/
