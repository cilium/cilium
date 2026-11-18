# Security Policy

## Supported Versions

| Version  | Supported          |
|----------| ------------------ |
| main     | :white_check_mark: |
| 1.20.x   | :white_check_mark: |
| 1.19.x   | :white_check_mark: |
| 1.18.x   | :white_check_mark: |
| < 1.18.0 | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities privately through
[Cilium's vulnerability reporting form](https://github.com/cilium/cilium/security/advisories/new)
before disclosing them in any public forums. Reports submitted through this
form will be treated with high priority by the Cilium Security Team.

For enquiries and reports not related to Cilium software, contact the Cilium
security team via security@cilium.io.

### Scope

A threat model for Cilium and recommendations for running Cilium in production
environments can be found [here][threat-model]. Please ensure that you have
taken this threat model into consideration before making a report, including
considering the feasibility of an attack against a correctly secured
environment.

Issues that only affect beta features do not need a private report. Please
open a [public GitHub issue](https://github.com/cilium/cilium/issues/new/choose)
for them.

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

- Reports of issues where there is no evidence that a stable release of Cilium
  is affected by the issue

In such cases, the project aims to credit reporters with an acknowledgement in
the relevant fix commit via a `Reported-by:` trailer in the commit message.

[threat-model]: https://docs.cilium.io/en/latest/security/threat-model/
