---
name: Bug Report
about: Report a bug encountered while operating Cilium
title: ''
labels: 'kind/bug'
assignees: ''

---

<!--

If you have usage questions, please try the [slack
channel](http://cilium.io/slack) and see the [FAQ](https://goo.gl/qG2YmU)
first.

Choose either "Proposal" or "Bug report"

-->

## Bug report

<!--

Important: For security related issues: We strongly encourage you to report
security vulnerabilities to our private security mailing list:
security@cilium.io - first, before disclosing them in any public forums.

-->

**General Information**

- Cilium version (run `cilium version`)
- Kernel version (run `uname -a`)
- Orchestration system version in use (e.g. `kubectl version`, ...)
- Link to relevant artifacts (policies, deployments scripts, ...)
- Generate and upload a system zip:
```
curl -sLO https://git.io/cilium-sysdump-latest.zip && python cilium-sysdump-latest.zip
```

**How to reproduce the issue**

1. instruction 1
2. instruction 2
