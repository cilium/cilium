.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _review_vendor:

****************************
Reviewing for @cilium/vendor
****************************

What is @cilium/vendor?
=======================

Team `@cilium/vendor <vendor_team_>`_ is a GitHub team of Cilium contributors
who are responsible for maintaining the good state of Go dependencies for
Cilium and its related projects by reviewing Pull Requests (PRs) that update
files related to dependency declaration:

* `go.mod <go_dot_mod_>`_
* `go.sum <go_dot_sum_>`_
* `vendor/ <vendor_slash_>`_

Each time a contributor opens a PR modifying these files, GitHub
automatically assigns one member of the team for review.

Open Pull Requests awaiting reviews from @cilium/vendor are
`listed here <vendor_to_review_>`_.

To join the team, you must be a Cilium Reviewer. see `Cilium's Contributor
Ladder <ladder_>`_ for details on the requirements and the application process.

The team has a dedicated Slack channel in the Cilium Community Slack Workspace
named `#sig-vendor <sig_vendor_slack_>`_, which can be used for starting discussions
and asking questions in regards to dependency management for Cilium and its related
projects.

.. _vendor_team: https://github.com/orgs/cilium/teams/vendor
.. _go_dot_mod: https://github.com/cilium/cilium/blob/main/go.mod
.. _go_dot_sum: https://github.com/cilium/cilium/blob/main/go.sum
.. _vendor_slash: https://github.com/cilium/cilium/blob/main/vendor
.. _vendor_to_review: https://github.com/pulls?q=is%3Aopen+is%3Apr+team-review-requested%3Acilium%2Fvendor+archived%3Afalse+org%3Acilium+
.. _ladder: https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md
.. _sig_vendor_slack: https://cilium.slack.com/archives/C07GZTL0Z1P

Reviewing Pull Requests
=======================

This section describes some of the processes and expectations for reviewing PRs
on behalf of @cilium/vendor. Note that :ref:`the generic PR review
process for Committers <review_process>` still applies, even though it is not
specific to dependencies.

Existing Dependencies
---------------------

Updates to existing dependencies most commonly occur through PRs opened by
`Renovate <renovate_>`_, which is a 3rd party service used throughout the
Cilium organization. Renovate continually checks repositories for out-of-date
dependencies and opens new PRs to update any it finds.

When reviewing PRs that update an existing dependency, members of the
@cilium/vendor team are required to ensure that the update does not include
any breaking changes or licensing issues. These checks are facilitated via
GitHub Action CI workflows, which are triggered by commenting ``/test`` within
a PR. See :ref:`CI  / GitHub Actions <ci_gha>` for more information on their
use.

.. _renovate: https://docs.renovatebot.com

New Dependencies
----------------

When a new dependency is added as part of a PR, the @cilium/vendor team will
be assigned to ensure the new dependency meets the following criteria:

1. The new dependency must add functionality that is not already provided, in
   order of preference, within Go's standard library, an internal package to the
   project, or an existing dependency.
2. The functionality provided by the new dependency must be non-trivial to
   re-implement manually.
3. The new dependency must be actively maintained, having new commits and/or
   releases within the past year.
4. The new dependency must appear to be of generally good quality, having a
   strong user base, automated testing with high code coverage, and documentation.
5. The new dependency must have a license which is allowed by the `CNCF <cncf_>`_,
   as either one of the `generally approved licenses <allowed_licenses_>`_ or one
   that is allowed via `exception <license_exceptions_>`_. An automated CI check
   is in place to help check this requirement, but may need updating as the list
   of allowable licenses by the CNCF changes and Cilium dependencies change. The
   source for the license check tool can be found `here <licensecheck_>`_.

These criteria ensure the long-term success of the project by justifying the
inclusion of the new dependency into the project's codebase.

.. _cncf: https://www.cncf.io
.. _allowed_licenses: https://github.com/cncf/foundation/blob/main/allowed-third-party-license-policy.md
.. _license_exceptions: https://github.com/cncf/foundation/tree/main/license-exceptions
.. _licensecheck: https://github.com/cilium/cilium/blob/main/tools/licensecheck/allowed.go

Cilium Imports
--------------

A subset of the repositories the @cilium/vendor team is responsible for import
code from cilium/cilium as a dependency. A complication in this relationship
is the usage of `replace directives <replace_directives_>`_ in the
`cilium/cilium go.mod file <go_dot_mod_>`_. Replace directives are only applied
to the main module's go.mod file and do not carry over when imported by
another module. This creates the need for replace directives used in
the cilium/cilium go.mod file to be synced with any module which imports
cilium/cilium as a dependency.

The vendor team is therefore responsible for explicitly discouraging the use
of replace directives where possible, due to the extra maintenance burden that
they incur.

A replace directive may be used if a required change to an imported
library is in the process of being upstreamed and a fork of the upstream library
is used as a temporary alternative until the upstream library is released with the
required change. The developer introducing the replace directive should ensure
that the replace directive will be removed before the next release, even if it
involves creating a fork of the upstream library and modifying import statements
of the library to point to the fork.

When a replace directive is added into the go.mod file, the vendor team is
responsible for the following:

1. A comment is added above the replace directive in the go.mod file describing the
   reason it was added.
2. An issue is created in the project's repository with a ``release-blocker`` label
   attached, tracking the removal of the replace directive before the next release
   of the project. The issue should be assigned to the developer who added the
   replace directive.
3. Ensuring that replace directives are synced when reviewing PRs which update the
   version of a cilium/cilium dependency.

If a change that is required to be made to an imported library cannot be upstreamed,
the library's import in the go.mod file should be changed to directly use a fork of
the library containing the change, avoiding the need for a replace directive. For
an example of this change, see `cilium/cilium#27582 <cilium_cilium_27582_>`_.

.. _replace_directives: https://go.dev/ref/mod#go-mod-file-replace
.. _cilium_cilium_27582: https://github.com/cilium/cilium/pull/27582
