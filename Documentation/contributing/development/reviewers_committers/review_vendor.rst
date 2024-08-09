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
Cilium and it's related projects by reviewing Pull Requests (PRs) that update
files related to dependency declaration:

* `go.mod <go_dot_mod_>`_
* `go.sum <go_dot_sum_>`_
* `vendor/ <vendor_slash_>`_

Each time a non-draft PR touching files owned by the team opens, GitHub
automatically assigns one member of the team for review. The team is currently
responsible for reviewing changes related to Go dependencies in the following
repositories:

* `cilium/cilium <cilium_slash_cilium_reviews_>`_
* `cilium/hubble <cilium_slash_hubble_reviews_>`_
* `cilium/cilium-cli <cilium_slash_cilium_cli_reviews_>`_
* `cilium/certgen <cilium_slash_certgen_reviews_>`_

Open Pull Requests awaiting reviews from @cilium/vendor are listed by repository
through the previously listed links.

To join the team, you must be a Cilium Reviewer. see `Cilium's Contributor
Ladder <ladder_>`_ for details on the requirements and the application process.

.. _vendor_team: https://github.com/orgs/cilium/teams/vendor
.. _go_dot_mod: https://github.com/cilium/cilium/blob/main/go.mod
.. _go_dot_sum: https://github.com/cilium/cilium/blob/main/go.sum
.. _vendor_slash: https://github.com/cilium/cilium/blob/main/vendor
.. _cilium_slash_cilium_reviews: https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+team-review-requested%3Acilium%2Fvendor
.. _cilium_slash_hubble_reviews: https://github.com/cilium/hubble/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+team-review-requested%3Acilium%2Fvendor
.. _cilium_slash_cilium_cli_reviews: https://github.com/cilium/cilium-cli/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+team-review-requested%3Acilium%2Fvendor
.. _cilium_slash_certgen_reviews: https://github.com/cilium/certgen/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+team-review-requested%3Acilium%2Fvendor
.. _ladder: https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md

Reviewing Pull Requests
=======================

This section describes some of the process and expectations for reviewing PRs
on behalf of @cilium/vendor. Note that :ref:`the generic PR review
process for Committers <review_process>` still applies, even though it is not
specific to dependencies.

Existing Dependencies
---------------------

Updates to existing dependencies most commonly occur through PRs opened by
`Renovate <renovate_>`_, which is a 3rd party service used throughout the
Cilium organization. Renovate continually checks repositories for out-of-date
dependencies and opens new PRs to update any it finds.

.. note::
   Renovate is configured via a file named ``renovate.json5`` found within the
   ``.github/`` folder of each repository it is enabled on. Cilium's Renovate
   configuration is long and complex, having been developed to enable
   dependency updates to Docker images and GitHub Actions. Only a few pieces
   of the configuration are relevant to the @cilium/vendor team.

.. _renovate: https://docs.renovatebot.com

When reviewing PRs that update an existing dependency, members of the
@cilium/vendor team are required to ensure that the update does not include
any breaking changes or licensing issues. These checks are facilitated via
GitHub Action CI workflows, which are triggered by commenting ``/test`` within
a PR. See :ref:`CI  / GitHub Actions <ci_gha>` for more information on their
use.

New Dependencies
----------------

When a new dependency is added as part of a PR, the @cilium/vendor team will
be assigned to ensure the new dependency meets the following criteria:

1. The new dependency must add functionality that is not already provided within
   an existing dependency, an internal package to the project, or Go's
   standard library.
2. The functionality provided by the new dependency must be non-trivial to
   re-implement manually.
3. The new dependency must be actively maintained, having new commits and/or
   releases within the past year.
4. The new dependency must appear to be of generally good quality.

These criteria ensure the long-term success of the project by justifying the
inclusion of the new dependency into the project's codebase.

Cilium Imports
--------------

A subset of the repositories the @cilium/vendor team is responsible for import
code from cilium/cilium as a dependency. A complication in this relationship
is the usage of `replace directives <replace_directives_>`_ in the
`cilium/cilium go.mod file <go_dot_mod_>`_. Replace directives are only applied
to the go.mod file they are used in and do not carry over when imported by
another modules. This creates the need for replace directives used in
the cilium/cilium go.mod file to by synced with any module which imports
cilium/cilium as a dependency.

The vendor team is therefore responsible for ensuring that replace directives
are synced when reviewing PRs which update the version of a cilium/cilium
dependency.

.. _replace_directives: https://go.dev/ref/mod#go-mod-file-replace
