.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Organization
============

Release Cadence
---------------

New feature releases of Cilium are released on a cadence of around six months.
Minor releases are typically designated by incrementing the ``Y`` in the
version format ``X.Y.Z``.

Three stable branches are maintained at a time: One for the most recent minor
release, and two for the prior two minor releases. For each minor release that
is currently maintained, the stable branch ``vX.Y`` on github contains the code
for the next stable release. New patch releases for an existing stable version
``X.Y.Z`` are published incrementing the ``Z`` in the version format.

New patch releases for stable branches are made periodically to provide
security and bug fixes, based upon community demand and bugfix severity.
Potential fixes for an upcoming release are first merged into the ``main``
branch, then backported to the relevant stable branches according to the
:ref:`backport_criteria`.

The following sections describe in more detail the general guidelines that the
release management team follows for Cilium. The team may diverge from this
process at their discretion.

Feature Releases
~~~~~~~~~~~~~~~~

There are several key dates during the feature development cycle of Cilium
which are important for developers:

* Pre-release days: The Cilium release management team aims to publish a
  snapshot of the latest changes in the ``main`` branch on the first weekday of
  each month. This provides developers a target delivery date to incrementally
  ship functionality, and allows community members to get early access to
  upcoming features to test and provide feedback. Pre-releases may not be
  published when a release candidate or final stable release is being
  published.

* Feature freeze: Around six weeks prior to a target feature release, the
  ``main`` branch is frozen for new feature contributions. The goal of the
  freeze is to focus community attention on stabilizing and hardening the
  upcoming release by prioritizing bugfixes, documentation improvements, and
  tests. In general, all new functionality that the community intends to
  distribute as part of the upcoming release must land into the ``main`` branch
  prior to this date. Any bugfixes, docs changes, or testing improvements can
  continue to be merged as usual following this date.

* Release candidates: Following the feature freeze, the release management team
  publishes a series of release candidates. These candidates should represent
  the functionality and behaviour of the final release. The release management
  team encourages community participation in testing and providing feedback on
  the release candidates, as this feedback is crucial to identifying any issues
  that may not have been discovered during development. Problems identified
  during this period may be reported as known issues in the final release or
  fixed, subject to severity and community contributions towards solutions.
  Release candidates are typically published every two weeks until the final
  release is published.

* Branching and feature thaw: Within two weeks of the feature freeze, the
  release management team aims to create a new branch to manage updates for the
  new stable feature release series. After this, all Pull Requests for the
  upcoming feature release must be labeled with a ``needs-backport/X.Y`` label
  with ``X.Y`` matching the target minor release version to trigger the
  backporting process and ensure the changes are ported to the release branch.
  The ``main`` branch is then unfrozen for feature changes and refactoring.
  Until the final release date, it is better to avoid invasive refactoring or
  significant new feature additions just to minimize the impact on backporting
  for the upcoming release during that period.

* Stable release: The new feature release ``X.Y.0`` version is published. All
  restrictions on submissions are lifted, and the cycle begins again.

Stable Releases
~~~~~~~~~~~~~~~

The Cilium release management team typically aims to publish fresh releases for
all maintained stable branches around the middle of each month. All changes
that are merged into the target branch by the first week of the month should
typically be published in that month's patch release. Changes which do not land
into the target branch by that time may be deferred to the following month's
patch release. For more information about how patches are merged into the
``main`` branch and subsequently backported to stable branches, see the
:ref:`backport_process`.
