.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Organization
============

Release tracking
----------------

Feature work for upcoming releases is tracked through GitHub Projects. You can
view the projects related to the \ |NEXT_RELEASE| release here:

* :github-project:`GitHub release projects<>`

Release Cadence
---------------

New versions of Cilium are released based on completion of feature work that
has been scheduled for that release. Minor releases are typically designated by
by incrementing the ``Y`` in the version format ``X.Y.Z``.

Three stable branches are maintained at a time: One for the most recent minor
release, and two for the prior two minor releases. For each minor release that
is currently maintained, the stable branch ``vX.Y`` on github contains the code
for the next stable release. New patch releases for an existing stable version
``X.Y.Z`` are published incrementing the ``Z`` in the version format.

New patch releases for stable branches are made periodically to provide
security and bug fixes, based upon community demand and bugfix severity.
Potential fixes for an upcoming release are first merged into the ``main``
branch, then backported to the relevant stable branches using the following
criteria.
