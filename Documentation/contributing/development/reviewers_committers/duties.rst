.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _periodic_duties:

Periodic duties
===============

Some members of the Cilium organization have rotational duties that change
periodically.

Release managers
----------------

Release managers take care of the patch releases for each supported stable
branch of Cilium. They typically coordinate in ``#launchpad`` on `Cilium
Slack`_.

Backporters
-----------

Backporters handle backports to Cilium's supported stable branches. They
typically coordinate in ``#launchpad`` on `Cilium Slack`_. The
:ref:`backport_process` provides some guidance on how to backport changes.

Triagers
--------

Triagers take care of several tasks:

  - They push and merge contributions from community contributors
  - They review updates to files without a dedicated code owner
  - They triage bugs, which means they interact with reporters until the issue
    is clear and can get the label associated to the corresponding working
    group, when possible
  - They keep an eye on `Cilium Slack`_, to try and answer questions from the
    community

They are members of the `TopHat team`_ on GitHub.

.. _TopHat team: https://github.com/orgs/cilium/teams/tophat/members

CI Health managers
------------------

CI Health managers monitor the status of the CI, track down flakes, and ensure
that CI checks keep running smoothly. They typically coordinate in ``#testing``
on `Cilium Slack`_.
