.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _contribute_guide:

*****************
Contributor Guide
*****************

We're happy you're interested in contributing to the Cilium project.

.. _dev_guide:

Development
-----------

This section of the Cilium documentation  will help you make sure you have an
environment capable of testing changes to the Cilium source code, and that you
understand the workflow of getting these changes reviewed and merged upstream.

.. toctree::
   :maxdepth: 3

   development/contributing_guide
   development/dev_setup
   development/images
   development/codeoverview
   development/debugging
   development/hubble
   development/introducing_new_crds
   development/season_of_docs

.. _release_management:

Release Management
------------------

This section describes the release processes for tracking, preparing, and
creating new Cilium releases. This includes information around the release
cycles and guides for developers responsible for backporting fixes or preparing
upcoming stable releases.

.. toctree::
   :maxdepth: 2

   release/organization
   release/backports
   release/stable
   release/rc
   release/feature

.. _testing_guide:

Testing
-------

There are multiple ways to test Cilium functionality, including unit-testing
and integration testing. In order to improve developer throughput, we provide
ways to run both the unit and integration tests in your own workspace as opposed
to being fully reliant on the Cilium CI infrastructure. We encourage all PRs to
add unit tests and if necessary, integration tests. Consult the following pages
to see how to run the variety of tests that have been written for Cilium, and
information about Cilium's CI infrastructure.

.. _testing_root:

.. toctree::
   :maxdepth: 1
   :glob:

   testing/ci
   testing/e2e
   testing/unit

.. _docs_guide:

Documentation
-------------

This section describes the style and testing methods of Cilium documentation.

.. toctree::
   :maxdepth: 1
   :glob:

   docs/docsstyle
   docs/docstest

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.