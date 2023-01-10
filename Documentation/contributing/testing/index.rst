.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

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
   :maxdepth: 2
   :glob:

   ci
   e2e
   unit
   bpf

The best way to get help if you get stuck is to ask a question on the `Cilium
Slack channel <https://cilium.herokuapp.com>`_.  With Cilium contributors
across the globe, there is almost always someone available to help.
