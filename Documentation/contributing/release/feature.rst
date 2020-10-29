.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _minor_release_process:

Feature Release Process
=======================

This document describes the process for creating a major or minor feature
release of Cilium.

On Freeze date
--------------

#. Fork a new release branch from master:

   ::

       git checkout master; git pull
       git checkout -b v1.2
       git push

#. Protect the branch using the GitHub UI to disallow direct push and require
   merging via PRs with proper reviews.

#. Replace the contents of the ``CODEOWNERS`` file with the following to reduce
   code reviews to essential approvals:

   ::

        * @cilium/janitors
        api/ @cilium/api
        pkg/apisocket/ @cilium/api
        pkg/monitor/payload @cilium/api
        pkg/policy/api/ @cilium/api
        pkg/proxy/accesslog @cilium/api

#. Set the right version for the ``CustomResourceDefinitionSchemaVersion`` in
   the ``pkg/k8s/...`` by following these instructions:

   Run ``./Documentation/check-crd-compat-table.sh vX.Y``

#. Commit changes, open a pull request against the new ``v1.2`` branch, and get
   the pull request merged

   ::

       git checkout -b pr/prepare-v1.2
       git add [...]
       git commit
       git push

#. Follow the :ref:`release_candidate_process` to release ``v1.2.0-rc1``.

#. Create the following GitHub labels:

   #. ``backport-pending/1.2``
   #. ``backport-done/1.2``
   #. ``backport/1.2``
   #. ``needs-backport/1.2``

#. Prepare the master branch for the next development cycle:

   ::

       git checkout master; git pull

#. Update the ``VERSION`` file to contain ``v1.2.90``
#. Add the ``VERSION`` file using ``git add`` and create & merge a PR titled
   ``Prepare for 1.3.0 development``.
#. Update the release branch on
    `Jenkins <https://jenkins.cilium.io/job/cilium-ginkgo/job/cilium/>`_ to be
    tested on every change and Nightly.
#. (Only 1.0 minor releases) Tag newest 1.0.x Docker image as ``v1.0-stable``
   and push it to Docker Hub. This will ensure that Kops uses latest 1.0 release by default.


For the final release
---------------------

#. Follow the :ref:`generic_release_process` to create the final replace and replace
   ``X.Y.0-rcX`` with ``X.Y.0``.
