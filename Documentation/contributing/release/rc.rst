.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _release_candidate_process:

Release Candidate Process
-------------------------

This process applies to all releases candidates:

If you intent to release a new feature release, see the
:ref:`minor_release_process` section instead.

.. note:: The following commands have been validated when ran in the VM
          used in the Cilium development process. See :ref:`dev_env` for
          detailed instructions about setting up said VM.

GitHub template process
~~~~~~~~~~~~~~~~~~~~~~~

#. File a `new release issue <https://github.com/cilium/cilium/issues/new?assignees=&labels=kind%2Frelease&template=release_template.md&title=vX.Y.Z+release>`_
   on GitHub, updating the title to reflect the version that will be released.

#. Follow the steps in the issue template to prepare the release.

Reference steps for the template
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   These instructions will generate a CHANGELOG based on the time when the
   ``start-release.sh`` script is run, so you should aim to coordinate with
   the core maintainers to complete these steps up until merging the PR
   before merging additional PRs from contributors.

#. Ensure that the necessary features and fixes have been completed and merged
   into the branch for which the release candidate will happen.

   #. Update GitHub project and create ``vX.Y.Z-rcW+1`` project if applicable.
   #. Update PRs / issues that were added to the ``vX.Y.Z-rcW`` project, but didn't
      make it into this release into the ``vX.Y.Z-rcW+1`` project.
   #. The `Cilium Release Tool <https://github.com/cilium/release>`__ tool can
      help to manage these for you.

#. Checkout the desired stable branch (can be master branch if stable branch was
   not created) and pull it:

   .. code-block:: shell-session

       git checkout v1.0; git pull

#. Run the release preparation script:

   .. code-block:: shell-session

       contrib/release/start-release.sh

   .. note::

       Check to see if the ``AUTHORS`` file has any formatting errors (for
       instance, indentation mismatches) as well as duplicate contributor
       names, and correct them accordingly.

#. Set the right version for the ``CustomResourceDefinitionSchemaVersion`` in
   the ``pkg/k8s/client`` by following these instructions:

   If you are doing the first RC for a new minor version, the validation schema
   version should be ``vX.Y.1`` regardless of the value set in
   ``CustomResourceDefinitionSchemaVersion``. For example, when setting up the
   first RC for Cilium ``1.11``, ``1.11.0-rc1``, the validation schema should be
   ``vX.Y+1.1`` where ``X`` and ``Y`` are the major and minor versions used in
   the schema version of Cilium ``1.10``.

   If this is not the first RC run, and there is a branch for ``vX.Y``:

   Run ``./Documentation/check-crd-compat-table.sh vX.Y``

   If a branch for ``vX.Y`` doesn't exist yet, then manually ensure the CRD
   schema version has not been incremented in the case there were no changes. If
   there were changes to the CRD, then ensure it is incremented at most by 1
   patch version.

#. If this release will be based on the ``master`` branch rather than a stable
   branch, add the AUTHORS modifications to a new commit.

#. Add all other modified files using ``git add`` and create a commit with the
   title ``Prepare for release vX.Y.Z-rcW+1``.

#. Prepare a pull request for the changes:

   .. code-block:: shell-session

      contrib/release/submit-release.sh

#. Ensure that the CI smoke tests and reviews are in for the pull request.

#. Revert the top commit on the branch and push the branch again to GitHub.

#. Follow standard procedures to get the aforementioned PR merged into the
   desired stable branch. See :ref:`submit_pr` for more information about this
   process.

#. Checkout out the stable branch and pull your merged changes:

   .. code-block:: shell-session

       git checkout v1.0; git pull

#. Check out the "Prepare for release" commit and create release tags:

   .. code-block:: shell-session

      git checkout NNNN && contrib/release/tag-release.sh

   .. note::

       There are two tags that correspond to the same release because GitHub
       recommends using ``vx.y.z`` for release version formatting, and ReadTheDocs,
       which hosts the Cilium documentation, requires the version to be in format
       ``x.y.z`` For more information about how ReadTheDocs does versioning, you can
       read their `Versions Documentation <https://docs.readthedocs.io/en/latest/versions.html>`_.

#. Approve the release from the `Release Image build UI <https://github.com/cilium/cilium/actions?query=workflow:%22Image+Release+Build%22>`_.

#. Once the release images are pushed, fetch the digests from the workflow.

#. Prepare Helm changes for the release using the `Cilium Helm Charts Repository <https://github.com/cilium/charts/>`__
   and push the changes into that repository (not the main cilium repository):

   .. code-block:: shell-session

      ./prepare_artifacts.sh /path/to/cilium/repository/checked/out/to/release/commit
      git push

#. Wait for the `Cilium Helm Charts Workflow <https://github.com/cilium/charts/actions>`__
   to successfully deploy a cluster using the new Helm charts.

#. `Publish a GitHub release <https://github.com/cilium/cilium/releases/>`_:

   Following the steps above, the release draft will already be prepared.

   #. Check the ``This is a pre-release`` box.
   #. Copy the official docker manifests for the release from the previous step
      into the end of the Github release announcement.
   #. Preview the description and then publish the release

#. Announce the release in the ``#general`` channel on Slack. Sample text:

   ::

      :cilium-new: Cilium release candidate vX.Y.Z-rcN has been released:
      https://github.com/cilium/cilium/releases/tag/vX.Y.Z-rcN

      This release is not recommended for use in production clusters, but if
      you're in a position to pull it and try it out in staging / testing
      environments and report issues that you find, this will help us to put
      out a high-quality, stable final release :)
