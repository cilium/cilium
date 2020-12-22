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

#. Ensure that the necessary features and fixes have been completed and merged
   into the branch for which the release candidate will happen.

   #. Update GitHub project and create ``vX.Y.Z-rcW+1`` project if applicable.
   #. Update PRs / issues that were added to the ``vX.Y.Z-rcW`` project, but didn't
      make it into this release into the ``vX.Y.Z-rcW+1`` project.

#. Checkout the desired stable branch (can be master branch if stable branch was
   not created) and pull it:

   ::

       git checkout v1.0; git pull

#. Create a branch for the release pull request:

   ::

       git checkout -b pr/prepare-v1.0.3

#. Update the ``AUTHORS file``

   ::

       make update-authors


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

   If a branch for ``vX.Y`` doesn't exist yet, then ensure the CRD schema
   version has not been incremented in the case there were no changes. If there
   were changes to the CRD, then ensure it is incremented at most by 1 patch
   version.

#. Add all modified files using ``git add`` and create a pull request with the
   title ``Prepare for release vX.Y.Z-rcW+1``. Add the backport label to the PR which
   corresponds to the branch for which the release is being performed, e.g.
   ``backport/1.0``.

   .. note::

       Make sure to create the PR against the desired stable branch. In this
       case ``v1.0``


#. Follow standard procedures to get the aforementioned PR merged into the
   desired stable branch. See :ref:`submit_pr` for more information about this
   process.

#. Checkout out the stable branch and pull your merged changes:

   ::

       git checkout v1.0; git pull

#. Check https://hub.docker.com and create a build for the new tag. This build
   will automatically be triggered when the tag is pushed to github.com

#. Create release tags:

   ::

       git tag -a v1.0.3 -m 'Release v1.0.3'
       git tag -a 1.0.3 -m 'Release 1.0.3'

   .. note::

       There are two tags that correspond to the same release because GitHub
       recommends using ``vx.y.z`` for release version formatting, and ReadTheDocs,
       which hosts the Cilium documentation, requires the version to be in format
       ``x.y.z`` For more information about how ReadTheDocs does versioning, you can
       read their `Versions Documentation <https://docs.readthedocs.io/en/latest/versions.html>`_.

#. Push the git release tag

   ::

       git push --tags


#. `Create a GitHub release <https://github.com/cilium/cilium/releases/new>`_:

   #. Choose the correct target branch, e.g. ``v1.0``
   #. Choose the correct target tag, e.g. ``v1.0.3``
   #. Title: ``1.0.3``
   #. Check the ``This is a pre-release`` box if you are releasing a release
      candidate.
   #. Fill in the release description:

      ::

           Summary of Changes
           ------------------

           **Important Bug Fixes**

           * Fix dropped packets upon agent bootstrap when iptables rules are installed (@ianvernon)

           **Enhancements**

           **Documentation**

           Changes
           -------

           ```
           << contents of NEWS.rst for this release >>
           ```

   #. Preview the description and then publish the release

#. Announce the release in the ``#general`` channel on Slack. Sample text:

   ::

      :cilium-new: Cilium release candidate vX.Y.Z-rcN has been released:
      https://github.com/cilium/cilium/releases/tag/vX.Y.Z-rcN

      This release is not recommended for use in production clusters, but if
      you're in a position to pull it and try it out in staging / testing
      environments and report issues that you find, this will help us to put
      out a high-quality, stable final release :)
