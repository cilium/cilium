.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _generic_release_process:

Generic Release Process
-----------------------

This process applies to all releases other than feature releases, this includes:

* Stable releases

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

#. Ensure that the necessary backports have been completed and merged. See
   :ref:`backport_process`.

   #. Update GitHub project and create ``vX.Y.Z+1`` project if applicable.
   #. Update PRs / issues that were added to the ``vX.Y.Z`` project, but didn't
      make it into this release into the ``vX.Y.Z+1`` project.

#. Create a new project named "X.Y.Z+1" to automatically track the backports
   for that particular release. `Direct Link: <https://github.com/cilium/cilium/projects/new>`_

#. Checkout the desired stable branch and pull it:

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

   Run ``./Documentation/check-crd-compat-table.sh vX.Y``

#. Add all modified files using ``git add`` and create a commit with the
   title ``Prepare for release v1.0.3``.

#. Prepare a pull request for the changes:

   .. code-block:: shell-session

      contrib/release/submit-release.sh

#. Follow standard procedures to get the aforementioned PR merged into the
   desired stable branch. See :ref:`submit_pr` for more information about this
   process.

#. Checkout out the stable branch and pull your merged changes:

   .. code-block:: shell-session

       git checkout v1.0; git pull

#. Create and push release tags to GitHub:

   .. code-block:: shell-session

      contrib/release/tag-release.sh

   .. note::

       There are two tags that correspond to the same release because GitHub
       recommends using ``vx.y.z`` for release version formatting, and ReadTheDocs,
       which hosts the Cilium documentation, requires the version to be in format
       ``x.y.z`` For more information about how ReadTheDocs does versioning, you can
       read their `Versions Documentation <https://docs.readthedocs.io/en/latest/versions.html>`_.

#. Approve the release from the `Release Image build UI <https://github.com/cilium/cilium/actions?query=workflow:%22Image+Release+Build%22>`_.

#. Once the release images are pushed, pull the image digests and prepare a PR with the official release image digests:

   .. code-block:: shell-session

      contrib/release/post-release.sh <URL of workflow run from the release link above>

   This will leave a file with the format ``digest-vX.Y.Z.txt`` in the local
   directory which can be used to prepare the release in the next step.

#. `Publish a GitHub release <https://github.com/cilium/cilium/releases/>`_:

   Following the steps above, the release draft will already be prepared.
   Preview the description and then publish the release.

   #. Copy the official docker manifests for the release from the previous step
      into the end of the Github release announcement.

#. Prepare Helm changes for the release using the `Cilium Helm Charts Repository <https://github.com/cilium/charts/>`__
   and push the changes into that repository (not the main cilium repository):

   .. code-block:: shell-session

      ./prepare_artifacts.sh /path/to/cilium/repository/checked/out/to/release/commit
      git push

#. Prepare Helm changes for the dev version of the branch using the `Cilium Helm Charts Repository <https://github.com/cilium/charts/>`__
   for the vX.Y helm charts, and push the changes into that repository (not the main cilium repository):

   In the ``cilium/cilium`` repository:

   #. ``git checkout vx.y -b vx.z-dev``
   #. Change the ``VERSION`` file to ``x.y-dev``
   #. Run ``make -C install/kubernetes``

   In the ``cilium/charts`` repository:

   .. code-block:: shell-session

      ./prepare_artifacts.sh /path/to/cilium/repository/checked/out/to/release/commit
      git push

   After pushing you can revert all the changes made in the local branch
   ``x.y-dev`` from ``cilium/cilium``.

#. Announce the release in the ``#general`` channel on Slack. Sample text:

   ::

      :cilium-new: **Announcement:** Cilium vX.Y.Z has been released :tada:

      <If security release or major bugfix, short summary of fix here>

      For more details, see the release notes:
      https://github.com/cilium/cilium/releases/tag/vX.Y.Z

#. Create a new git branch based on the master branch to update ``README.rst``:

   .. code-block:: shell-session

      $ git checkout -b pr/bump-readme-vX.Y.Z origin/master
      $ contrib/release/bump-readme.sh
      $ # (Commit changes & submit PR)

#. Bump the version of Cilium used in the Cilium upgrade tests to use the new release

   Please reach out on the ``#development`` channel on Slack for assistance with
   this task.

#. Update the ``stable`` tags for ``cilium``, ``cilium-operator``,
   ``cilium-operator-aws``, ``cilium-operator-azure``,
   ``cilium-operator-generic``, ``cilium-docker-plugin``, ``hubble-relay`` and
   ``clustermesh-apiserver`` on DockerHub, for the latest version of Cilium.
   For example, if the latest version is ``1.8``, then for all patch releases
   on the ``1.8`` line, this step should be performed. Once ``1.9`` is out for
   example, then this is no longer required for ``1.8`` or earlier releases.

   .. code-block:: shell-session

       contrib/release/bump-docker-stable.sh X.Y.Z

#. Check if all docker images are available before announcing the release:

   .. code-block:: shell-session

      make -C install/kubernetes/ check-docker-images

#. Update the following external tools and guides to point to the released
   Cilium version. This step is only required on a new minor release like going
   from ``1.8`` to ``1.9``.

    * `kubeadm <https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/>`_
    * `kops <https://github.com/kubernetes/kops/>`_
    * `kubespray <https://github.com/kubernetes-sigs/kubespray/>`_

