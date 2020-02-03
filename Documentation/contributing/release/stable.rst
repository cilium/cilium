.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

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

#. Ensure that the necessary backports have been completed and merged. See
   :ref:`backport_process`.

   #. Update GitHub project and create ``vX.Y.Z+1`` project if applicable.
   #. Update PRs / issues that were added to the ``vX.Y.Z`` project, but didn't
      make it into this release into the ``vX.Y.Z+1`` project.

#. Checkout the desired stable branch and pull it:

   ::

       git checkout v1.0; git pull

#. Create a branch for the release pull request:

   ::

       git checkout -b pr/prepare-v1.0.3

#. Update the ``VERSION`` file to represent ``X.Y.Z+1``
#. If this is the first release after creating a new release branch. Adjust the
   image pull policy for all ``.sed`` files in ``install/kubernetes/cilium/values.yaml`` from
   ``Always`` to ``IfNotPresent``.
#. Update Helm chart documentation

   #. Update versions in ``install/kubernetes/quick-install.yaml``
   #. Update ``version`` and ``appVersion`` in ``install/kubernetes/cilium/Chart.yaml``
   #. Update version tag in ``install/kubernetes/cilium/values.yaml``

#. Update the image tag versions in the examples:

   ::

       make -C install/kubernetes clean all

#. Update the ``cilium_version`` and ``cilium_tag`` variables in
   ``examples/getting-started/Vagrantfile``

#. Update the ``AUTHORS file``

   ::

       make update-authors


   .. note::

       Check to see if the ``AUTHORS`` file has any formatting errors (for
       instance, indentation mismatches) as well as duplicate contributor
       names, and correct them accordingly.


#. Generate the ``NEWS.rst`` addition based off of the prior release tag
   (e.g., if you are generating the ``NEWS.rst`` for v1.0.3):

   ::

       git shortlog v1.0.2.. > add-to-NEWS.rst

#. Add a new section to ``NEWS.rst``:

    ::

        v1.0.3
        ======

        ::

            <<contents of add-to-NEWS.rst>>
            [...]
            <<end of add-to-NEWS.rst>>

#. Add all modified files using ``git add`` and create a pull request with the
   title ``Prepare for release v1.0.3``. Add the backport label to the PR which
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

#. Build the container images and push them

   ::

      DOCKER_IMAGE_TAG=v1.0.3 make docker-image
      docker push cilium/cilium:v1.0.3

   .. note:

      This step requires you to login with ``docker login`` first and it will
      require your Docker hub ID to have access to the ``Cilium`` organization.
      You can alternatively trigger a build on DockerHub directly if you have
      credentials to do so.

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

#. Build the binaries and push it to the release bucket:

   ::

       DOMAIN=releases.cilium.io ./contrib/release/uploadrev v1.0.3


   This step will print a markdown snippet which you will need when crafting
   the GitHub release so make sure to keep it handy.

   .. note:

       This step requires valid AWS credentials to be available via the
       environment variables ``AWS_ACCESS_KEY_ID`` and
       ``AWS_SECRET_ACCESS_KEY``. Ping in the ``#development`` channel on Slack
       if you have no access. It also requires the aws-cli tools to be installed.

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

           Release binaries
           ----------------

           << contents of snippet outputed by uploadrev >>

   #. Preview the description and then publish the release

#. Announce the release in the ``#general`` channel on Slack

#. Update the ``README.rst#stable-releases`` section from the Cilium master branch

#. Bump the version of Cilium used in the Cilium upgrade tests to use the new release

   Please reach out on the ``#development`` channel on Slack for assistance with
   this task.

#. Update the ``stable`` tags for ``cilium``, ``cilium-operator``, and
   ``cilium-docker-plugin`` on DockerHub.

#. Update the external tools and guides to point to the released Cilium version:

    * `kubeadm <https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/>`_
    * `kops <https://github.com/kubernetes/kops/>`_
    * `kubespray <https://github.com/kubernetes-sigs/kubespray/>`_

