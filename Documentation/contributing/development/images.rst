.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _container_images:

Building Container Images
=========================

Two make targets exists to build container images automatically based on the
locally checked out branch:

Developer images
~~~~~~~~~~~~~~~~

Run ``make dev-docker-image`` to build a cilium-agent Docker image that
contains your local changes.

::

    DOCKER_DEV_ACCOUNT=quay.io/myaccount DOCKER_IMAGE_TAG=jane-developer-my-fix make dev-docker-image

Run ``make docker-operator-generic-image`` (respectively,
``docker-operator-aws-image`` or ``docker-operator-azure-image``) to build the
cilium-operator Docker image:

::

    DOCKER_DEV_ACCOUNT=quay.io/myaccount DOCKER_IMAGE_TAG=jane-developer-my-fix make docker-operator-generic-image

The commands above assumes that your username for ``quay.io`` is ``myaccount``.
You can then push the image tag to your own registry for development builds:

::

    docker push quay.io/myaccount/cilium-dev:jane-developer-my-fix-amd64

Official release images
~~~~~~~~~~~~~~~~~~~~~~~

Anyone can build official release images using the make target below.

::

    DOCKER_IMAGE_TAG=v1.4.0 make docker-images-all

Official Cilium repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following table contains the main container image repositories managed by
Cilium team. It is planned to convert the build process for all images based
on GH actions.

+-------------------------------+---------------------------------------------+-----------------------------------------------+-------------------------+-------------------+
|     **Github Repository**     |                **Dockerfile**               |      **container image repository**           |   **Architectures**     | **Build process** |
|                               |                                             |                                               +-----------+-------------+                   |
|                               |                                             |                                               | **amd64** | **aarch64** |                   |
+-------------------------------+---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
| github.com/cilium/cilium      | contrib/packaging/docker/Dockerfile.runtime | quay.io/cilium/cilium-runtime                 |     Y     |      N      |     Quay auto     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | Dockerfile.builder                          | quay.io/cilium/cilium-builder                 |     Y     |      N      |     Quay auto     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | Dockerfile                                  | [docker|quay].io/cilium/cilium                |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | cilium-docker-plugin.Dockerfile             | [docker|quay].io/cilium/docker-plugin         |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | hubble-relay.Dockerfile                     | [docker|quay].io/cilium/hubble-relay          |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | cilium-operator.Dockerfile                  | [docker|quay].io/cilium/operator              |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | cilium-operator-aws.Dockerfile              | [docker|quay].io/cilium/operator-aws          |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | cilium-operator-azure.Dockerfile            | [docker|quay].io/cilium/operator-azure        |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | cilium-operator-generic.Dockerfile          | [docker|quay].io/cilium/operator-generic      |     Y     |      N      |  Quay/Docker auto |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | clustermesh-apiserver.Dockerfile            | [docker|quay].io/cilium/clustermesh-apiserver |     Y     |      N      |  Quay/Docker auto |
+-------------------------------+---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
| github.com/cilium/proxy       | Dockerfile.builder                          | quay.io/cilium/cilium-envoy-builder           |     Y     |      N      |     Quay auto     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | Dockerfile                                  | quay.io/cilium/cilium-envoy                   |     Y     |      N      |     Quay auto     |
+-------------------------------+---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/bpftool/Dockerfile                   | docker.io/cilium/cilium-bpftool               |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/iproute2/Dockerfile                  | docker.io/cilium/cilium-iproute2              |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/llvm/Dockerfile                      | docker.io/cilium/cilium-llvm                  |     Y     |      Y      |     GH Action     |
| github.com/cilium/image-tools +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/compilers/Dockerfile                 | docker.io/cilium/image-compilers              |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/maker/Dockerfile                     | docker.io/cilium/image-maker                  |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/startup-script/Dockerfile            | docker.io/cilium/startup-script               |     Y     |      Y      |     GH Action     |
+-------------------------------+---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+

Image dependency:

::

    [docker|quay].io/cilium/cilium
     depends on:
      quay.io/cilium/cilium-builder
       depends on:
        quay.io/cilium/cilium-runtime
         depends on:
          docker.io/cilium/cilium-iproute2
          docker.io/cilium/cilium-bpftool
          docker.io/cilium/cilium-llvm
      quay.io/cilium/cilium-envoy
       depends on:
        quay.io/cilium/cilium-envoy-builder
         depends on:
          quay.io/cilium/cilium-builder
           depends on:
            quay.io/cilium/cilium-runtime
             depends on:
              docker.io/cilium/cilium-iproute2
              docker.io/cilium/cilium-bpftool
              docker.io/cilium/cilium-llvm


Update cilium-builder and cilium-runtime images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section will require you to install `Skopeo <https://github.com/containers/skopeo>`__.

Login to quay.io with your credentials to the repository that you want to
update:

`cilium-runtime <https://hub.docker.com/repository/docker/cilium/cilium-runtime-dev/builds>`__ - contains Cilium run-time dependencies

#. After login, click the "Configure Automated Builds" button.

#. Add a new build rule, taking care to point to the correct Dockerfile and
   Build context, and tagging with the date and suffix ``-v1.9``.

   .. image:: ../../images/cilium-dockerhub-tag-0.png
       :align: center

#. Delete all of the old build rules.

#. Click "Save and Build".

#. Wait for DockerHub to build the image.

#. Log into skopeo into both dockerhub and quay.io, and copy the image across:

   .. code-block:: shell-session

      $ skopeo login docker.io
      $ skopeo login quay.io
      $ skopeo copy docker://docker.io/cilium/cilium-runtime-dev:YYYY-MM-DD-vX.Y docker://quay.io/cilium/cilium-runtime:YYYY-MM-DD-vX.Y

#. Fetch the digest of this image:

   .. code-block:: shell-session

      $ skopeo inspect docker://quay.io/cilium/cilium-runtime:YYYY-MM-DD-vX.Y | jq -r '.Digest'
      sha256:b3f895d40df862c46f247b2942de0658b9d91f07d0bad11202d22af7c7ce3c60

#. Create a new branch in your local Cilium repo based on the tip of the v1.9 tree

#. Replace all references to the cilium-runtime image to now point to the new
   image, replacing the tag and digest using the information from previous steps:

   .. code-block:: shell-session

      $ export NEW_IMAGE=quay.io/cilium/cilium-runtime:YYYY-MM-DD-vX.Y@sha256:ZZZZ
      $ git grep -l 'quay.io/cilium/cilium-runtime' | \
        xargs sed -i 's;\(quay.io/cilium/cilium-runtime:[-_.:@a-zA-Z0-9]\+\);'$NEW_IMAGE';g'

#. Commit with the message 'Update Cilium base images'.

   .. code-block:: shell-session

      $ git add --patch
      $ git ci -s -m "Update Cilium base images"


#. Submit the PR for review

   .. code-block:: shell-session

      $ gh pr create -B v1.9

#. Update the versions of the images that are pulled into the CI VMs.

   * Open a PR against the :ref:`packer_ci` with an update to said image versions. Once your PR is merged, a new version of the VM will be ready for consumption in the CI.
   * Update the ``SERVER_VERSION``  field in ``test/Vagrantfile`` to contain the new version, which is the build number from the `Jenkins Job for the VMs <https://jenkins.cilium.io/job/Vagrant-Master-Boxes-Packer-Build/>`_. For example, build 119 from the pipeline would be the value to set for ``SERVER_VERSION``.
   * Open a pull request with this version change in the cilium repository.

Nightly Docker image
~~~~~~~~~~~~~~~~~~~~

After each successful Nightly build, a `cilium/nightly`_ image is pushed to dockerhub.

To use latest nightly build, please use ``cilium/nightly:latest`` tag.
Nightly images are stored on dockerhub tagged with following format: ``YYYYMMDD-<job number>``.
Job number is added to tag for the unlikely event of two consecutive nightly builds being built on the same date.

.. _cilium/nightly: https://hub.docker.com/r/cilium/nightly/
