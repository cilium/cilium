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

.. code-block:: shell-session

    ARCH=amd64 DOCKER_DEV_ACCOUNT=quay.io/myaccount DOCKER_IMAGE_TAG=jane-developer-my-fix make dev-docker-image

Run ``make docker-operator-generic-image`` (respectively,
``docker-operator-aws-image`` or ``docker-operator-azure-image``) to build the
cilium-operator Docker image:

.. code-block:: shell-session

    ARCH=amd64 DOCKER_DEV_ACCOUNT=quay.io/myaccount DOCKER_IMAGE_TAG=jane-developer-my-fix make docker-operator-generic-image

The commands above assumes that your username for ``quay.io`` is ``myaccount``.

~~~~~~~~~~~~~~
Race detection
~~~~~~~~~~~~~~

See section on :ref:`compiling Cilium with race detection
<compile-cilium-with-race-detection>`.

Official release images
~~~~~~~~~~~~~~~~~~~~~~~

Anyone can build official release images using the make target below.

.. code-block:: shell-session

    DOCKER_IMAGE_TAG=v1.4.0 make docker-images-all

Experimental Docker BuildKit and Buildx support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Docker BuildKit allows build artifact caching between builds and
generally results in faster builds for the developer. Support can be
enabled by:

.. code-block:: shell-session

    export DOCKER_BUILDKIT=1

Multi-arch image build support for arm64 (aka aarch64) and amd64 (aka
x86-64) can be enabled by defining:

.. code-block:: shell-session

    export DOCKER_BUILDX=1

Multi-arch images are built using a cross-compilation builder by
default, which uses Go cross compilation for Go targets, and QEMU
based emulation for other build steps. You can also define your own
Buildx builder if you have access to both arm64 and amd64 machines.
The "cross" builder will be defined and used if your current builder
is "default".

Buildx targets push images automatically, so you must also have
DOCKER_REGISTRY and DOCKER_DEV_ACCOUNT defined, e.g.:

.. code-block:: shell-session

    export DOCKER_REGISTRY=docker.io
    export DOCKER_DEV_ACCOUNT=your-account

Currently the cilium-runtime and cilium-builder images are released
for amd64 only (see the table below). This means that you have to
build your own cilium-runtime and cilium-builder images:

.. code-block:: shell-session

    make docker-image-runtime

After the build finishes update the runtime image references in other
Dockerfiles (``docker buildx imagetools inspect`` is useful for finding
image information). Then proceed to build the cilium-builder:

.. code-block:: shell-session

    make docker-image-builder

After the build finishes update the main Cilium Dockerfile with the
new builder reference, then proceed to build Hubble from
github.com/cilium/hubble. Hubble builds via buildx QEMU based
emulation, unless you have an ARM machine added to your buildx
builder:

.. code-block:: shell-session

    export IMAGE_REPOSITORY=${DOCKER_REGISTRY}/${DOCKER_DEV_ACCOUNT}/hubble
    CONTAINER_ENGINE="docker buildx" DOCKER_FLAGS="--push --platform=linux/arm64,linux/amd64" make image

Update the main Cilium Dockerfile with the new Hubble reference and
build the multi-arch versions of the Cilium images:

.. code-block:: shell-session

    make docker-images-all

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
| github.com/cilium/cilium      | images/runtime/Dockerfile                   | quay.io/cilium/cilium-runtime                 |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/builder/Dockerfile                   | quay.io/cilium/cilium-builder                 |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/cilium/Dockerfile                    | [docker|quay].io/cilium/cilium                |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/cilium-docker-plugin/Dockerfile      | [docker|quay].io/cilium/docker-plugin         |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/hubble-relay/Dockerfile              | [docker|quay].io/cilium/hubble-relay          |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/operator/Dockerfile                  | [docker|quay].io/cilium/operator              |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/operator-aws/Dockerfile              | [docker|quay].io/cilium/operator-aws          |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/operator-azure/Dockerfile            | [docker|quay].io/cilium/operator-azure        |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/operator-generic/Dockerfile          | [docker|quay].io/cilium/operator-generic      |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | images/clustermesh-apiserver/Dockerfile     | [docker|quay].io/cilium/clustermesh-apiserver |     Y     |      Y      |     GH Action     |
+-------------------------------+---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
| github.com/cilium/proxy       | Dockerfile.builder                          | quay.io/cilium/cilium-envoy-builder           |     Y     |      Y      |     GH Action     |
|                               +---------------------------------------------+-----------------------------------------------+-----------+-------------+-------------------+
|                               | Dockerfile                                  | quay.io/cilium/cilium-envoy                   |     Y     |      Y      |     GH Action     |
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

#. cilium-builder depends on cilium-runtime so one needs to update
   cilium-runtime first. Steps 4 and 7 will fetch the digest of the image built
   by GitHub actions.

   .. code-block:: shell-session

       $ make -C images/ update-runtime-image

#. Commit your changes and create a PR in cilium/cilium.

   .. code-block:: shell-session

       $ git commit -s -a -m "update cilium-{runtime,builder}"

#. Ping one of the members of `team/build <https://github.com/orgs/cilium/teams/build/members>`__
   to approve the build that was created by GitHub Actions `here <https://github.com/cilium/cilium/actions?query=workflow:%22Base+Image+Release+Build%22>`__.
   Note that at this step cilium-builder build failure is expected since we have yet to update the runtime digest.

#. Wait for cilium-runtime build to complete. Only after the image is available run:

   .. code-block:: shell-session

       $ make -C images/ update-runtime-image update-builder-image

#. Commit your changes and re-push to the PR in cilium/cilium.

   .. code-block:: shell-session

       $ git commit --amend -s -a

#. Ping one of the members of `team/build <https://github.com/orgs/cilium/teams/build/members>`__
   to approve the build that was created by GitHub Actions `here <https://github.com/cilium/cilium/actions?query=workflow:%22Base+Image+Release+Build%22>`__.

#. Wait for the build to complete. Only after the image is available run:

   .. code-block:: shell-session

       $ make -C images/ update-runtime-image update-builder-image

#. Commit your changes and re-push to the PR in cilium/cilium.

   .. code-block:: shell-session

       $ git commit --amend -s -a

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
