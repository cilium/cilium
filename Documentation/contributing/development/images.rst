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

    make -C images runtime-image

After the build finishes update the runtime image references in other
Dockerfiles (``docker buildx imagetools inspect`` is useful for finding
image information). Then proceed to build the cilium-builder:

.. code-block:: shell-session

    make -C images builder-image

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



.. _update_cilim_builder_runtime_images:

Update cilium-builder and cilium-runtime images
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The steps described here, starting with a commit that updates the image
versions, build the necessary images and update all the appropriate
locations in the Cilium codebase. Hence, before executing the following steps,
the user should have such a commit (e.g., see
`this commit
<https://github.com/cilium/cilium/pull/17713/commits/b7a37ff80df8681d25a24fd5b464082d360fc6e2>`__)
in their local tree. After following the steps below, the result would be another
commit with the image updates (e.g,. see `this commit
<https://github.com/cilium/cilium/pull/17713/commits/bd3357704647117fa9ef4839b9f603cd0435b7cc>`__).
Please keep the two commits separate to ease backporting.

If you only wish to update the packages in these images, then you can manually
update the ``FORCE_BUILD`` variable in ``images/runtime/Dockerfile`` to have a
different value and then proceed with the steps below.

#. Commit your changes and create a PR in cilium/cilium.

   .. code-block:: shell-session

       $ git commit -sam "images: update cilium-{runtime,builder}"

#. Ping one of the members of `team/build <https://github.com/orgs/cilium/teams/build/members>`__
   to approve the build that was created by GitHub Actions `here <https://github.com/cilium/cilium/actions?query=workflow:%22Base+Image+Release+Build%22>`__.
   Note that at this step cilium-builder build failure is expected since we have yet to update the runtime digest.

#. Wait for build to complete. If the PR was opened from an external fork the
   build will fail while trying to push the changes, this is expected.

#. If the PR was opened from an external fork, run the following commands and
   re-push the changes to your branch. Once this is done the CI can be executed.

   .. code-block:: shell-session

       $ make -C images/ update-runtime-image
       $ git commit -sam "images: update cilium-{runtime,builder}" --amend
       $ make -C images/ update-builder-image
       $ git commit -sam "images: update cilium-{runtime,builder}" --amend

#. If the PR was opened from the main repository, the build will automatically
   generate one commit and push it to your branch with all the necessary changes
   across files in the repository. Once this is done the CI can be executed.

#. After merging the PR, do the following steps to update the versions of the
   images that are pulled into the CI VMs.

* Open a PR against the :ref:`packer_ci` with an update to said image versions.
  Once your PR is merged and the new boxes are built, a new version of the VM
  will be ready for consumption in the CI.
* Update all ``*SERVER_VERSION`` fields in ``vagrant_box_defaults.rb`` to
  contain the new versions, which is the build number from the `Jenkins Jobs for
  the VMs <https://jenkins.cilium.io/view/Packer%20builds/>`_. For example,
  build 72 from the pipeline would be the value to set for ``SERVER_VERSION``.
* After merging the `packer-ci-build`_ PR, open a pull request with this version
  change in the cilium repository.

.. _packer-ci-build: https://github.com/cilium/packer-ci-build/

Nightly Docker image
~~~~~~~~~~~~~~~~~~~~

After each successful Nightly build, a `cilium/nightly`_ image is pushed to dockerhub.

To use latest nightly build, please use ``cilium/nightly:latest`` tag.
Nightly images are stored on dockerhub tagged with following format: ``YYYYMMDD-<job number>``.
Job number is added to tag for the unlikely event of two consecutive nightly builds being built on the same date.

.. _cilium/nightly: https://hub.docker.com/r/cilium/nightly/

Image Building Process
~~~~~~~~~~~~~~~~~~~~~~

Images are automatically created by a GitHub action: ``build-images``. This
action will automatically run for any Pull Request, including Pull Requests
submitted from forked repositories, and push the images into
``quay.io/cilium/*-ci``. They will be available there for 1 week before they are
removed by the ``ci-images-garbage-collect`` workflow. Once they are removed, the
developer must re-push the Pull Request into GitHub so that new images are
created.
