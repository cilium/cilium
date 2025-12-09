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

Set ``BASE_IMAGE_REGISTRY`` to redirect pull of base images (``cilium-builder``, ``cilium-runtime``, ``cilium-envoy``).
This allows to keeps tags/digests pinned in the Dockerfile, but use custom registry for builds.

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

Official Cilium repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following table contains the main container image repositories managed by the Cilium team. All images are built via Github
Actions from their corresponding Github repositories. All images are `multi-platform <https://docs.docker.com/build/building/multi-platform/>`_
with support for both ``linux/amd64`` and ``linux/arm64`` platforms.

+-------------------------------+---------------------------------------------+-----------------------------------------------+
|     **Github Repository**     |                **Dockerfile**               |      **Container image repository**           |
|                               |                                             |                                               +
|                               |                                             |                                               |
+-------------------------------+---------------------------------------------+-----------------------------------------------+
| github.com/cilium/cilium      | images/builder/Dockerfile                   | quay.io/cilium/cilium-builder                 |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/cilium-docker-plugin/Dockerfile      | [quay|docker].io/cilium/docker-plugin         |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/cilium/Dockerfile                    | [quay|docker].io/cilium/cilium                |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/clustermesh-apiserver/Dockerfile     | [quay|docker].io/cilium/clustermesh-apiserver |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/hubble-relay/Dockerfile              | [quay|docker].io/cilium/hubble-relay          |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/operator/Dockerfile                  | [quay|docker].io/cilium/operator              |
|                               +                                             +-----------------------------------------------+
|                               |                                             | [quay|docker].io/cilium/operator-alibabacloud |
|                               +                                             +-----------------------------------------------+
|                               |                                             | [quay|docker].io/cilium/operator-aws          |
|                               +                                             +-----------------------------------------------+
|                               |                                             | [quay|docker].io/cilium/operator-azure        |
|                               +                                             +-----------------------------------------------+
|                               |                                             | [quay|docker].io/cilium/operator-generic      |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/runtime/Dockerfile                   | quay.io/cilium/cilium-runtime                 |
+-------------------------------+---------------------------------------------+-----------------------------------------------+
| github.com/cilium/cilium-cli  | Dockerfile                                  | quay.io/cilium/cilium-cli                     |
+-------------------------------+---------------------------------------------+-----------------------------------------------+
| github.com/cilium/image-tools | images/bpftool/Dockerfile                   | quay.io/cilium/cilium-bpftool                 |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/compilers/Dockerfile                 | quay.io/cilium/image-compilers                |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/llvm/Dockerfile                      | quay.io/cilium/cilium-llvm                    |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/maker/Dockerfile                     | quay.io/cilium/image-maker                    |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | images/startup-script/Dockerfile            | quay.io/cilium/startup-script                 |
+-------------------------------+---------------------------------------------+-----------------------------------------------+
| github.com/cilium/proxy       | Dockerfile.builder                          | quay.io/cilium/cilium-envoy-builder           |
|                               +---------------------------------------------+-----------------------------------------------+
|                               | Dockerfile                                  | quay.io/cilium/cilium-envoy                   |
+-------------------------------+---------------------------------------------+-----------------------------------------------+

Images dependency:

::

    cilium/cilium
    └── cilium/cilium-builder
        └── cilium/cilium-runtime
            ├── cilium/cilium-bpftool
            └── cilium/cilium-llvm

    cilium/cilium-envoy
    └── cilium/cilium-envoy-builder
        └── cilium/cilium-builder
            └── cilium/cilium-runtime
                ├── cilium/cilium-bpftool
                └── cilium/cilium-llvm

    cilium/operator
    └── cilium/cilium-builder
        └── cilium/cilium-runtime
            ├── cilium/cilium-bpftool
            └── cilium/cilium-llvm



.. _update_cilium_builder_runtime_images:

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
   across files in the repository.

#. Run the full CI and ensure that it passes.

#. Merge the PR.

Image Building Process
~~~~~~~~~~~~~~~~~~~~~~

Images are automatically created by a GitHub action: ``build-images``. This
action will automatically run for any Pull Request, including Pull Requests
submitted from forked repositories, and push the images into
``quay.io/cilium/*-ci``. They will be available there for 1 week before they are
removed by the ``ci-images-garbage-collect`` workflow. Once they are removed, the
developer must re-push the Pull Request into GitHub so that new images are
created.
