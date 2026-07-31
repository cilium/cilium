.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Setup Helm repository:

.. tabs::

   .. group-tab:: Helm Repository

      .. code-block:: shell-session

         helm repo add cilium https://helm.cilium.io/

   .. group-tab:: OCI Registry

      Cilium charts are also available via OCI registries (Quay.io and Docker Hub).
      No setup required - you can install directly using ``oci://`` URLs.

      See the :ref:`OCI Registry section <k8s_install_helm>` for more information,
      including chart signing verification and digest-based installations.
