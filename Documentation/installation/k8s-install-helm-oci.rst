.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_helm_oci:

***************************************
Installation using Helm OCI Registries
***************************************

Cilium Helm charts are available directly from OCI container registries,
eliminating the need for a separate Helm repository. This is the recommended
approach for new installations.

.. tip::

   No ``helm repo add`` required! Just reference the chart directly with
   ``oci://quay.io/cilium/charts/cilium``.

Quick Start
===========

.. only:: stable

   .. parsed-literal::

      helm install cilium oci://quay.io/cilium/charts/cilium \\
        --version |CHART_VERSION| \\
        --namespace kube-system

.. only:: not stable

   .. code-block:: shell-session

      helm install cilium oci://quay.io/cilium/charts/cilium \\
        --version <VERSION> \\
        --namespace kube-system

   Replace ``<VERSION>`` with the desired version (e.g., ``1.15.0``).

That's it. The chart is pulled directly from the registry and installed.

Why OCI Registries?
===================

Storing Helm charts in OCI registries alongside container images offers
several advantages:

* **Signed charts** — All charts are signed with cosign for verification
* **Simpler setup** — No repository configuration needed
* **Digest pinning** — Reference exact chart versions by SHA for reproducibility
* **Unified tooling** — Use the same registry infrastructure for images and charts

Available Registries
--------------------

Both registries contain identical, signed charts:

* ``oci://quay.io/cilium/charts/cilium``

Finding Available Versions
==========================

OCI registries don't support ``helm search``. Here's how to find available
versions:

.. important::

   **Version format matters**: Helm chart versions follow SemVer 2.0 *without*
   the "v" prefix (e.g., ``1.15.0``). Container image tags *include* the "v"
   (e.g., ``v1.15.0``). Use versions without the "v" for Helm commands.

**Browse the registry:**

* `Quay.io tags <https://quay.io/repository/cilium/cilium?tab=tags>`_

**Query via CLI:**

.. code-block:: shell-session

   # Using crane
   crane ls quay.io/cilium/cilium

**Check releases:** https://github.com/cilium/cilium/releases

Upgrading
=========

.. only:: stable

   .. parsed-literal::

      helm upgrade cilium oci://quay.io/cilium/charts/cilium \
        --version |CHART_VERSION| \
        --namespace kube-system

.. only:: not stable

   .. code-block:: shell-session

      helm upgrade cilium oci://quay.io/cilium/charts/cilium \
        --version <NEW_VERSION> \
        --namespace kube-system

Migrating from helm.cilium.io
-----------------------------

If you're using the traditional repository (``https://helm.cilium.io/``),
switching is straightforward as the charts are identical:

.. only:: stable

   .. parsed-literal::

      helm upgrade cilium oci://quay.io/cilium/charts/cilium \
        --version |CHART_VERSION| \
        --namespace kube-system \
        --reuse-values

.. only:: not stable

   .. code-block:: shell-session

      helm upgrade cilium oci://quay.io/cilium/charts/cilium \
        --version <VERSION> \
        --namespace kube-system \
        --reuse-values

The ``--reuse-values`` flag preserves your existing configuration.

Security
========

Verifying Signatures
--------------------

All charts are signed with cosign. Verify before installing:

.. code-block:: shell-session

   cosign verify \
     --certificate-identity-regexp='https://github.com/cilium/cilium/.*' \
     --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
     quay.io/cilium/cilium:<VERSION>

See https://docs.sigstore.dev/cosign/installation/ for cosign installation.

Pinning by Digest
-----------------

For reproducible deployments, pin charts by digest instead of tag:

.. code-block:: shell-session

   # Get the digest
   helm pull oci://quay.io/cilium/charts/cilium --version <VERSION>

   # Install with digest
   helm install cilium oci://quay.io/cilium/charts/cilium@sha256:<DIGEST> \
     --namespace kube-system

This guarantees the exact same chart every time.

OCI vs Traditional Repository
=============================

+---------------------+---------------------------+---------------------------+
| Feature             | OCI Registry              | Traditional Repository    |
+=====================+===========================+===========================+
| Setup               | None                      | ``helm repo add``         |
+---------------------+---------------------------+---------------------------+
| Chart signing       | Yes (cosign)              | No                        |
+---------------------+---------------------------+---------------------------+
| Digest pinning      | Yes                       | Limited                   |
+---------------------+---------------------------+---------------------------+
| Air-gapped install  | Standard OCI mirror tools | Separate chart mirror     |
+---------------------+---------------------------+---------------------------+

Both methods remain fully supported.

Troubleshooting
===============

"failed to authorize: failed to fetch anonymous token"
------------------------------------------------------

This usually means network or registry connectivity issues. Test access:

.. code-block:: shell-session

   curl https://quay.io/v2/

"chart not found"
-----------------

Double-check your version number. Remember: no "v" prefix for Helm versions.
See `Finding Available Versions`_ for how to list what's available.
