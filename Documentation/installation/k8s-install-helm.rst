.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_helm:

***********************
Installation using Helm
***********************

This guide will show you how to install Cilium using `Helm
<https://helm.sh/>`_. This involves a couple of additional steps compared to
the :ref:`k8s_quick_install` and requires you to manually select the best
datapath and IPAM mode for your particular environment.

Helm Installation Methods
==========================

Cilium can be installed using Helm in two ways:

1. **OCI Registry (Recommended)** — Install directly from OCI registries without adding a Helm repository
2. **Traditional Repository** — Use the classic ``https://helm.cilium.io/`` repository

Using OCI Registries (Recommended)
-----------------------------------

Cilium Helm charts are available directly from OCI container registries,
eliminating the need for a separate Helm repository.

.. tip::

   No ``helm repo add`` required! Just reference the chart directly with
   ``oci://quay.io/cilium/charts/cilium``.

**Why OCI Registries?**

Storing Helm charts in OCI registries alongside container images offers
several advantages:

* **Signed charts** — All charts are signed with cosign for verification
* **Simpler setup** — No repository configuration needed
* **Digest pinning** — Reference exact chart versions by SHA for reproducibility
* **Unified tooling** — Use the same registry infrastructure for images and charts

**Quick Start with OCI:**

.. only:: stable

   .. parsed-literal::

      helm install cilium oci://quay.io/cilium/charts/cilium \
        --version |CHART_VERSION| \
        --namespace kube-system

.. only:: not stable

   .. code-block:: shell-session

      helm install cilium oci://quay.io/cilium/charts/cilium \
        --version <VERSION> \
        --namespace kube-system

   Replace ``<VERSION>`` with the desired version (e.g., ``1.15.0``).

**Finding Available Versions:**

OCI registries don't support ``helm search``. Here's how to find available
versions:

.. important::

   **Version format matters**: Helm chart versions follow SemVer 2.0 *without*
   the "v" prefix (e.g., ``1.15.0``). Container image tags *include* the "v"
   (e.g., ``v1.15.0``). Use versions without the "v" for Helm commands.

* **Browse the registry:** `Quay.io tags <https://quay.io/repository/cilium/cilium?tab=tags>`_
* **Query via CLI:**

  .. code-block:: shell-session

     # Using crane
     crane ls quay.io/cilium/charts/cilium

* **Check releases:** https://github.com/cilium/cilium/releases

**Verifying Chart Signatures:**

All charts are signed with cosign. Verify before installing:

.. code-block:: shell-session

   cosign verify \
     --certificate-identity-regexp='https://github.com/cilium/cilium/.*' \
     --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
     quay.io/cilium/charts/cilium:<VERSION>

See https://docs.sigstore.dev/cosign/installation/ for cosign installation.

**Pinning by Digest:**

For reproducible deployments, pin charts by digest instead of tag:

.. code-block:: shell-session

   # Get the digest
   helm pull oci://quay.io/cilium/charts/cilium --version <VERSION>

   # Install with digest
   helm install cilium oci://quay.io/cilium/charts/cilium@sha256:<DIGEST> \
     --namespace kube-system

This guarantees the exact same chart every time.

Using Traditional Helm Repository
----------------------------------

You can also install Cilium using the traditional Helm repository method.
Both installation methods are fully supported.

Install Cilium
==============

.. include:: k8s-install-download-release.rst

.. tabs::

    .. group-tab:: Generic

       These are the generic instructions on how to install Cilium into any
       Kubernetes cluster using the default configuration options below. Please
       see the other tabs for distribution/platform specific instructions which
       also list the ideal default configuration for particular platforms.

       **Default Configuration:**

       =============== =============== ==============
       Datapath        IPAM            Datastore
       =============== =============== ==============
       Encapsulation   Cluster Pool    Kubernetes CRD
       =============== =============== ==============

       .. include:: requirements-generic.rst

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. cilium-helm-install::
          :namespace: kube-system

    .. group-tab:: GKE

       .. include:: requirements-gke.rst

       **Install Cilium:**

       Extract the Cluster CIDR to enable native-routing:

       .. code-block:: shell-session

          NATIVE_CIDR="$(gcloud container clusters describe "${NAME}" --zone "${ZONE}" --format 'value(clusterIpv4Cidr)')"
          echo $NATIVE_CIDR

       Deploy Cilium release via Helm:

       .. cilium-helm-install::
          :namespace: kube-system
          :set: nodeinit.enabled=true
                nodeinit.reconfigureKubelet=true
                nodeinit.removeCbrBridge=true
                cni.binPath=/home/kubernetes/bin
                gke.enabled=true
                ipam.mode=kubernetes
                ipv4NativeRoutingCIDR=$NATIVE_CIDR

       The NodeInit DaemonSet is required to prepare the GKE nodes as nodes are added
       to the cluster. The NodeInit DaemonSet will perform the following actions:

       * Reconfigure kubelet to run in CNI mode
       * Mount the eBPF filesystem

    .. group-tab:: AKS

       .. include:: ../installation/requirements-aks.rst

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. cilium-helm-install::
          :namespace: kube-system
          :set: aksbyocni.enabled=true

       .. note::

          Installing Cilium via helm is supported only for AKS BYOCNI cluster and
          not for Azure CNI Powered by Cilium clusters.

    .. group-tab:: EKS

       .. include:: requirements-eks.rst

       **Patch VPC CNI (aws-node DaemonSet)**

       Cilium will manage ENIs instead of VPC CNI, so the ``aws-node``
       DaemonSet has to be patched to prevent conflict behavior.

       .. code-block:: shell-session

          kubectl -n kube-system patch daemonset aws-node --type='strategic' -p='{"spec":{"template":{"spec":{"nodeSelector":{"io.cilium/aws-node-enabled":"true"}}}}}'

       **Install Cilium:**

       Deploy Cilium release via Helm:

       .. cilium-helm-install::
          :namespace: kube-system
          :set: eni.enabled=true

       .. note::

          This helm command sets ``eni.enabled=true``,
          meaning that Cilium will allocate a fully-routable AWS ENI IP address
          for each pod, similar to the behavior of the `Amazon VPC CNI plugin
          <https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html>`_.

          This mode depends on a set of :ref:`ec2privileges` from the EC2 API.

          Cilium can alternatively run in EKS using an overlay mode that gives
          pods non-VPC-routable IPs.  This allows running more pods per
          Kubernetes worker node than the ENI limit but includes the following caveats:

            1. Pod connectivity to resources outside the cluster (e.g., VMs in the VPC
               or AWS managed services) is masqueraded (i.e., SNAT) by Cilium to use the
               VPC IP address of the Kubernetes worker node.
            2. The EKS API Server is unable to route packets to the overlay network. This
               implies that any `webhook <https://kubernetes.io/docs/reference/access-authn-authz/webhook/>`_
               which needs to be accessed must be host networked or exposed through a service
               or ingress.

          To set up Cilium overlay mode, follow the steps below:

            1. Excluding the line ``eni.enabled=true`` from the helm command will configure Cilium to use
               overlay routing mode (which is the helm default).
            2. Flush iptables rules added by VPC CNI

               .. code-block:: shell-session

                  iptables -t nat -F AWS-SNAT-CHAIN-0 \
                     && iptables -t nat -F AWS-SNAT-CHAIN-1 \
                     && iptables -t nat -F AWS-CONNMARK-CHAIN-0 \
                     && iptables -t nat -F AWS-CONNMARK-CHAIN-1

    .. group-tab:: OpenShift

       .. include:: requirements-openshift.rst

       **Install Cilium:**

       Cilium is a `Certified OpenShift CNI Plugin <https://access.redhat.com/articles/5436171>`_
       and is best installed when an OpenShift cluster is created using the OpenShift
       installer. Please refer to :ref:`k8s_install_openshift_okd` for more information.

    .. group-tab:: RKE

       .. include:: requirements-rke.rst

    .. group-tab:: k3s

       .. include:: requirements-k3s.rst

       **Install Cilium:**

       .. cilium-helm-install::
          :namespace: $CILIUM_NAMESPACE
          :set: operator.replicas=1

    .. group-tab:: Rancher Desktop

       **Configure Rancher Desktop:**

       To install Cilium on `Rancher Desktop <https://rancherdesktop.io>`_,
       perform the following steps:

       .. include:: rancher-desktop-configure.rst

       **Install Cilium:**

       .. cilium-helm-install::
          :namespace: $CILIUM_NAMESPACE
          :set: operator.replicas=1
                cni.binPath=/usr/libexec/cni

    .. group-tab:: Talos Linux

       To install Cilium on `Talos Linux <https://www.talos.dev/>`_,
       perform the following steps.

       .. include:: k8s-install-talos-linux.rst

    .. group-tab:: Alibaba ACK

        .. include:: ../installation/alibabacloud-eni.rst

.. admonition:: Video
  :class: attention

  If you'd like to learn more about Cilium Helm values, check out `eCHO episode 117: A Tour of the Cilium Helm Values <https://www.youtube.com/watch?v=ni0Uw4WLHYo>`__.

Upgrading
=========

Using OCI Registry
------------------

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

Migrating from Traditional Repository to OCI
---------------------------------------------

If you're using the traditional repository (``https://helm.cilium.io/``),
switching to OCI is straightforward as the charts are identical:

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

OCI vs Traditional Repository
==============================

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

.. include:: k8s-install-restart-pods.rst

.. include:: k8s-install-validate.rst

.. include:: next-steps.rst
