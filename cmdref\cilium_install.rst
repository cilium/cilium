.. _cmdref_cilium_install:

cilium install
==============

Install Cilium into a Kubernetes cluster.

.. warning::

   **Check IP address ranges before installing.**

   Ensure that your Pod CIDR, Node IP range, and Service CIDR are
   **non-overlapping** before running this command. Overlapping ranges cause
   connectivity failures that require cluster recreation to fix.

   Quick check:

   .. code-block:: shell-session

      # Node IPs
      $ kubectl get nodes -o wide

      # Service CIDR
      $ cat /etc/kubernetes/manifests/kube-apiserver.yaml \
          | grep service-cluster-ip-range

   See :ref:`ip_address_planning` for the full guide.

Usage
-----

.. code-block:: shell-session

   $ cilium install [flags]

Common Flags
------------

.. list-table::
   :widths: 30 70
   :header-rows: 1

   * - Flag
     - Description
   * - ``--version``
     - Cilium version to install
   * - ``--set``
     - Helm values (e.g., ``--set ipam.operator.clusterPoolIPv4PodCIDRList={10.244.0.0/16}``)
   * - ``--namespace``
     - Namespace to install Cilium into (default: ``kube-system``)
   * - ``--helm-values``
     - Path to a Helm values file

Examples
--------

Install with a custom Pod CIDR (ensure it does not overlap with Node IPs
or Service CIDR):

.. code-block:: shell-session

   $ cilium install \
       --set ipam.operator.clusterPoolIPv4PodCIDRList="{10.244.0.0/16}"

See Also
--------

- :ref:`ip_address_planning` — IP address planning guide
- :ref:`k8s_install_helm` — Helm installation guide
