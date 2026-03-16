.. _k8s_install_helm:

Helm Installation
=================

This guide walks through installing Cilium using Helm.

.. contents:: Table of Contents
   :local:
   :depth: 2

Prerequisites
-------------

Before proceeding, ensure you have reviewed :ref:`system_requirements`.

.. warning::
   :class: important

   **IP Address Ranges Must Not Overlap**

   A very common installation mistake is configuring overlapping IP address
   ranges for Pods, Nodes, and Services. This causes connectivity failures
   that are difficult to diagnose.

   Ensure the following ranges are **non-overlapping** before you install:

   +-------------------+------------------------------------+------------------------+
   | Range             | Where Configured                   | Example                |
   +===================+====================================+========================+
   | **Pod CIDR**      | Cilium Helm value                  | ``10.244.0.0/16``      |
   |                   | ``ipam.operator.                   |                        |
   |                   | clusterPoolIPv4PodCIDRList``       |                        |
   +-------------------+------------------------------------+------------------------+
   | **Node IPs**      | Your infrastructure/cloud provider | ``192.168.0.0/24``     |
   +-------------------+------------------------------------+------------------------+
   | **Service CIDR**  | ``kube-apiserver``                 | ``10.96.0.0/12``       |
   |                   | ``--service-cluster-ip-range``     |                        |
   +-------------------+------------------------------------+------------------------+

   See :ref:`ip_address_planning` for a complete guide.

Step 1 — Add the Cilium Helm Repository
----------------------------------------

.. code-block:: shell-session

   $ helm repo add cilium https://helm.cilium.io/
   $ helm repo update

Step 2 — Plan Your IP Ranges
------------------------------

Before running ``helm install``, confirm your IP ranges are non-overlapping:

.. code-block:: shell-session

   # Check your node IPs
   $ kubectl get nodes -o wide

   # Check Service CIDR in kube-apiserver (example for kubeadm clusters)
   $ cat /etc/kubernetes/manifests/kube-apiserver.yaml \
       | grep service-cluster-ip-range

   # Ensure your planned Pod CIDR does not overlap with either of the above.
   # See https://docs.cilium.io/en/stable/installation/ip-address-planning/

Step 3 — Install Cilium
------------------------

.. code-block:: shell-session

   $ helm install cilium cilium/cilium --version |CHART-VERSION| \
       --namespace kube-system \
       --set ipam.operator.clusterPoolIPv4PodCIDRList="{10.244.0.0/16}"

.. note::

   Replace ``10.244.0.0/16`` with your chosen Pod CIDR. Verify it does not
   overlap with your Node IPs (``192.168.x.x`` in the example) or your
   Service CIDR (``10.96.0.0/12`` by default).

Step 4 — Verify Installation
------------------------------

.. code-block:: shell-session

   $ cilium status --wait

Troubleshooting
---------------

If you experience connectivity issues after installation, one of the first
things to check is whether your IP ranges are overlapping. See
:ref:`ip_address_planning` for a diagnostic checklist.

For general troubleshooting, see :ref:`troubleshooting_k8s`.
