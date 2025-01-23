.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _IdentityManagementMode:

***************************
Identity Management Mode
***************************

Cilium supports Cilium Identity (CID) management by either the Cilium Agents (default) or the
Cilium Operator.

When the Operator manages identities, identity creation is centralized. This provides benefits
such as reduced CID duplication, which can occur when multiple Agents simultaneously create identities for
the same set of labels. Given that there is a limitation on the maximum number of identities in a cluster
and eBPF Policy Map size (see :ref:`bpf_map_limitations`), when the operator manages identities, we can improve the
reliability of network policies and cluster scalability.

.. note::

    Labels relevant to identity management may be configured in the Cilium ConfigMap (see: :ref:`identity-relevant-labels`).
    If the Cilium Operator is managing identities, both the Operator and Agents must be restarted to pick up the new label
    pattern setting.

Enable Identity Management by the Cilium Operator (Beta)
=========================================================

.. include:: ../../beta.rst

The Cilium Agents manage CIDs by default. This section describes the steps necessary for enabling CID management by the Cilium Operator.

Enable Operator Managing Identities on a New Cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To enable the Cilium Operator to manage identities on a new cluster, set the ``identityManagementMode`` value to ``operator`` in your Helm chart
or set the ``identity-management-mode`` flag to ``operator`` in the ``cilium-config`` configmap.

How to Migrate from Cilium Agent to Cilium Operator Managing Identities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In order to minimize disruptions to connections or workload management, the following procedure should be followed. Note that in order
to prevent disruptions to the cluster, there is an intermediate state where both the Cilium Agents and the Operator manage identities.
As long as the Cilium Agents are creating identities, the CID duplication issue may occur. The transitional state is intended to
only be used temporarily for the purpose of migrating identity management modes.

#. Allow the Operator to also manage identities by setting the ``identityManagementMode`` value to ``both`` in your Helm chart or
   by setting the ``identity-management-mode`` flag to ``both`` in the ``cilium-config`` configmap. Restart the Operator.

#. Once the operator is running, upgrade the Cilium Agents by setting the ``identityManagementMode`` value to ``operator``
   or by setting the ``identity-management-mode`` flag to ``operator`` and restarting the Cilium Agent DaemonSet.

How to Downgrade from Cilium Operator to Cilium Agent Managing Identities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a safe downgrade, the following procedure should be followed.

#. First, downgrade the Cilium Agents by setting the ``identityManagementMode`` value to ``both`` in your Helm chart or
   by setting the ``identity-management-mode`` flag to ``both`` in the ``cilium-config`` configmap. Restart the Cilium Agent DaemonSet.

#. Once the Cilium Agents are running, downgrade the Operator by setting the ``identityManagementMode`` value to ``agent`` and restarting
   the Operator.

Metrics
========
Metrics for identity management by the operator are documented in the :ref:`identity_management_metrics` section of the metric documentation.
