.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _configuration:

Configuration
=============

Your Cilium installation is configured by one or more Helm values -
see :ref:`helm_reference`. These helm values are converted to arguments
for the individual components of a Cilium installation, such as
:doc:`../cmdref/cilium-agent` and :doc:`../cmdref/cilium-operator`, and
stored in a ConfigMap.

.. _cilium-config-configmap:

``cilium-config`` ConfigMap
-----------------------------

These arguments are stored in a shared ConfigMap called ``cilium-config``
(albeit without the leading ``--``). For example, a typical installation
may look like

.. code-block:: shell-session

   $ kubectl -n kube-system get configmap cilium-config -o yaml
   data:
     agent-not-ready-taint-key: node.cilium.io/agent-not-ready
     arping-refresh-period: 30s
     auto-direct-node-routes: "false"
     (output continues)

.. _making-config-changes:

Making Changes
--------------

You may change the configuration of a running installation in three ways:

#. Via ``helm upgrade``

   Do so by providing new values to Helm and applying them to the existing
   installation. By setting the value ``rollOutCiliumPods=true``, the agent
   pods will be gradually restarted.


#. Via ``cilium config set``

   The `Cilium CLI <https://github.com/cilium/cilium-cli/>`_ has the ability
   to update individual values in the ``cilium-config`` ConfigMap. This will
   not affect running pods; pods must be deleted manually to pick up any changes.

#. Via ``CiliumNodeConfig`` objects

   Cilium also supports configuration on sets of nodes. See the
   :ref:`per-node-configuration` page for more details. Likewise, this also requires
   that pods be manually deleted for changes to take effect.


Core Agent
----------
.. toctree::
   :maxdepth: 1
   :glob:

   api-rate-limiting
   api-restrictions
   per-node-config
   sctp
   vlan-802.1q
   argocd-issues

Security
--------
.. toctree::
   :maxdepth: 1
   :glob:

   verify-image-signatures
   sbom
