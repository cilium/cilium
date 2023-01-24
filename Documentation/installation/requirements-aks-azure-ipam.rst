**Requirements:**

* The AKS cluster must be created with ``--network-plugin azure``. The
  Azure network plugin will be replaced with Cilium by the installer.

**Limitations:**

* All VMs and VM scale sets used in a cluster must belong to the same
  resource group.

* Adding new nodes to node pools might result in application pods being
  scheduled on the new nodes before Cilium is ready to properly manage
  them. The only way to fix this is either by making sure application pods
  are not scheduled on new nodes before Cilium is ready, or by restarting
  any unmanaged pods on the nodes once Cilium is ready.

  Ideally we would recommend node pools should be tainted with
  ``node.cilium.io/agent-not-ready=true:NoExecute`` to ensure application
  pods will only be scheduled/executed once Cilium is ready to manage them
  (see :ref:`Considerations on node pool taints and unmanaged pods <taint_effects>`
  for more details), however this is not an option on AKS clusters:

  * It is not possible to assign custom node taints such as
    ``node.cilium.io/agent-not-ready=true:NoExecute`` to system node
    pools, cf. `Azure/AKS#2578 <https://github.com/Azure/AKS/issues/2578>`_:
    only ``CriticalAddonsOnly=true:NoSchedule`` is available for our use
    case. To make matters worse, it is not possible to assign taints to
    the initial node pool created for new AKS clusters, cf.
    `Azure/AKS#1402 <https://github.com/Azure/AKS/issues/1402>`_.

  * Custom node taints on user node pools cannot be properly managed at
    will anymore, cf. `Azure/AKS#2934 <https://github.com/Azure/AKS/issues/2934>`_.

  * These issues prevent usage of our previously recommended scenario via
    replacement of initial system node pool with
    ``CriticalAddonsOnly=true:NoSchedule`` and usage of additional user
    node pools with ``node.cilium.io/agent-not-ready=true:NoExecute``.

  We do not have a standard and foolproof alternative to recommend, hence
  the only solution is to craft a custom mechanism that will work in your
  environment to handle this scenario when adding new nodes to AKS
  clusters.
