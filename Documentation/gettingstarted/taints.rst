.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _taint_effects:

#####################################################
Considerations on node pool taints and unmanaged pods
#####################################################

Depending on the environment or cloud provider being used, a CNI plugin and/or
configuration file may be pre-installed in nodes belonging to a given cluster
where Cilium is being installed or already running. Upon starting on a given
node, and if it is intended as the exclusive CNI plugin for the cluster, Cilium
does its best to take ownership of CNI on the node. However, a couple situations
can prevent this from happening:

* Cilium can only take ownership of CNI on a node after starting. Pods starting
  before Cilium runs on a given node may get IPs from the pre-configured CNI.

* Some cloud providers may revert changes made to the CNI configuration by
  Cilium during operations such as node reboots, updates or routine maintenance.

This is notably the case with GKE (non-Dataplane V2), in which node reboots and
upgrades will undo changes made by Cilium and re-instate the default CNI
configuration.

To help overcome this situation to the largest possible extent in environments
and cloud providers where Cilium isn't supported as the single CNI, Cilium can
manipulate Kubernetes's `taints <https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/>`_
on a given node to help preventing pods from starting before Cilium runs on said
node. The mechanism works as follows:

1. The cluster administrator places a specific taint (see below) on a given
   uninitialized node. Depending on the taint's effect (see below), this prevents
   pods that don't have a matching toleration from either being scheduled or
   altogether running on the node until the taint is removed.

2. Cilium runs on the node, initializes it and, once ready, removes the
   aforementioned taint.

3. From this point on, pods will start being scheduled and running on the node,
   having their networking managed by Cilium.

By default, the taint key is ``node.cilium.io/agent-not-ready``, but in some
scenarios (such as when Cluster Autoscaler is being used but its flags cannot be
configured) this key may need to be tweaked. This can be done using the
``agent-not-ready-taint-key`` option. In the aforementioned example, users should
specify a key starting with ``ignore-taint.cluster-autoscaler.kubernetes.io/``.
When such a value is used, the Cluster Autoscaler will ignore it when simulating
scheduling, allowing the cluster to scale up.

The taint's effect should be chosen taking into account the following
considerations:

* If ``NoSchedule`` is used, pods won't be *scheduled* to a node until Cilium
  has the chance to remove the taint. However, one practical effect of this is
  that if some external process (such as a reboot) resets the CNI configuration on
  said node, pods that were already scheduled will be allowed to start
  concurrently with Cilium when the node next reboots, and hence may become
  unmanaged and have their networking being managed by another CNI plugin.

* If ``NoExecute`` is used, pods won't be *executed* (nor *scheduled*) on a node
  until Cilium has had the chance to remove the taint. One practical effect of
  this is that whenever the taint is added back to the node by some external
  process (such as during an upgrade or eventually a routine operation), pods
  will be evicted from the node until Cilium has had the chance to remove the
  taint.

Another important thing to consider is the concept of node itself, and the
different point of views over a node. For example, the instance/VM which backs a
Kubernetes node can be patched or reset filesystem-wise by a cloud provider, or
altogether replaced with an entirely new instance/VM that comes back with the
same name as the already-existing Kubernetes ``Node`` resource. Even though in
said scenarios the node-pool-level taint will be added back to the ``Node``
resource, pods that were already scheduled to the node having this name will run
on the node at the same time as Cilium, potentially becoming unmanaged. This is
why ``NoExecute`` is recommended, as assuming the taint is added back in this
scenario, already-scheduled pods won't run.

However, on some environments or cloud providers, and as mentioned above, it may
happen that a taint established at the node-pool level is added back to a node
after Cilium has removed it and for reasons other than a node upgrade/reset.
The exact circumstances in which this may happen may vary, but this may lead to
unexpected/undesired pod evictions in the particular case when ``NoExecute`` is
being used as the taint effect. It is, thus, recommended that in each deployment
and depending on the environment or cloud provider, a careful decision is made
regarding the taint effect (or even regarding whether to use the taint-based
approach at all) based on the information above, on the environment or cloud
provider's documentation, and on the fact that one is essentially establishing
a trade-off between having unmanaged pods in the cluster (which can lead to
dropped traffic and other issues) and having unexpected/undesired evictions
(which can lead to application downtime).

Taking into account all of the above, throughout the Cilium documentation we
recommend ``NoExecute`` to be used as we believe it to be the least disruptive
mode that users can use to deploy Cilium on cloud providers.
