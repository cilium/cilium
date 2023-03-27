.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _l2_announcements:

************************************
L2 Announcements / L2 Aware LB
************************************

L2 Announcements is a feature which makes services visible and reachable on 
the local area network. This feature is primarily intended for bare metal 
deployments within networks without BGP based routing such as office or 
campus networks.

When used, this feature will respond to ARP queries for ExternalIPs and/or 
LoadBalancer IPs. These IPs are Virtual IPs (not installed on network 
devices) on multiple nodes, so for each service one node at a time will respond
to the ARP queries and respond with its MAC address. This node will perform 
load balancing with the service load balancing feature, thus acting as a 
north/south load balancer.

The advantage over this feature over NodePort services is that each service can
use a unique IP so multiple service can use the same port numbers. When using 
NodePorts its up to the client to decide to which host to send traffic, if a node
goes down, the IP+Port combo becomes unusable. With L2 announcements the service
VIP simply migrates to another node and will continue to work.

The L2 Announcements feature and all the requirements can be enabled as follow:

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set l2announcements.enabled=true \\
               --set kubeProxyReplacement=strict

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-l2-announcements: true
            kube-proxy-replacement: strict

Prerequisites
#############

* Kube Proxy replacement mode must be enabled, see :ref:`kubeproxy-free` for details.

* All devices on which L2 Aware LB should be enabled should be included in the 
  ``--devices`` flag or ``devices`` Helm option if explicitly set, see :ref:`NodePort Devices`.

* The ``externalIPs.enable=true`` Helm option should be set, if usage of externalIPs
  is desired. Otherwise service load balancing for external IPs is disabled.

Limitations
###########

* The feature currently does not support IPv6/NDP

* Due to the way L3->L2 translation protocols work, one node receives all 
  per IP, no load balancing before traffic hits the cluster.

* The feature currently has no traffic balancing mechanism so nodes within the
  same policy might be asymmetrically loaded. For details see :ref:`l2_announcements_leader_election`.

Policies
########

Policies provide fine-grained control over which services should be announced,
where, and how. This is an example of policy using all optional fields:

.. code-block:: yaml

    apiVersion: "cilium.io/v2alpha1"
    kind: CiliumL2AnnouncementPolicy
    metadata:
      name: policy1
    spec:
      serviceSelector:
        matchLabels:
          color: blue
      nodeSelector:
        matchLabels:
          role: worker
      interfaces:
      - ^eth[0-9]+
      externalIPs: true
      loadBalancerIPs: true  

Service Selector
----------------

The service selector is a `label selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/>`__ 
that determines which services are selected by this policy. If no service 
selector is provided, all services are selected by the policy.

There are a few special purpose selector fields which don't match on labels but
instead on other metadata like ``.meta.name`` or ``.meta.namespace``.

=============================== ===================
Selector                        Field
------------------------------- -------------------
io.kubernetes.service.namespace ``.meta.namespace``
io.kubernetes.service.name      ``.meta.name``
=============================== ===================

Node Selector
-------------

The node selector field is a `label selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/>`__
which determines which nodes are candidates to announce the services from.

It might be desirable to pick a subset of nodes in you cluster, since the chosen
node (see :ref:`l2_announcements_leader_election`) will act as the North/South
load balancer for all of the traffic for a particular service.

Interfaces
----------

The interfaces field is a list of regular expressions (`golang syntax <https://pkg.go.dev/regexp/syntax>`__
that determine over which network interfaces the selected services will be 
announced. This field is optional, if not specified all interfaces will be used.

The expressions are OR-ed together, so any network device matching any of the 
expressions will be matched.

L2 announcements only work if the selected devices are also part of the set of 
devices specified in the ``devices`` Helm option, see :ref:`NodePort Devices`

.. note::
    This selector is NOT a security feature, services will still be available 
    via interfaces when not advertised (for example by hard-coding ARP entries).

IP Types
--------

The ``externalIPs`` and ``loadBalancerIPs`` fields determine what sort of IPs 
are announced. They are ``false`` by default, so a functional policy should always
have one or both set to ``true``.

If ``externalIPs`` is ``true`` all IPs in `.spec.externalIPs <https://kubernetes.io/docs/concepts/services-networking/service/#external-ips>`__
are announced, which are managed by service authors.

If ``loadBalancerIPs` is ``true`` all IPs in ``.status.loadbalacer.ingress``
are announced. These can be assigned by :ref:`lb_ipam` which can be configured
by cluster admins for better control over which IPs can be allocated.

.. note::
    If a user intends to use ``externalIPs``, the ``externalIPs.enable=true`` 
    Helm option should be set to enable service load balancing for external IPs.

Status
------

If a policy is invalid for any number of reasons, the status of the policy will reflect that.
For example if a invalid match expression is provided:

.. code-block:: shell-session

  $ kubectl describe l2announcement 
  Name:         policy1
  Namespace:    
  Labels:       <none>
  Annotations:  <none>
  API Version:  cilium.io/v2alpha1
  Kind:         CiliumL2AnnouncementPolicy
  Metadata:
    #[...]
  Spec:
    #[...]
    Service Selector:
      Match Expressions:
        Key:       something
        Operator:  NotIn
        Values:
  Status:
    Conditions:
      Last Transition Time:  2023-05-12T15:39:01Z
      Message:               values: Invalid value: []string(nil): for 'in', 'notin' operators, values set can't be empty
      Observed Generation:   1
      Reason:                error
      Status:                True
      Type:                  io.cilium/bad-service-selector

The status of these error conditions will go to ``False`` as soon as the user 
updates the policy to resolve the error.

.. _l2_announcements_leader_election:

Leader Election
###############

Due to the way ARP/NDP works, hosts only store one MAC address per IP, that being
the latest reply they see. This means that only one node in the cluster is allowed
to reply to requests for a given IP.

To implement this behavior, every Cilium agent resolves which services are 
selected for its node and will start participating in leader election for every 
service. We use Kubernetes `lease mechanism <https://kubernetes.io/docs/concepts/architecture/leases/>`__
to achieve this. Each service translates to a lease, the lease holder will start
replying to requests on the selected interfaces.

The lease mechanism is a first come, first serve picking order. So the first 
node to claim a lease gets it. This might cause asymmetric traffic distribution.

Leases
------

The leases are created in the same namespace where Cilium is deployed, 
typically ``kube-system``. You can inspect the leases with the following command:

.. code-block:: shell-session

    $ kubectl -n kube-system get lease
    NAME                                  HOLDER                                                    AGE
    cilium-l2announce-default-deathstar   worker-node                                               2d20h
    cilium-operator-resource-lock         worker-node2-tPDVulKoRK                                   2d20h
    kube-controller-manager               control-plane-node_9bd97f6c-cd0c-4565-8486-e718deb310e4   2d21h
    kube-scheduler                        control-plane-node_2c490643-dd95-4f73-8862-139afe771ffd   2d21h

The leases starting with ``cilium-l2announce-`` are leases used by this feature.
The last part of the name is the namespace and service name. The holder indicates
the name of the node that currently holds the lease and thus announced the IPs 
of that given service.

To inspect a lease:

.. code-block:: shell-session

    $ kubectl -n kube-system get lease/cilium-l2announce-default-deathstar -o yaml
    apiVersion: coordination.k8s.io/v1
    kind: Lease
    metadata:
      creationTimestamp: "2023-05-09T15:13:32Z"
      name: cilium-l2announce-default-deathstar
      namespace: kube-system
      resourceVersion: "449966"
      uid: e3c9c020-6e24-4c5c-9df9-d0c50f6c4cec
    spec:
      acquireTime: "2023-05-09T15:14:20.108431Z"
      holderIdentity: worker-node
      leaseDurationSeconds: 3
      leaseTransitions: 1
      renewTime: "2023-05-12T12:15:26.773020Z"

The ``acquireTime`` is the time at which the current leader acquired the lease.
The ``holderIdentity`` is the name of the current holder/leader node. 
If the leader does not renew the lease for ``leaseDurationSeconds`` seconds a
new leader is chosen. ``leaseTransitions`` indicates how often the lease changed
hands and ``renewTime`` the last time the leader renewed the lease.

There are three Helm options that can be tuned with regards to leases:

* ``l2announcements.leaseDuration`` determines the ``leaseDurationSeconds`` value
  of created leases and by extent how long a leader must be "down" before 
  failover occurs. (default is 15s)

* ``l2announcements.leaseRenewDeadline`` is the interval at which the leader 
  should renew the lease. (default is 5s)

* ``l2announcements.leaseRetryPeriod`` if renewing the lease fails, how long 
  should the agent wait before it tries again. (default is 2s)

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set l2announcements.enabled=true \\
               --set kubeProxyReplacement=strict \\
               --set l2announcements.leaseDuration=3s \\
               --set l2announcements.leaseRenewDeadline=1s \\
               --set l2announcements.leaseRetryPeriod=200ms

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-l2-announcements: true
            kube-proxy-replacement: strict
            l2-announcements-lease-duration: 3s
            l2-announcements-renew-deadline: 1s
            l2-announcements-retry-period: 200ms

There is a trade-off between fast failure detection and CPU + network usage. 
Each service incurs a CPU and network overhead, so clusters with smaller amounts
of services can more easily afford faster failover times. Larger clusters might
need to increase parameters if the overhead is to much.

Failover
--------

When nodes participating in leader election detect that the lease holder did not
renew the lease for ``leaseDurationSeconds`` amount of seconds, they will ask
the API server to make them the new holder. The first request to be processed 
gets through and the rest are denied.

When a node becomes the leader/holder, it will send out a gratuitous ARP reply 
over all of the configured interfaces. Clients whom accept these will update 
their ARP tables at once causing them to send traffic to the new leader/holder.
Not all clients accept gratuitous ARP replies since they can be used for ARP spoofing. 
Such clients might experience longer downtime then configured in the leases 
since they will only re-query via ARP when TTL in their internal tables 
has been reached.
