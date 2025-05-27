.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _l2_announcements:

*************************************
L2 Announcements / L2 Aware LB (Beta)
*************************************

.. include:: ../beta.rst

L2 Announcements is a feature which makes services visible and reachable on 
the local area network. This feature is primarily intended for on-premises
deployments within networks without BGP based routing such as office or 
campus networks.

When used, this feature will respond to ARP queries for ExternalIPs and/or 
LoadBalancer IPs. These IPs are Virtual IPs (not installed on network 
devices) on multiple nodes, so for each service one node at a time will respond
to the ARP queries and respond with its MAC address. This node will perform 
load balancing with the service load balancing feature, thus acting as a 
north/south load balancer.

The advantage of this feature over NodePort services is that each service can
use a unique IP so multiple services can use the same port numbers. When using 
NodePorts, it is up to the client to decide to which host to send traffic, and if a node
goes down, the IP+Port combo becomes unusable. With L2 announcements the service
VIP simply migrates to another node and will continue to work.

.. _l2_announcements_settings:

Configuration
#############

The L2 Announcements feature and all the requirements can be enabled as follows:

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set l2announcements.enabled=true \\
               --set k8sClientRateLimit.qps={QPS} \\
               --set k8sClientRateLimit.burst={BURST} \\
               --set kubeProxyReplacement=true \\
               --set k8sServiceHost=${API_SERVER_IP} \\
               --set k8sServicePort=${API_SERVER_PORT}
               

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-l2-announcements: true
            kube-proxy-replacement: true
            k8s-client-qps: {QPS}
            k8s-client-burst: {BURST}

.. warning::
  Sizing the client rate limit (``k8sClientRateLimit.qps`` and ``k8sClientRateLimit.burst``) 
  is important when using this feature due to increased API usage. See :ref:`sizing_client_rate_limit` for sizing guidelines.

Prerequisites
#############

* Kube Proxy replacement mode must be enabled. For more information, see
  :ref:`kubeproxy-free`.

* All devices on which L2 Aware LB will be announced should be enabled and included in the 
  ``--devices`` flag or ``devices`` Helm option if explicitly set, see :ref:`NodePort Devices`.

* The ``externalIPs.enabled=true`` Helm option must be set, if usage of externalIPs
  is desired. Otherwise service load balancing for external IPs is disabled.

Limitations
###########

* The feature currently does not support IPv6/NDP.

* Due to the way L3->L2 translation protocols work, one node receives all 
  ARP requests for a specific IP, so no load balancing can happen before traffic hits the cluster.

* The feature currently has no traffic balancing mechanism so nodes within the
  same policy might be asymmetrically loaded. For details see :ref:`l2_announcements_leader_election`.

* The feature is incompatible with the ``externalTrafficPolicy: Local`` on services as it may cause 
  service IPs to be announced on nodes without pods causing traffic drops.

Policies
########

Policies provide fine-grained control over which services should be announced,
where, and how. This is an example policy using all optional fields:

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
        matchExpressions:
          - key: node-role.kubernetes.io/control-plane
            operator: DoesNotExist
      interfaces:
      - ^eth[0-9]+
      externalIPs: true
      loadBalancerIPs: true  

Service Selector
----------------

The service selector is a `label selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/>`__ 
that determines which services are selected by this policy. If no service 
selector is provided, all services are selected by the policy. A service must have
`loadBalancerClass <https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`__
unspecified or set to ``io.cilium/l2-announcer`` to be selected by a policy for announcement.

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
node (see :ref:`l2_announcements_leader_election`) will act as the north/south
load balancer for all of the traffic for a particular service.

Interfaces
----------

The interfaces field is a list of regular expressions (`golang syntax <https://pkg.go.dev/regexp/syntax>`__)
that determine over which network interfaces the selected services will be 
announced. This field is optional, if not specified all interfaces will be used.

The expressions are OR-ed together, so any network device matching any of the 
expressions will be matched.

L2 announcements only work if the selected devices are also part of the set of 
devices specified in the ``devices`` Helm option, see :ref:`NodePort Devices`.

.. note::
    This selector is NOT a security feature, services will still be available 
    via interfaces when not advertised (for example by hard-coding ARP entries).

IP Types
--------

The ``externalIPs`` and ``loadBalancerIPs`` fields determine what sort of IPs 
are announced. They are both set to ``false`` by default, so a functional policy should always
have one or both set to ``true``.

If ``externalIPs`` is ``true`` all IPs in `.spec.externalIPs <https://kubernetes.io/docs/concepts/services-networking/service/#external-ips>`__
field are announced. These IPs are managed by service authors.

If ``loadBalancerIPs`` is ``true`` all IPs in the service's ``.status.loadbalancer.ingress`` field
are announced. These can be assigned by :ref:`lb_ipam` which can be configured
by cluster admins for better control over which IPs can be allocated.

.. note::
    If a user intends to use ``externalIPs``, the ``externalIPs.enable=true`` 
    Helm option should be set to enable service load balancing for external IPs.

Status
------

If a policy is invalid for any number of reasons, the status of the policy will reflect that.
For example if an invalid match expression is provided:

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
  failover occurs. Its default value is 15s, it must always be greater than 1s
  and be larger than ``leaseRenewDeadline``.

* ``l2announcements.leaseRenewDeadline`` is the interval at which the leader 
  should renew the lease. Its default value is 5s, it must be greater than
  ``leaseRetryPeriod`` by at least 20% and is not allowed to be below ``1ns``.

* ``l2announcements.leaseRetryPeriod`` if renewing the lease fails, how long 
  should the agent wait before it tries again. Its default value is 2s, it
  must be smaller than ``leaseRenewDeadline`` by at least 20% and above ``1ns``.

.. note::
  The theoretical shortest time between failure and failover is 
  ``leaseDuration - leaseRenewDeadline`` and the longest ``leaseDuration + leaseRenewDeadline``.
  So with the default values, failover occurs between 10s and 20s.
  For the example below, these times are between 2s and 4s.

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set l2announcements.enabled=true \\
               --set kubeProxyReplacement=true \\
               --set k8sServiceHost=${API_SERVER_IP} \\
               --set k8sServicePort=${API_SERVER_PORT} \\
               --set k8sClientRateLimit.qps={QPS} \\
               --set k8sClientRateLimit.burst={BURST} \\
               --set l2announcements.leaseDuration=3s \\
               --set l2announcements.leaseRenewDeadline=1s \\
               --set l2announcements.leaseRetryPeriod=200ms

    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-l2-announcements: true
            kube-proxy-replacement: true
            l2-announcements-lease-duration: 3s
            l2-announcements-renew-deadline: 1s
            l2-announcements-retry-period: 200ms
            k8s-client-qps: {QPS}
            k8s-client-burst: {BURST}

There is a trade-off between fast failure detection and CPU + network usage. 
Each service incurs a CPU and network overhead, so clusters with smaller amounts
of services can more easily afford faster failover times. Larger clusters might
need to increase parameters if the overhead is too high.

.. _sizing_client_rate_limit:

Sizing client rate limit
========================

The leader election process continually generates API traffic, the exact amount
depends on the configured lease duration, configured renew deadline, and amount
of services using the feature.

The default client rate limit is 5 QPS with allowed bursts up to 10 QPS. this
default limit is quickly reached when utilizing L2 announcements and thus users
should size the client rate limit accordingly.

In a worst case scenario, services are distributed unevenly, so we will assume
a peak load based on the renew deadline. In complex scenarios with multiple 
policies over disjointed sets of node, max QPS per node will be lower.

.. code-block:: text

  QPS = #services * (1 / leaseRenewDeadline)

  // example
  #services = 65
  leaseRenewDeadline = 2s
  QPS = 65 * (1 / 2s) = 32.5 QPS

Setting the base QPS to around the calculated value should be sufficient, given
in multi-node scenarios leases are spread around nodes, and non-holders participating
in the election have a lower QPS.

The burst QPS should be slightly higher to allow for bursts of traffic caused
by other features which also use the API server.

Failover
--------

When nodes participating in leader election detect that the lease holder did not
renew the lease for ``leaseDurationSeconds`` amount of seconds, they will ask
the API server to make them the new holder. The first request to be processed 
gets through and the rest are denied.

When a node becomes the leader/holder, it will send out a gratuitous ARP reply 
over all of the configured interfaces. Clients who accept these will update 
their ARP tables at once causing them to send traffic to the new leader/holder.
Not all clients accept gratuitous ARP replies since they can be used for ARP spoofing. 
Such clients might experience longer downtime then configured in the leases 
since they will only re-query via ARP when TTL in their internal tables 
has been reached.

.. note::
   Since this feature has no IPv6 support yet, only ARP messages are sent, no 
   Unsolicited Neighbor Advertisements are sent.

Troubleshooting
###############

This section is a step by step guide on how to troubleshoot L2 Announcements,
hopefully solving your issue or narrowing it down to a specific area.

The first thing we need to do is to check that the feature is enabled, kube proxy replacement
is active and optionally that external IPs are enabled.

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg config --all | grep EnableL2Announcements
    EnableL2Announcements             : true

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg config --all | grep KubeProxyReplacement
    KubeProxyReplacement              : true

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg config --all | grep EnableExternalIPs
    EnableExternalIPs                 : true

If ``EnableL2Announcements`` or ``KubeProxyReplacement`` indicates ``false``, make sure to enable the
correct settings and deploy the helm chart :ref:`l2_announcements_settings`. ``EnableExternalIPs`` should be set to ``true`` if you intend to use external IPs.

Next, ensure you have at least one policy configured, L2 announcements will not work without a policy.

.. code-block:: shell-session

    $ kubectl get CiliumL2AnnouncementPolicy
    NAME      AGE
    policy1   6m16s

L2 announcements should now create a lease for every service matched by the policy. We can check the leases like so:

.. code-block:: shell-session

    $ kubectl -n kube-system get lease | grep "cilium-l2announce"
    cilium-l2announce-default-service-red   kind-worker                       34s

If the output is empty, then the policy is not correctly configured or the agent is not running correctly. 
Check the logs of the agent for error messages:

.. code-block:: shell-session

    $ kubectl -n kube-system logs ds/cilium | grep "l2"

A common error is that the agent is not able to create leases. 

.. code-block:: shell-session

    $ kubectl -n kube-system logs ds/cilium | grep "error"
    time="2024-06-25T12:01:43Z" level=error msg="error retrieving resource lock kube-system/cilium-l2announce-default-service-red: leases.coordination.k8s.io \"cilium-l2announce-default-service-red\" is forbidden: User \"system:serviceaccount:kube-system:cilium\" cannot get resource \"leases\" in API group \"coordination.k8s.io\" in the namespace \"kube-system\"" subsys=klog

This can happen if the cluster role of the agent is not correct. This tends to happen when L2 announcements is enabled
without using the helm chart. Redeploy the helm chart or manually update the cluster role, by running
``kubectl edit clusterrole cilium`` and adding the following block to the rules:

.. code-block:: yaml

    - apiGroups:
      - coordination.k8s.io
      resources:
      - leases
      verbs:
      - create
      - get
      - update
      - list
      - delete

Another common error is that the configured client rate limit is too low. 
This can be seen in the logs as well:

.. code-block:: shell-session

    $ kubectl -n kube-system logs ds/cilium | grep "l2"
    2023-07-04T14:59:51.959400310Z level=info msg="Waited for 1.395439596s due to client-side throttling, not priority and fairness, request: GET:https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/cilium-l2announce-default-example" subsys=klog
    2023-07-04T15:00:12.159409007Z level=info msg="Waited for 1.398748976s due to client-side throttling, not priority and fairness, request: PUT:https://127.0.0.1:6443/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/cilium-l2announce-default-example" subsys=klog

These logs are associated with intermittent failures to renew the lease, connection issues and/or frequent leader changes.
See :ref:`sizing_client_rate_limit` for more information on how to size the client rate limit.

If you find a different L2 related error, please open a GitHub issue with the error message and the 
steps you took to get there.

Assuming the leases are created, the next step is to check the agent internal state. Pick a service which isn't working
and inspect its lease. Take the holder name and find the cilium agent pod for the holder node.
Finally, take the name of the cilium agent pod and inspect the l2-announce state:

.. code-block:: shell-session

    $ kubectl -n kube-system get lease cilium-l2announce-default-service-red
    NAME                                    HOLDER        AGE
    cilium-l2announce-default-service-red   <node-name>   20m

    $ kubectl -n kube-system get pod -l 'app.kubernetes.io/name=cilium-agent' -o wide | grep <node-name>
    <agent-pod>   1/1     Running   0          35m   172.19.0.3   kind-worker          <none>           <none>

    $ kubectl -n kube-system exec pod/<agent-pod> -- cilium-dbg shell -- db/show l2-announce
    # IP        NetworkInterface
    10.0.10.0   eth0

The l2 announce state should contain the IP of the service and the network interface it is announced on.
If the lease is present but its IP is not in the l2-announce state, or you are missing an entry for a given network device.
Double check that the device selector in the policy matches the desired network device (values are regular expressions).
If the filter seems correct or isn't specified, inspect the known devices:

.. code-block:: shell-session

    $ kubectl -n kube-system exec ds/cilium -- cilium-dbg shell -- db/show devices
    Name              Index   Selected   Type     MTU     HWAddr              Flags                    Addresses
    lxc5d23398605f6   10      false      veth     1500    b6:ed:d8:d2:dd:ec   up|broadcast|multicast   fe80::b4ed:d8ff:fed2:ddec
    lxc3bf03c00d6e3   12      false      veth     1500    8a:d1:0c:91:8a:d3   up|broadcast|multicast   fe80::88d1:cff:fe91:8ad3
    eth0              50      true       veth     1500    02:42:ac:13:00:03   up|broadcast|multicast   172.19.0.3, fc00:c111::3, fe80::42:acff:fe13:3
    lo                1       false      device   65536                       up|loopback              127.0.0.1, ::1
    cilium_net        2       false      veth     1500    1a:a9:2f:4d:d3:3d   up|broadcast|multicast   fe80::18a9:2fff:fe4d:d33d
    cilium_vxlan      4       false      vxlan    1500    2a:05:26:8d:79:9c   up|broadcast|multicast   fe80::2805:26ff:fe8d:799c
    lxc611291f1ecbb   8       false      veth     1500    7a:fb:ec:54:e2:5c   up|broadcast|multicast   fe80::78fb:ecff:fe54:e25c
    lxc_health        16      false      veth     1500    0a:94:bf:49:d5:50   up|broadcast|multicast   fe80::894:bfff:fe49:d550
    cilium_host       3       false      veth     1500    22:32:e2:80:21:34   up|broadcast|multicast   10.244.1.239, fd00:10:244:1::f58a

Only devices with ``Selected`` set to ``true`` can be used for L2 announcements. Typically all physical devices with IPs
assigned to them will be considered selected. The ``--devices`` flag or ``devices`` Helm option can be used to filter
out devices. If your desired device is in the list but not selected, check the devices flag/option to see if it filters it out.

Please open a Github issue if your desired device doesn't appear in the list or it isn't selected while you believe it should be.

If the L2 state contains the IP and device combination but there are still connection issues, it's time to test ARP 
within the cluster. Pick a cilium agent pod other than the lease holder on the same L2 network.
Then use the following command to send an ARP request to the service IP:

.. code-block:: shell-session

    $ kubectl -n kube-system exec pod/cilium-z4ef7 -- sh -c 'apt update && apt install -y arping && arping -i <netdev-on-l2> <service-ip>'
    [omitting apt output...]
    ARPING 10.0.10.0
    58 bytes from 02:42:ac:13:00:03 (10.0.10.0): index=0 time=11.772 usec
    58 bytes from 02:42:ac:13:00:03 (10.0.10.0): index=1 time=9.234 usec
    58 bytes from 02:42:ac:13:00:03 (10.0.10.0): index=2 time=10.568 usec

If the output is as above yet the service is still unreachable, from clients within the same L2 network,
the issue might be client related. If you expect the service to be reachable from outside the L2 network,
and it is not, check the ARP and routing tables of the gateway device.

If the ARP request fails (the output shows ``Timeout``), check the BPF map of the cilium-agent with the lease:

.. code-block:: shell-session

    $ kubectl -n kube-system exec pod/cilium-vxz67 -- bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_l2_responder_v4
    [{
            "key": {
                "ip4": 655370,
                "ifindex": 50
            },
            "value": {
                "responses_sent": 20
            }
        }
    ]

The ``responses_sent`` field is incremented every time the datapath responds to an ARP request. If the field
is 0, then the ARP request doesn't make it to the node. If the field is greater than 0, the issue is on the
return path. In both cases, inspect the network and the client.

It is still possible that the service is unreachable even though ARP requests are answered. This can happen 
for a number of reasons, usually unrelated to L2 announcements, but rather other Cilium features.

One common issue however is caused by the usage of ``.Spec.ExternalTrafficPolicy: Local`` on services. This setting
normally tells a load balancer to only forward traffic to nodes with at least 1 ready pod to avoid a second hop.
Unfortunately, L2 announcements isn't currently aware of this setting and will announce the service IP on all nodes
matching policies. If a node without a pod receives traffic, it will drop it. To fix this, set the policy to 
``.Spec.ExternalTrafficPolicy: Cluster``.

Please open a Github issue if none of the above steps helped you solve your issue.

.. _l2_pod_announcements:

L2 Pod Announcements
####################

L2 Pod Announcements announce Pod IP addresses on the L2 network using
Gratuitous ARP replies. When enabled, the node transmits Gratuitous ARP
replies for every locally created pod, on the configured network
interface(s). This feature is enabled separately from the above L2
announcements feature.

To enable L2 Pod Announcements, set the following:

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set l2podAnnouncements.enabled=true \\
               --set l2podAnnouncements.interface=eth0


    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-l2-pod-announcements: true
            l2-pod-announcements-interface: eth0

The ``l2podAnnouncements.interface``/``l2-pod-announcements-interface`` options allows you to specify 
one interface use to send announcements.  If you would like to send announcements on multiple interfaces, you should use the
``l2podAnnouncements.interfacePattern``/``l2-pod-announcements-interface-pattern`` option instead. 
This option takes a regex, matching on multiple interfaces.

.. tabs::
    .. group-tab:: Helm

        .. parsed-literal::

            $ helm upgrade cilium |CHART_RELEASE| \\
               --namespace kube-system \\
               --reuse-values \\
               --set l2podAnnouncements.enabled=true \\
               --set l2podAnnouncements.interfacePattern='^(eth0|ens1)$'


    .. group-tab:: ConfigMap

        .. code-block:: yaml

            enable-l2-pod-announcements: true
            l2-pod-announcements-interface-pattern: "^(eth0|ens1)$"

.. note::
   Since this feature has no IPv6 support yet, only ARP messages are
   sent, no Unsolicited Neighbor Advertisements are sent.
