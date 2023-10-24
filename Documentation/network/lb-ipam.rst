.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _lb_ipam:

********************************************
LoadBalancer IP Address Management (LB IPAM)
********************************************

LB IPAM is a feature that allows Cilium to assign IP addresses to Services of
type ``LoadBalancer``. This functionality is usually left up to a cloud provider,
however, when deploying in a private cloud environment, these facilities are not
always available.

LB IPAM works in conjunction with features such as :ref:`bgp_control_plane` and :ref:`l2_announcements`. Where
LB IPAM is responsible for allocation and assigning of IPs to Service objects and
other features are responsible for load balancing and/or advertisement of these
IPs. 

Use :ref:`bgp_control_plane` to advertise the IP addresses assigned by LB IPAM over BGP and :ref:`l2_announcements` to advertise them locally.

LB IPAM is always enabled but dormant. The controller is awoken when the first
IP Pool is added to the cluster.

.. _lb_ipam_pools:

Pools
#####

LB IPAM has the notion of IP Pools which the administrator can create to tell 
Cilium which IP ranges can be used to allocate IPs from.

A basic IP Pools with both an IPv4 and IPv6 range looks like this:

.. code-block:: yaml

    apiVersion: "cilium.io/v2alpha1"
    kind: CiliumLoadBalancerIPPool
    metadata:
      name: "blue-pool"
    spec:
      blocks:
      - cidr: "10.0.10.0/24"
      - cidr: "2004::0/64"
      - start: "20.0.20.100"
        stop: "20.0.20.200"
      - start: "1.2.3.4"

After adding the pool to the cluster, it appears like so.

.. code-block:: shell-session

    $ kubectl get ippools                           
    NAME        DISABLED   CONFLICTING   IPS AVAILABLE   AGE
    blue-pool   false      False         65788           2s

CIDRs, Ranges and reserved IPs
------------------------------

An IP pool can have multiple blocks of IPs. A block can be specified with CIDR
notation (<prefix>/<bits>) or a range notation with a start and stop IP. As
pictured in :ref:`lb_ipam_pools`.

CIDRs are often used to specify routable IP ranges. By convention, the first
and the last IP of a CIDR are reserved. The first IP is the 
"network address" and the last IP is the "broadcast address". In some networks
these IPs are not usable and they do not always play well with all network 
equipment. LB-IPAM will not assign these by default. Exceptions are /32 and 
/31 IPv4 CIDRs and /128 and /127 IPv6 CIDRs since these only have 1 or 2 IPs 
respectively.

If you wish to use the first and last IPs of CIDRs, you can set the 
``.spec.allowFirstLastIPs`` field to ``yes``.

Since Ranges are typically used to indicate subsections of routable IP ranges,
no IPs are reserved.

.. warning::

  In v1.15, ``.spec.allowFirstLastIPs`` defaults to ``no``. This will change to
  ``yes`` in v1.16. Please set this field explicitly if you rely on the field
  being set to ``no``.

Service Selectors
-----------------

IP Pools have an optional ``.spec.serviceSelector`` field which allows administrators
to limit which services can get IPs from which pools using a `label selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/>`__.
The pool will allocate to any service if no service selector is specified.

.. code-block:: yaml

    apiVersion: "cilium.io/v2alpha1"
    kind: CiliumLoadBalancerIPPool
    metadata:
      name: "blue-pool"
    spec:
      blocks:
      - cidr: "20.0.10.0/24"
      serviceSelector:
        matchExpressions:
          - {key: color, operator: In, values: [blue, cyan]}
    ---
    apiVersion: "cilium.io/v2alpha1"
    kind: CiliumLoadBalancerIPPool
    metadata:
      name: "red-pool"
    spec:
      blocks:
      - cidr: "20.0.10.0/24"
      serviceSelector:
        matchLabels:
          color: red

There are a few special purpose selector fields which don't match on labels but
instead on other metadata like ``.meta.name`` or ``.meta.namespace``.

=============================== ===================
Selector                        Field
------------------------------- -------------------
io.kubernetes.service.namespace ``.meta.namespace``
io.kubernetes.service.name      ``.meta.name``
=============================== ===================

For example:

.. code-block:: yaml

    apiVersion: "cilium.io/v2alpha1"
    kind: CiliumLoadBalancerIPPool
    metadata:
      name: "blue-pool"
    spec:
      blocks:
      - cidr: "20.0.10.0/24"
      serviceSelector:
        matchLabels:
          "io.kubernetes.service.namespace": "tenant-a"

Conflicts
---------

IP Pools are not allowed to have overlapping CIDRs. When an administrator does
create pools which overlap, a soft error is caused. The last added pool will be
marked as ``Conflicting`` and no further allocation will happen from that pool.
Therefore, administrators should always check the status of all pools after making
modifications.

For example, if we add 2 pools (``blue-pool`` and ``red-pool``) both with the same
CIDR, we will see the following:

.. code-block:: shell-session

    $ kubectl get ippools
    NAME        DISABLED   CONFLICTING   IPS AVAILABLE   AGE
    blue-pool   false      False         254             25m
    red-pool    false      True          254             11s

The reason for the conflict is stated in the status and can be accessed like so

.. code-block:: shell-session

    $ kubectl get ippools/red-pool -o jsonpath='{.status.conditions[?(@.type=="cilium.io/PoolConflict")].message}'
    Pool conflicts since CIDR '20.0.10.0/24' overlaps CIDR '20.0.10.0/24' from IP Pool 'blue-pool'

or

.. code-block:: shell-session

    $ kubectl describe ippools/red-pool
    Name:         red-pool
    #[...]
    Status:
      Conditions:
        #[...]
            Last Transition Time:  2022-10-25T14:09:05Z
            Message:               Pool conflicts since CIDR '20.0.10.0/24' overlaps CIDR '20.0.10.0/24' from IP Pool 'blue-pool'
            Observed Generation:   1
            Reason:                cidr_overlap
            Status:                True
            Type:                  cilium.io/PoolConflict
        #[...]

Disabling a Pool
-----------------

IP Pools can be disabled. Disabling a pool will stop LB IPAM from allocating
new IPs from the pool, but doesn't remove existing allocations. This allows
an administrator to slowly drain pool or reserve a pool for future use.

.. code-block:: yaml

    apiVersion: "cilium.io/v2alpha1"
    kind: CiliumLoadBalancerIPPool
    metadata:
      name: "blue-pool"
    spec:
      blocks:
      - cidr: "20.0.10.0/24"
      disabled: true

.. code-block:: shell-session

    $ kubectl get ippools          
    NAME        DISABLED   CONFLICTING   IPS AVAILABLE   AGE
    blue-pool   true       False         254             41m

Status
------

The IP Pool's status contains additional counts which can be used to monitor
the amount of used and available IPs. A machine parsable output can be obtained like so.

.. code-block:: shell-session

    $ kubectl get ippools -o jsonpath='{.items[*].status.conditions[?(@.type!="cilium.io/PoolConflict")]}' | jq
    {
      "lastTransitionTime": "2022-10-25T14:08:55Z",
      "message": "254",
      "observedGeneration": 1,
      "reason": "noreason",
      "status": "Unknown",
      "type": "cilium.io/IPsTotal"
    }
    {
      "lastTransitionTime": "2022-10-25T14:08:55Z",
      "message": "254",
      "observedGeneration": 1,
      "reason": "noreason",
      "status": "Unknown",
      "type": "cilium.io/IPsAvailable"
    }
    {
      "lastTransitionTime": "2022-10-25T14:08:55Z",
      "message": "0",
      "observedGeneration": 1,
      "reason": "noreason",
      "status": "Unknown",
      "type": "cilium.io/IPsUsed"
    }

Or human readable output like so

.. code-block:: shell-session

    $ kubectl describe ippools/blue-pool
    Name:         blue-pool
    Namespace:    
    Labels:       <none>
    Annotations:  <none>
    API Version:  cilium.io/v2alpha1
    Kind:         CiliumLoadBalancerIPPool
    #[...]
    Status:
      Conditions:
        #[...]
        Last Transition Time:  2022-10-25T14:08:55Z
        Message:               254
        Observed Generation:   1
        Reason:                noreason
        Status:                Unknown
        Type:                  cilium.io/IPsTotal
        Last Transition Time:  2022-10-25T14:08:55Z
        Message:               254
        Observed Generation:   1
        Reason:                noreason
        Status:                Unknown
        Type:                  cilium.io/IPsAvailable
        Last Transition Time:  2022-10-25T14:08:55Z
        Message:               0
        Observed Generation:   1
        Reason:                noreason
        Status:                Unknown
        Type:                  cilium.io/IPsUsed

Services
########

Any service with ``.spec.type=LoadBalancer`` can get IPs from any pool as long
as the IP Pool's service selector matches the service.

Lets say we add a simple service.

.. code-block:: yaml

    apiVersion: v1
    kind: Service
    metadata:
      name: service-red
      namespace: example
      labels:
        color: red
    spec:
      type: LoadBalancer
      ports:
      - port: 1234

This service will appear like so.

.. code-block:: shell-session

    $ kubectl -n example get svc
    NAME          TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
    service-red   LoadBalancer   10.96.192.212   <pending>     1234:30628/TCP   24s

The ExternalIP field has a value of ``<pending>`` which means no LB IPs have been assigned.
When LB IPAM is unable to allocate or assign IPs for the service, it will update the service
conditions in the status.

The service conditions can be checked like so:

.. code-block:: shell-session

    $ kubectl -n example get svc/service-red -o jsonpath='{.status.conditions}' | jq
    [
      {
        "lastTransitionTime": "2022-10-06T13:40:48Z",
        "message": "There are no enabled CiliumLoadBalancerIPPools that match this service",
        "reason": "no_pool",
        "status": "False",
        "type": "io.cilium/lb-ipam-request-satisfied"
      }
    ]

After updating the service labels to match our ``blue-pool`` from before we see:

.. code-block:: shell-session

    $ kubectl -n example get svc
    NAME          TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
    service-red   LoadBalancer   10.96.192.212   20.0.10.163   1234:30628/TCP   12m

    $ kubectl -n example get svc/service-red -o jsonpath='{.status.conditions}' | jq
    [
      {
        "lastTransitionTime": "2022-10-06T13:40:48Z",
        "message": "There are no enabled CiliumLoadBalancerIPPools that match this service",
        "reason": "no_pool",
        "status": "False",
        "type": "io.cilium/lb-ipam-request-satisfied"
      },
      {
        "lastTransitionTime": "2022-10-06T13:52:55Z",
        "message": "",
        "reason": "satisfied",
        "status": "True",
        "type": "io.cilium/lb-ipam-request-satisfied"
      }
    ]

IPv4 / IPv6 families + policy
-----------------------------

LB IPAM supports IPv4 and/or IPv6 in SingleStack or `DualStack <https://kubernetes.io/docs/concepts/services-networking/dual-stack/>`__ mode. 
Services can use the ``.spec.ipFamilyPolicy`` and ``.spec.ipFamilies`` fields to change
the requested IPs.

If ``.spec.ipFamilyPolicy`` isn't specified, ``SingleStack`` mode is assumed. 
If both IPv4 and IPv6 are enabled in ``SingleStack`` mode, an IPv4 address is allocated.

If ``.spec.ipFamilyPolicy`` is set to ``PreferDualStack``, LB IPAM will attempt to allocate 
both an IPv4 and IPv6 address if both are enabled on the cluster. If only IPv4 or only IPv6 is
enabled on the cluster, the service is still considered "satisfied".

If ``.spec.ipFamilyPolicy`` is set to ``RequireDualStack`` LB IPAM will attempt to allocate
both an IPv4 and IPv6 address. The service is considered "unsatisfied" If IPv4 
or IPv6 is disabled on the cluster.

The order of ``.spec.ipFamilies`` has no effect on LB IPAM but is significant for cluster IP
allocation which isn't handled by LB IPAM.

LoadBalancerClass
-----------------

Kubernetes >= v1.24 supports `multiple load balancers <https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`_ 
in the same cluster. Picking between load balancers is done with the ``.spec.loadBalancerClass`` field. 
When LB IPAM is enabled it allocates and assigns IPs for services with 
no load balancer class set.

LB IPAM only does IP allocation and doesn't provide load balancing services by itself. Therefore,
users should pick one of the following Cilium load balancer classes, all of which use LB IPAM
for allocation (if the feature is enabled):

=============================== ========================
loadBalancerClass               Feature
------------------------------- ------------------------
``io.cilium/bgp-control-plane`` :ref:`bgp_control_plane`
=============================== ========================

If the ``.spec.loadBalancerClass`` is set to a class which isn't handled by Cilium's LB IPAM, 
then Cilium's LB IPAM will ignore the service entirely, not even setting a condition in the status. 

Requesting IPs
--------------

Services can request specific IPs. The legacy way of doing so is via ``.spec.loadBalancerIP``
which takes a single IP address. This method has been deprecated in k8s v1.24 but is supported
until its future removal.

The new way of requesting specific IPs is to use annotations, ``io.cilium/lb-ipam-ips`` in the case
of Cilium LB IPAM. This annotation takes a comma-separated list of IP addresses, allowing for
multiple IPs to be requested at once.

The service selector of the IP Pool still applies, requested IPs will not be allocated or assigned
if the services don't match the pool's selector.

Don't configure the annotation to request the first or last IP of an IP pool. They are reserved 
for the network and broadcast addresses respectively.

.. code-block:: yaml

    apiVersion: v1
    kind: Service
    metadata:
      name: service-blue
      namespace: example
      labels:
        color: blue
      annotations:
        "io.cilium/lb-ipam-ips": "20.0.10.100,20.0.10.200"
    spec:
      type: LoadBalancer
      ports:
      - port: 1234

.. code-block:: shell-session

    $ kubectl -n example get svc                
    NAME           TYPE           CLUSTER-IP     EXTERNAL-IP               PORT(S)          AGE
    service-blue   LoadBalancer   10.96.26.105   20.0.10.100,20.0.10.200   1234:30363/TCP   43s

Sharing Keys
------------

Services can share the same IP or set of IPs with other services. This is done by setting the ``io.cilium/lb-ipam-sharing-key`` annotation on the service.
Services that have the same sharing key annotation will share the same IP or set of IPs. The sharing key is a string that can be any value.

.. code-block:: yaml

  apiVersion: v1
  kind: Service
  metadata:
    name: service-blue
    namespace: example
    labels:
      color: blue
    annotations:
      "io.cilium/lb-ipam-sharing-key": "1234"
  spec:
    type: LoadBalancer
    ports:
    - port: 1234
  ---
  apiVersion: v1
  kind: Service
  metadata:
    name: service-red
    namespace: example
    labels:
      color: red
    annotations:
      "io.cilium/lb-ipam-sharing-key": "1234"
  spec:
    type: LoadBalancer
    ports:
    - port: 2345

.. code-block:: shell-session

  $ kubeclt -n example get svc
  NAME           TYPE           CLUSTER-IP     EXTERNAL-IP               PORT(S)          AGE
  service-blue   LoadBalancer   10.96.26.105   20.0.10.100               1234:30363/TCP   43s
  service-red    LoadBalancer   10.96.26.106   20.0.10.100               2345:30131/TCP   43s

As long as the services do not have conflicting ports, they will be allocated the same IP. If the services have conflicting ports, they will be allocated different IPs, which will be added to the set of IPs belonging to the sharing key.
If a service has a sharing key and also requests a specific IP, the service will be allocated the requested IP and it will be added to the set of IPs belonging to that sharing key.
