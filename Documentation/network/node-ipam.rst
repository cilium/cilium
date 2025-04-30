.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _node_ipam:

************
Node IPAM LB
************

Node IPAM LoadBalancer is a feature inspired by k3s "ServiceLB" that allows you
to "advertise" the node's IPs directly inside a Service LoadBalancer. This feature
is especially useful if you don't control the network you are running on and can't
use either the L2 or BGP capabilities of Cilium.

It works by getting the Node addresses of the selected Nodes and advertising them.
It will respect the ``.spec.ipFamilies`` to decide if IPv4 or IPv6 addresses
shall be used and will use the ``ExternalIP`` addresses if any or the
``InternalIP`` addresses otherwise.

If the Service has ``.spec.externalTrafficPolicy`` set to ``Cluster``, Node IPAM
considers all nodes as candidates for selection. Otherwise, if
``.spec.externalTrafficPolicy`` is set to ``Local``, then Node IPAM considers
all the Pods selected by the Service (via their EndpointSlices) as candidates.

.. warning::
    Node IPAM does not work properly if ``.spec.externalTrafficPolicy`` is set
    to ``Local`` but no EndpointSlice (or dummy EndpointSlice) is linked to
    the corresponding Service.

    As a result, you **cannot** set ``.spec.externalTrafficPolicy`` to ``Local``
    with the Cilium implementations for GatewayAPI or Ingress, because Cilium
    currently uses a dummy Endpoints for the Service LoadBalancer (`see here
    <https://github.com/cilium/cilium/blob/495f228ad8791c89f0851e0abbad90f09b136f80/install/kubernetes/cilium/templates/cilium-ingress-service.yaml#L58>`__).
    Only the Cilium implementation is known to be affected by this limitation.
    Most other implementations are expected to work with this configuration.
    If they don't, check if the matching EndpointSlices look correct and/or
    try setting ``.spec.externalTrafficPolicy`` to ``Cluster``.

Node IPAM honors the Node label ``node.kubernetes.io/exclude-from-external-load-balancers``
and the Node taint ``ToBeDeletedByClusterAutoscaler``. Node IPAM **doesn't**
consider a node as a candidate for load balancing if the label
``node.kubernetes.io/exclude-from-external-load-balancers`` or the taint
``ToBeDeletedByClusterAutoscaler`` is present.

To restrict the Nodes that should listen for incoming traffic, add annotation
``io.cilium.nodeipam/match-node-labels`` to the Service. The value of the
annotation is a
`Label Selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors>`__.

Enable and use Node IPAM
------------------------

To use this feature your Service must be of type ``LoadBalancer`` and have the
`loadBalancerClass <https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`__
set to ``io.cilium/node``. You can also allow set ``defaultLBServiceIPAM``
to ``nodeipam`` to use this feature on a Service that doesn't specify a loadBalancerClass.

Cilium's node IPAM is disabled by default.
To install Cilium with the node IPAM, run:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set nodeIPAM.enabled=true

To enable node IPAM on an existing installation, run:

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --reuse-values \\
     --set nodeIPAM.enabled=true
   kubectl -n kube-system rollout restart deployment/cilium-operator
