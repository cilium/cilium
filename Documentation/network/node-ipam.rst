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

It works by getting the Node addresses of the selected pods and advertising them.
It will respect the ``.spec.ipFamilies`` to decide if IPv4 or IPv6 addresses
shall be used and will use the ``ExternalIP`` addresses if any or the
``InternalIP`` addresses otherwise.

To use this feature your service must be of type ``LoadBalancer`` and have the
`loadBalancerClass <https://kubernetes.io/docs/concepts/services-networking/service/#load-balancer-class>`__
set to ``io.cilium/node``.

Cilium's node IPAM is disabled by default.
To install Cilium with the node IPAM, run:

.. parsed-literal::

   helm install cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --set nodeIPAM.enabled=true

To enable the node IPAM on an existing installation, run:

.. parsed-literal::

   helm upgrade cilium |CHART_RELEASE| \\
     --namespace kube-system \\
     --reuse-values \\
     --set nodeIPAM.enabled=true
   kubectl -n kube-system rollout restart deployment/cilium-operator
