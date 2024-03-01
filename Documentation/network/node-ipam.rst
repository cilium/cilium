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
use either the L2 Aware LB or BGP capabilities of Cilium.

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

Gateway API and Ingress Controller Considerations
-------------------------------------------------

By Spec, Kubernetes requires at least one address in the Endpoints list if Pod Label selectors are not used.
In order to overcome this limitation, Services created for Gateway API and Ingress Controller-managed resources,
Cilium will inject a "virtual" Endpoint of ``192.192.192.192:9999``.

Because all Cilium Agents are able to process Gateway API or Ingress traffic, it is possible for the Node IPAM LB
to allow all Nodes in the Cluster to listen for incoming connections. Setting the ``loadBalancerClass`` to ``io.cilium/node``
will add all Nodes to the Ingress IP list in the Load Balancer Service and accept traffic on the requested ports.

Selecting Nodes to Listen for Gateway and Ingress Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To restrict the Nodes that should listen for incoming traffic for Cilium Gateway and Ingress Services, you may
add an annotation, ``io.cilium.nodeipam/match-node-labels``, to the Service. The value of the annotation is a
`Label Selector <https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors>`__.

.. note::
   The node selector feature only works for Cilium-managed LoadBalancers for Gateways and Ingresses.
   Applying this label has no effect on other LoadBalancer Services.


You can test this Label Selector by using the ``kubectl get nodes`` command. For example, to exclude traffic to all
Control Plane nodes, you may use this Label Selector: ``!node-role.kubernetes.io/control-plane``
The Annotation would be configured as follows:

.. parsed-literal::
   io.cilium.nodeipam/match-node-labels="!node-role.kubernetes.io/control-plane"

To verify the Nodes that would be returned, run the following command in your terminal:

.. parsed-literal::
   kubectl get nodes -l '!node-role.kubernetes.io/control-plane'

   NAME          STATUS   ROLES    AGE     VERSION
   kind-worker   Ready    <none>   6h32m   v1.29.1

It is possible to combine multiple filters. For example, Nodes where the Label ``beehive.local/node`` value is
``hive1`` or ``hive2``, the Label ``honey`` is set to ``yes``, and the Label ``bears`` does not exist would use the
following filter Annotation:

.. parsed-literal::
   io.cilium.nodeipam/match-node-labels="beehive.local/node in (hive1,hive2),honey=yes,!bears"

Configuring Resources for Node IPAM LB
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Ingress Controller**

Use the following Helm values to enabling Node IPAM LB for the shared Ingress Controller:

.. parsed-literal::
   nodeIPAM:
     enabled: true
   ingressController:
     enabled: true
     loadbalancerMode: shared
     service:
       loadBalancerClass: io.cilium/node
   # Annotation is optional. Enable to limit Load Balancer IPs to the desired Nodes.
       annotations:
         io.cilium.nodeipam/match-node-labels: "..."

Node IPAM LB support for dedicated Ingress resources is not directly possible.
See the Warning in the Gateway API section below for more details on how to possibly configure a policy to update
your dedicated Ingresses. You will need to add the ``io.cilium.nodeipam`` prefix to the ``ingressController.ingressLBAnnotationPrefixes``
value in your Helm Chart.

Using Node IPAM LB with dedicated Ingresses has not been tested!

**Gateway API**

See the :doc:`servicemesh/gateway-api/gateway-api` Documentation for more fully configuring the appropriate resources.
As an example, you can add the Annotation to the ``spec.infrastructure.annotations`` field where it will be copied to
the created Gateway Service.

.. warning::
   Cilium does not currently support specifying the ``loadBalancerClass`` field for Gateway resources. It is possible
   to set this value with a mutating admission webhook.
   See this `Github Issue comment <https://github.com/cilium/cilium/issues/27493#issuecomment-1681970707>`__ for more details.

To specify the annotation to be automatically copied from the Gateway to Service resource, see the following example Gateway spec:

.. parsed-literal::
   apiVersion: gateway.networking.k8s.io/v1
   kind: Gateway
   metadata:
     name: my-gateway
   spec:
     gatewayClassName: cilium
   # Annotation is optional. Enable to limit Load Balancer IPs to the desired Nodes.
     infrastructure:
       annotations:
         io.cilium.nodeipam/match-node-labels: "..."
     listeners:
     - <...snip...>