.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _envoy:

=====
Envoy
=====

Envoy proxy shipped with Cilium is built with minimal Envoy extensions and custom policy enforcement filters.
Cilium uses this minimal distribution as its host proxy for enforcing HTTP and other L7 policies as specified in network policies
for the cluster. Cilium proxy is distributed within the Cilium images.

For more information on the version compatibility matrix, see `Cilium Proxy documentation <https://github.com/cilium/proxy#version-compatibility-matrix>`_.

***********************
Deployment as DaemonSet
***********************

Background
==========

When Cilium L7 functionality (Ingress, Gateway API, Network Policies with L7 functionality, L7 Protocol Visibility)
is enabled or installed in a Kubernetes cluster, the Cilium agent starts an Envoy proxy as separate process within
the Cilium agent pod.

That Envoy proxy instance becomes responsible for proxying all matching L7 requests on that node.
As a result, L7 traffic targeted by policies depends on the availability of the Cilium agent pod.

Alternatively, it's possible to deploy the Envoy proxy as independently life-cycled DaemonSet called ``cilium-envoy``
instead of running it from within the Cilium Agent Pod.

The communication between Cilium agent and Envoy proxy takes place via UNIX domain sockets in both deployment modes.
Be that streaming the access logs (e.g. L7 Protocol Visibility), updating the configuration via
`xDS <https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol>`_ or accessing the admin interface.
Due to the use of UNIX domain sockets, Envoy DaemonSet and the Cilium Agent need to have compatible types when SELinux is enabled on the host. This is the case if not specified otherwise, both using the highly privileged type: ``spc_t``. SELinux is enabled by default on Red Hat OpenShift Container Platform.

Enable and configure Envoy DaemonSet
====================================

To enable the dedicated Envoy proxy DaemonSet, install Cilium with the Helm value ``envoy.enabled`` set to ``true``.

Please see the :ref:`helm_reference` (keys with ``envoy.*``) for detailed information on how to configure the Envoy proxy DaemonSet.

Potential Benefits
==================

- Cilium Agent restarts (e.g. for upgrades) without impacts for the live traffic proxied via Envoy.
- Envoy patch release upgrades without impacts for the Cilium Agent.
- Separate CPU and memory limits for Envoy and Cilium Agent for performance isolation.
- Envoy application log not mixed with the one of the Cilium Agent.
- Dedicated health probes for the Envoy proxy.
- Explicit deployment of Envoy proxy during Cilium installation (compared to on demand in the embedded mode).

.. admonition:: Video
 :class: attention

  If you'd like to see Cilium Envoy in action, check out `eCHO episode 127: Cilium & Envoy <https://www.youtube.com/watch?v=HEwruycGbCU>`__.
