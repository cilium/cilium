.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _proxy_visibility:

*******************
L7 Proxy Visibility
*******************

While :ref:`monitor` provides introspection into datapath state, it only
provides L3/L4 visibility if it is ran in an environment which is running
with no policy enforcement at L7. To get more visibility into the application
layer, when running in tandem with Kubernetes, Cilium provides a means of
prescribing visibility via `annotations <https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/>`_.

Visibility information is represented by a comma-separated list of tuples in 
the annotation:

``<{Traffic Direction}/{L4 Port}/{L4 Protocol}/{L7 Protocol}>``

For example:

.. code:: bash

  <Ingress/53/UDP/DNS>,<Egress/80/TCP/HTTP>


To do this, you can provide the annotation in your Kubernetes YAMLs, or via the
command line, e.g.:

.. code:: bash

    kubectl annotate pod foo -n bar io.cilium.proxy-visibility="<Ingress/53/UDP/DNS>,<Egress/80/TCP/HTTP>"

Cilium will pick up that pods have received these annotations, and will 
transparently redirect traffic to the proxy such that the output of 
``cilium monitor`` shows traffic being redirected to the proxy, e.g.:

.. code:: bash

    -> Request http from 1474 ([k8s:id=app2 k8s:io.kubernetes.pod.namespace=default k8s:appSecond=true k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=app2-account k8s:zgroup=testapp]) to 244 ([k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=app1-account k8s:io.kubernetes.pod.namespace=default k8s:zgroup=testapp k8s:id=app1]), identity 30162->42462, verdict Forwarded GET http://app1-service/ => 0
    -> Response http to 1474 ([k8s:zgroup=testapp k8s:id=app2 k8s:io.kubernetes.pod.namespace=default k8s:appSecond=true k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=app2-account]) from 244 ([k8s:io.cilium.k8s.policy.serviceaccount=app1-account k8s:io.kubernetes.pod.namespace=default k8s:zgroup=testapp k8s:id=app1 k8s:io.cilium.k8s.policy.cluster=default]), identity 30162->42462, verdict Forwarded GET http://app1-service/ => 200

Limitations
-----------

* Visibility annotations do not apply if rules are imported which select the pod
  which is annotated.
* Proxylib parsers are not supported.
