.. only:: not (epub or latex or html)
  
    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _proxy_visibility:

***************************
Layer 7 Protocol Visibility
***************************

While :ref:`monitor` provides introspection into datapath state, by default it
will only provide visibility into L3/L4 packet events. If :ref:`l7_policy` are
configured, one can get visibility into L7 protocols, but this requires the full
policy for each selected endpoint to be written. To get more visibility into the
application without configuring a full policy, Cilium provides a means of
prescribing visibility via `annotations <https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/>`_
when running in tandem with Kubernetes.

Visibility information is represented by a comma-separated list of tuples in
the annotation:

``<{Traffic Direction}/{L4 Port}/{L4 Protocol}/{L7 Protocol}>``

For example:

::

  <Egress/53/UDP/DNS>,<Egress/80/TCP/HTTP>


To do this, you can provide the annotation in your Kubernetes YAMLs, or via the
command line, e.g.:

.. code-block:: shell-session

    kubectl annotate pod foo -n bar policy.cilium.io/proxy-visibility="<Egress/53/UDP/DNS>,<Egress/80/TCP/HTTP>"

Cilium will pick up that pods have received these annotations, and will
transparently redirect traffic to the proxy such that the output of
``cilium monitor`` shows traffic being redirected to the proxy, e.g.:

::

    -> Request http from 1474 ([k8s:id=app2 k8s:io.kubernetes.pod.namespace=default k8s:appSecond=true k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=app2-account k8s:zgroup=testapp]) to 244 ([k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=app1-account k8s:io.kubernetes.pod.namespace=default k8s:zgroup=testapp k8s:id=app1]), identity 30162->42462, verdict Forwarded GET http://app1-service/ => 0
    -> Response http to 1474 ([k8s:zgroup=testapp k8s:id=app2 k8s:io.kubernetes.pod.namespace=default k8s:appSecond=true k8s:io.cilium.k8s.policy.cluster=default k8s:io.cilium.k8s.policy.serviceaccount=app2-account]) from 244 ([k8s:io.cilium.k8s.policy.serviceaccount=app1-account k8s:io.kubernetes.pod.namespace=default k8s:zgroup=testapp k8s:id=app1 k8s:io.cilium.k8s.policy.cluster=default]), identity 30162->42462, verdict Forwarded GET http://app1-service/ => 200

You can check the status of the visibility policy by checking the Cilium
endpoint of that pod, for example:

.. code-block:: shell-session

    $ kubectl get cep -n kube-system
    NAME                       ENDPOINT ID   IDENTITY ID   INGRESS ENFORCEMENT   EGRESS ENFORCEMENT   VISIBILITY POLICY   ENDPOINT STATE   IPV4           IPV6
    coredns-7d7f5b7685-wvzwb   1959          104           false                 false                                    ready            10.16.75.193   f00d::a10:0:0:2c77
    $
    $ kubectl annotate pod -n kube-system coredns-7d7f5b7685-wvzwb policy.cilium.io/proxy-visibility="<Egress/53/UDP/DNS>,<Egress/80/TCP/HTTP>" --overwrite
    pod/coredns-7d7f5b7685-wvzwb annotated
    $
    $ kubectl get cep -n kube-system
    NAME                       ENDPOINT ID   IDENTITY ID   INGRESS ENFORCEMENT   EGRESS ENFORCEMENT   VISIBILITY POLICY   ENDPOINT STATE   IPV4           IPV6
    coredns-7d7f5b7685-wvzwb   1959          104           false                 false                OK                  ready            10.16.75.193   f00d::a10:0:0:2c7

In order for Cilium to populate the ``INGRESS ENFORCEMENT``, ``EGRESS ENFORCEMENT``
and ``VISIBILITY POLICY`` fields, it must run with ``--endpoint-status=policy``
to make field values visible.

Troubleshooting
---------------

If L7 visibility is not appearing in ``cilium monitor`` or Hubble components,
it is worth double-checking that:

 * No enforcement policy is applied in the direction specified in the
   annotation
 * The "Visibility Policy" column in the CiliumEndpoint shows ``OK``. If it
   is blank, then no annotation is configured; if it shows an error then there
   is a problem with the visibility annotation.

The following example deliberately misconfigures the annotation to demonstrate
that the CiliumEndpoint for the pod presents an error when the visibility
annotation cannot be implemented:

.. code-block:: shell-session

    $ kubectl annotate pod -n kube-system coredns-7d7f5b7685-wvzwb policy.cilium.io/proxy-visibility="<Ingress/53/UDP/DNS>,<Egress/80/TCP/HTTP>"
    pod/coredns-7d7f5b7685-wvzwb annotated
    $
    $ kubectl get cep -n kube-system
    NAME                       ENDPOINT ID   IDENTITY ID   INGRESS ENFORCEMENT   EGRESS ENFORCEMENT   VISIBILITY POLICY                        ENDPOINT STATE   IPV4           IPV6
    coredns-7d7f5b7685-wvzwb   1959          104           false                 false                dns not allowed with direction Ingress   ready            10.16.75.193   f00d::a10:0:0:2c77

Limitations
-----------

* Visibility annotations do not apply if rules are imported which select the pod
  which is annotated.
* DNS visibility is available on egress only.
* Proxylib parsers are not supported, including Kafka. To gain visibility on
  these protocols, you must create a network policy that allows all of the
  traffic at L7, either by following :ref:`l7_policy`
  (:ref:`Kafka <kafka_policy>`) or the :ref:`envoy` proxylib extensions guide.
  This limitation is tracked by :gh-issue:`14072`.
