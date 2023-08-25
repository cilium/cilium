.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_envoy_custom_listener:

*******************
L7 Path Translation
*******************

This example replicates the Prometheus metrics listener which is
already available via the command line option ``--proxy-prometheus-port``.
So the point of this example is not to add new functionality, but to show
how a feature that previously required Cilium Agent code changes can be
implemented with the new Cilium Envoy Config CRD.

Apply Example CRD
=================

This example adds a new Envoy listener ``envoy-prometheus-metrics-listener``
on the standard Prometheus port (e.g. ``9090``) to each Cilium node, translating
the default Prometheus metrics path ``/metrics`` to Envoy's Prometheus metrics path
``/stats/prometheus``.

Apply this Cilium Envoy Config CRD:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-prometheus-metrics-listener.yaml

This version of the ``CiliumClusterwideEnvoyConfig`` CRD is Cluster-scoped,
(i.e., not namespaced), so the name needs to be unique in the cluster,
unless you want to replace a CRD with a new one.

.. include:: warning.rst

.. code-block:: shell-session

    $ kubectl logs -n kube-system ds/cilium | grep -E "level=(error|warning)"

Test the Listener Port
======================

Test that the new port is responding to the metrics requests:

.. code-block:: shell-session

    $ curl http://<node-IP>:9090/metrics

Where ``<node-IP>`` is the IP address of one of your k8s cluster nodes.

Clean-up
========

Remove the prometheus listener with:

.. parsed-literal::

    $ kubectl delete -f \ |SCM_WEB|\/examples/kubernetes/servicemesh/envoy/envoy-prometheus-metrics-listener.yaml
