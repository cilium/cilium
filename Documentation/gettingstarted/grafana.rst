.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _install_metrics:

****************************
Running Prometheus & Grafana
****************************

Installation
============

This is an example deployment that includes Prometheus and Grafana in a single
deployment.

The default installation contains:

- **Grafana**: A visualization dashboard with Cilium Dashboard pre-loaded.
- **Prometheus**: a time series database and monitoring system.


 .. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/addons/prometheus/monitoring-example.yaml
    configmap/cilium-metrics-config created
    namespace/cilium-monitoring created
    configmap/prometheus created
    deployment.extensions/prometheus created
    clusterrolebinding.rbac.authorization.k8s.io/prometheus created
    clusterrole.rbac.authorization.k8s.io/prometheus created
    serviceaccount/prometheus-k8s created
    service/prometheus created
    deployment.extensions/grafana created
    service/grafana created
    configmap/grafana-config created

How to enable metrics
=====================

Both ``cilium-agent`` and ``cilium-operator`` do not expose metrics by
default. Enabling metrics for these services will open ports ``9090``
and ``6942`` on all nodes of your cluster where these components are running.

To enable metrics for ``cilium-agent`` for the default installation, set the
``prometheus-serve-addr`` option as follows:

.. parsed-literal::
    $ kubectl patch -n kube-system configmap cilium-config --type merge --patch '{"data":{"prometheus-serve-addr":":9090"}}'
    configmap/cilium-config patched

As with any changes to the config map, you will have to restart any existing
Cilium pods in order for this change to take effect.

For ``cilium-operator``, append the ``--enable-metrics`` command-line
argument to the ``cilium-operator`` deployment:

.. parsed-literal::
    $ kubectl patch -n kube-system deployment cilium-operator --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--enable-metrics"}]'
    deployment.extensions/cilium-operator patched

How to access Grafana
=====================

Expose the port on your local machine

.. code:: bash

    kubectl -n cilium-monitoring port-forward service/grafana 3000:3000

Access it via your browser: ``https://localhost:3000``

How to access Prometheus
========================

Expose the port on your local machine

.. code:: bash

    kubectl -n cilium-monitoring port-forward service/prometheus 9090:9090

Access it via your browser: ``https://localhost:9090``

Examples
========

Generic
-------

.. image:: images/grafana_generic.png

Network
-------

.. image:: images/grafana_network.png

Policy
-------

.. image:: images/grafana_policy.png
.. image:: images/grafana_policy2.png

Endpoints
---------

.. image:: images/grafana_endpoints.png

Controllers
-----------

.. image:: images/grafana_controllers.png

Kubernetes
----------

.. image:: images/grafana_k8s.png

