.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_microk8s:

******************************
Getting Started Using MicroK8s
******************************

This guide uses `microk8s <https://microk8s.io/>`_ to demonstrate deployment
and operation of Cilium in a single-node Kubernetes cluster. To run Cilium
inside microk8s, a GNU/Linux distribution with kernel 4.9 or later is
required (per the :ref:`admin_system_reqs`).

Install microk8s
================

#. Install ``microk8s`` >= 1.15 as per microk8s documentation: `MicroK8s User
   guide <https://microk8s.io/docs/>`_.

#. Enable the microk8s Cilium service

   .. code-block:: shell-session

      microk8s enable cilium

#. Cilium is now configured! The ``cilium`` CLI is provided as ``microk8s.cilium``.

Next steps
==========

Now that you have a Kubernetes cluster with Cilium up and running, you can take
a couple of next steps to explore various capabilities:

* :ref:`gs_http`
* :ref:`gs_dns`
* :ref:`gs_cassandra`
* :ref:`gs_kafka`
