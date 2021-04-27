.. _gs_clustermesh_services:

**********************************
Load-balancing & Service Discovery
**********************************

This tutorial will guide you to perform load-balancing and service
discovery across multiple Kubernetes clusters when using Cilium.

Prerequisites
#############

You need to have a functioning Cluster Mesh setup, please follow the guide
:ref:`gs_clustermesh` to set it up.

Load-balancing with Global Services
###################################

Establishing load-balancing between clusters is achieved by defining a
Kubernetes service with identical name and namespace in each cluster and adding
the annotation ``io.cilium/global-service: "true"`` to declare it global.
Cilium will automatically perform load-balancing to pods in both clusters.

.. literalinclude:: ../../../examples/kubernetes/clustermesh/global-service-example/rebel-base-global-shared.yaml
  :language: YAML

Load-balancing Only to a Remote Cluster
#######################################

By default, a Global Service will load-balance across backends in multiple clusters.
This implicitly configures ``io.cilium/shared-service: "true"``. To prevent service
backends from being shared to other clusters, and to ensure that the service
will only load-balance to backends in remote clusters, this option should be
disabled.

Below example will expose remote endpoint without sharing local endpoints.

.. code-block:: yaml

   apiVersion: v1
   kind: Service
   metadata:
     name: rebel-base
     annotations:
       io.cilium/global-service: "true"
       io.cilium/shared-service: "false"
   spec:
     type: ClusterIP
     ports:
     - port: 80
     selector:
       name: rebel-base


Deploying a Simple Example Service
==================================

1. In cluster 1, deploy:

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/global-service-example/rebel-base-global-shared.yaml
       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/global-service-example/cluster1.yaml

2. In cluster 2, deploy:

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/global-service-example/rebel-base-global-shared.yaml
       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/global-service-example/cluster2.yaml

3. From either cluster, access the global service:

   .. code-block:: shell-session

      kubectl exec -ti xwing-xxx -- curl rebel-base

   You will see replies from pods in both clusters.
