.. _gs_clustermesh_service_affinity:

****************
Service Affinity
****************

This tutorial will guide you to enable service affinity across multiple
Kubernetes clusters.

Prerequisites
#############

You need to have a functioning Cluster Mesh with a Global Service, please
follow the guide :ref:`gs_clustermesh` and :ref:`gs_clustermesh_services`
to set it up.

Enabling Global Service Affinity
################################

Load-balancing across multiple clusters might not be ideal in some cases.
The annotation ``service.cilium.io/affinity: "local|remote|none"`` can be used
to specify the preferred endpoint destination.

For example, if the value of annotation ``service.cilium.io/affinity`` is local,
the Global Service will load-balance across healthy ``local`` backends, and only user
remote endpoints if and only if all of local backends are not available or unhealthy.

.. code-block:: yaml

   apiVersion: v1
   kind: Service
   metadata:
     name: rebel-base
     annotations:
        service.cilium.io/global: "true"
        # Possible values:
        # - local
        #    preferred endpoints from local cluster if available
        # - remote
        #    preferred endpoints from remote cluster if available
        # none (default)
        #    no preference. Default behavior if this annotation does not exist
        service.cilium.io/affinity: "local"
   spec:
     type: ClusterIP
     ports:
     - port: 80
     selector:
       name: rebel-base


1. In cluster 1, add ``service.cilium.io/affinity="local"`` to existing global service

   .. code-block:: shell-session

      kubectl annotate service rebel-base service.cilium.io/affinity=local --overwrite

2. From cluster 1, access the global service:

   .. code-block:: shell-session

      kubectl exec -ti deployment/x-wing -- curl rebel-base

   You will see replies from pods in ``cluster 1`` only.

3. From cluster 2, access the global service:

   .. code-block:: shell-session

      kubectl exec -ti deployment/x-wing -- curl rebel-base

   You will see replies from pods in both clusters as usual.

4. From cluster 1, check the service endpoints, the local endpoints are marked
   as preferred.

   .. code-block:: shell-session

      kubectl exec -n kube-system -ti ds/cilium -- cilium service list --clustermesh-affinity

      ID   Frontend            Service Type   Backend
      1    10.96.0.1:443       ClusterIP      1 => 172.18.0.3:6443 (active)
      2    10.96.0.10:53       ClusterIP      1 => 10.244.1.171:53 (active)
                                              2 => 10.244.2.206:53 (active)
      3    10.96.0.10:9153     ClusterIP      1 => 10.244.1.171:9153 (active)
                                              2 => 10.244.2.206:9153 (active)
      4    10.96.210.49:2379   ClusterIP      1 => 10.244.2.216:2379 (active)
      5    10.96.173.113:80    ClusterIP      1 => 10.244.2.136:80 (active)
                                              2 => 10.244.1.61:80 (active) (preferred)
                                              3 => 10.244.2.31:80 (active) (preferred)
                                              4 => 10.244.2.200:80 (active)

5. In cluster 1, change ``service.cilium.io/affinity`` value to ``remote`` for existing global service

   .. code-block:: shell-session

      kubectl annotate service rebel-base service.cilium.io/affinity=remote --overwrite

6. From cluster 1, access the global service:

   .. code-block:: shell-session

      kubectl exec -ti deployment/x-wing -- curl rebel-base

   This time, the replies are coming from pods in ``cluster 2`` only.

7. From cluster 1, check the service endpoints, now the remote endpoints are marked
   as preferred.

   .. code-block:: shell-session

      kubectl exec -n kube-system -ti ds/cilium -- cilium service list --clustermesh-affinity

      ID   Frontend            Service Type   Backend
      1    10.96.0.1:443       ClusterIP      1 => 172.18.0.3:6443 (active)
      2    10.96.0.10:53       ClusterIP      1 => 10.244.1.171:53 (active)
                                              2 => 10.244.2.206:53 (active)
      3    10.96.0.10:9153     ClusterIP      1 => 10.244.1.171:9153 (active)
                                              2 => 10.244.2.206:9153 (active)
      4    10.96.210.49:2379   ClusterIP      1 => 10.244.2.216:2379 (active)
      5    10.96.173.113:80    ClusterIP      1 => 10.244.2.136:80 (active) (preferred)
                                              2 => 10.244.1.61:80 (active)
                                              3 => 10.244.2.31:80 (active)
                                              4 => 10.244.2.200:80 (active) (preferred)

8. From cluster 2, access the global service:

   .. code-block:: shell-session

      kubectl exec -ti deployment/x-wing -- curl rebel-base

   You will see replies from pods in both clusters as usual.

9. In cluster 1, remove ``service.cilium.io/affinity`` annotation for existing global service

   .. code-block:: shell-session

      kubectl annotate service rebel-base service.cilium.io/affinity- --overwrite

10. From either cluster, access the global service:

    .. code-block:: shell-session

        kubectl exec -ti deployment/x-wing -- curl rebel-base

    You will see replies from pods in both clusters again.
