.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

.. _gsg_ipam_crd_multi_pool:

*******************************************
CRD-Backed by Cilium Multi-Pool IPAM (Beta)
*******************************************

.. include:: ../../beta.rst

This is a quick tutorial walking through how to enable multi-pool IPAM backed by the
``CiliumPodIPPool`` CRD. The purpose of this tutorial is to show how components are configured and
resources interact with each other to enable users to automate or extend on their own.

For more details, see the section :ref:`ipam_crd_multi_pool`

Enable Multi-pool IPAM mode
===========================

#. Setup Cilium for Kubernetes using helm with the options:

   * ``--set ipam.mode=multi-pool``
   * ``--set tunnel=disabled``
   * ``--set autoDirectNodeRoutes=true``
   * ``--set ipv4NativeRoutingCIDR=10.0.0.0/8``
   * ``--set endpointRoutes.enabled=true``
   * ``--set kubeProxyReplacement=true``
   * ``--set bpf.masquerade=true``

   For more details on why each of these options are needed, please refer to
   :ref:`ipam_crd_multi_pool_limitations`.

#. Create the ``default`` pool for IPv4 addresses with the options:

   * ``--set ipam.operator.autoCreateCiliumPodIPPools.default.ipv4.cidrs='{10.10.0.0/16}'``
   * ``--set ipam.operator.autoCreateCiliumPodIPPools.default.ipv4.maskSize=27``

#. Deploy Cilium and Cilium-Operator. Cilium will automatically wait until the
   ``podCIDR`` is allocated for its node by Cilium Operator.

Validate installation
=====================

#. Validate that Cilium has started up correctly

   .. code-block:: shell-session

       $ cilium status --wait
           /¯¯\
        /¯¯\__/¯¯\    Cilium:             OK
        \__/¯¯\__/    Operator:           OK
        /¯¯\__/¯¯\    Envoy DaemonSet:    disabled (using embedded mode)
        \__/¯¯\__/    Hubble Relay:       OK
           \__/       ClusterMesh:        disabled

       [...]

#. Validate that the ``CiliumPodIPPool`` resource for the ``default`` pool was created with the
   CIDRs specified in the ``ipam.operator.multiPoolMap.default.*`` Helm values:

   .. code-block:: shell-session

       $ kubectl get ciliumpodippool default -o yaml
       apiVersion: cilium.io/v2alpha1
       kind: CiliumPodIPPool
       metadata:
         name: default
       spec:
         ipv4:
           cidrs:
           - 10.10.0.0/16
           maskSize: 27

#. Create an additional pod IP pool ``mars`` using the following ``CiliumPodIPPool`` resource:

   .. code-block:: shell-session

       $ cat <<EOF | kubectl apply -f -
       apiVersion: cilium.io/v2alpha1
       kind: CiliumPodIPPool
       metadata:
         name: mars
       spec:
         ipv4:
           cidrs:
           - 10.20.0.0/16
           maskSize: 27
       EOF

#. Validate that both pool resources exist:

   .. code-block:: shell-session

       $ kubectl get ciliumpodippools
       NAME      AGE
       default   106s
       mars      7s

#. Create two deployments with two pods each. One allocating from the ``default`` pool and one
   allocating from the ``mars`` pool by way of the ``ipam.cilium.io/ipam-pool: mars`` annotation:

   .. code-block:: shell-session

       $ cat <<EOF | kubectl apply -f -
       apiVersion: apps/v1
       kind: Deployment
       metadata:
         name: nginx-default
       spec:
         selector:
           matchLabels:
             app: nginx-default
         replicas: 2
         template:
           metadata:
             labels:
               app: nginx-default
           spec:
             containers:
             - name: nginx
               image: nginx:1.25.1
               ports:
               - containerPort: 80
       ---
       apiVersion: apps/v1
       kind: Deployment
       metadata:
         name: nginx-mars
       spec:
         selector:
           matchLabels:
             app: nginx-mars
         replicas: 2
         template:
           metadata:
             labels:
               app: nginx-mars
             annotations:
               ipam.cilium.io/ip-pool: mars
           spec:
             containers:
             - name: nginx
               image: nginx:1.25.1
               ports:
               - containerPort: 80
       EOF

#. Validate that the pods were assigned IPv4 addresses from different CIDRs as specified in the pool
   definition:

   .. code-block:: shell-session

       $ kubectl get pods -o wide
       NAME                             READY   STATUS    RESTARTS   AGE    IP            NODE           NOMINATED NODE   READINESS GATES
       nginx-default-79885c7f58-fdfgf   1/1     Running   0          5s     10.10.10.36   kind-worker2   <none>           <none>
       nginx-default-79885c7f58-qch6b   1/1     Running   0          5s     10.10.10.77   kind-worker    <none>           <none>
       nginx-mars-76766f95f5-d9vzt      1/1     Running   0          5s     10.20.0.20    kind-worker2   <none>           <none>
       nginx-mars-76766f95f5-mtn2r      1/1     Running   0          5s     10.20.0.37    kind-worker    <none>           <none>

#. Test connectivity between pods:

   .. code-block:: shell-session

       $ kubectl exec pod/nginx-default-79885c7f58-fdfgf -- curl -s -o /dev/null -w "%{http_code}" http://10.20.0.37
       200

#. Alternatively, the ``ipam.cilium.io/ipam-pool`` annotation can also be applied to a namespace:

   .. code-block:: shell-session

       $ kubectl create namespace cilium-test
       $ kubectl annotate namespace cilium-test ipam.cilium.io/ip-pool=mars

   All new pods created in the namespace ``cilium-test`` will be assigned IPv4 addresses from the
   ``mars`` pool.  Run the Cilium connectivity tests (which use namespace ``cilium-test`` by default
   to create their workloads) to verify connectivity:

   .. code-block:: shell-session

       $ cilium connectivity test
       [...]
       ✅ All 42 tests (295 actions) successful, 13 tests skipped, 0 scenarios skipped.

  **Note:** The connectivity test requires a cluster with at least 2 worker nodes to complete successfully.

#. Verify that the connectivity test pods were assigned IPv4 addresses from the 10.20.0.0/16 CIDR
   defined in the ``mars`` pool:

   .. code-block:: shell-session

       $ kubectl --namespace cilium-test get pods -o wide
       NAME                                  READY   STATUS    RESTARTS   AGE     IP            NODE                 NOMINATED NODE   READINESS GATES
       client-6f6788d7cc-7fw9w               1/1     Running   0          8m56s   10.20.0.238   kind-worker          <none>           <none>
       client2-bc59f56d5-hsv2g               1/1     Running   0          8m56s   10.20.0.193   kind-worker          <none>           <none>
       echo-other-node-646976b7dd-5zlr4      2/2     Running   0          8m56s   10.20.1.145   kind-worker2         <none>           <none>
       echo-same-node-58f99d79f4-4k5v4       2/2     Running   0          8m56s   10.20.0.202   kind-worker          <none>           <none>
       ...
