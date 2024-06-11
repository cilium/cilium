Cluster Mesh Troubleshooting
============================


Install the Cilium CLI
----------------------

.. include:: /installation/cli-download.rst

Automatic Verification
----------------------

 #. Validate that Cilium pods are healthy and ready:

    .. code-block:: shell-session

       cilium status

 #. Validate that Cluster Mesh is enabled and operational:

    .. code-block:: shell-session

       cilium clustermesh status

 #. In case of errors, run the troubleshoot command to automatically investigate
    Cilium agents connectivity issues towards the ClusterMesh control plane in
    remote clusters:

    .. code-block:: shell-session

       kubectl exec -it -n kube-system ds/cilium -c cilium-agent -- cilium-dbg troubleshoot clustermesh

    The troubleshoot command performs a set of automatic checks to validate
    DNS resolution, network connectivity, TLS authentication, etcd authorization
    and more, and reports the output in a user friendly format.

    When KVStoreMesh is enabled, the output of the troubleshoot command refers
    to the connections from the agents to the local cache, and it is expected to
    be the same for all the clusters they are connected to. Run the troubleshoot
    command inside the clustermesh-apiserver to investigate KVStoreMesh connectivity
    issues towards the ClusterMesh control plane in remote clusters:

    .. code-block:: shell-session

      kubectl exec -it -n kube-system deploy/clustermesh-apiserver -c kvstoremesh -- \
        clustermesh-apiserver kvstoremesh-dbg troubleshoot

    .. tip::

      You can specify one or more cluster names as parameters of the troubleshoot
      command to run the checks only towards a subset of remote clusters.


Manual Verification
-------------------

As an alternative to leveraging the tools presented in the previous section,
you may perform the following steps to troubleshoot ClusterMesh issues.

 #. Validate that each cluster is assigned a **unique** human-readable name as well
    as a numeric cluster ID (1-255).

 #. Validate that the clustermesh-apiserver is initialized correctly for each cluster:

    .. code-block:: shell-session

        $ kubectl logs -n kube-system deployment/clustermesh-apiserver -c apiserver
        ...
        level=info msg="Connecting to etcd server..." config=/var/lib/cilium/etcd-config.yaml endpoints="[https://127.0.0.1:2379]" subsys=kvstore
        level=info msg="Got lock lease ID 7c0281854b945c07" subsys=kvstore
        level=info msg="Initial etcd session established" config=/var/lib/cilium/etcd-config.yaml endpoints="[https://127.0.0.1:2379]" subsys=kvstore
        level=info msg="Successfully verified version of etcd endpoint" config=/var/lib/cilium/etcd-config.yaml endpoints="[https://127.0.0.1:2379]" etcdEndpoint="https://127.0.0.1:2379" subsys=kvstore version=3.4.13

 #. Validate that ClusterMesh is healthy running ``cilium-dbg status --all-clusters`` inside each Cilium agent::

        ClusterMesh:   1/1 remote clusters ready, 10 global-services
           k8s-c2: ready, 3 nodes, 25 endpoints, 8 identities, 10 services, 0 reconnections (last: never)
           └  etcd: 1/1 connected, leases=0, lock lease-ID=7c028201b53de662, has-quorum=true: https://k8s-c2.mesh.cilium.io:2379 - 3.5.4 (Leader)
           └  remote configuration: expected=true, retrieved=true, cluster-id=3, kvstoremesh=false, sync-canaries=true
           └  synchronization status: nodes=true, endpoints=true, identities=true, services=true

    When KVStoreMesh is enabled, additionally check its status and validate that
    it is correctly connected to all remote clusters:

    .. code-block:: shell-session

      $ kubectl --context $CLUSTER1 exec -it -n kube-system deploy/clustermesh-apiserver \
          -c kvstoremesh -- clustermesh-apiserver kvstoremesh-dbg status --verbose

 #. Validate that the required TLS secrets are set up properly. By default, the
    following TLS secrets must be available in the namespace in which Cilium is
    installed:

    * ``clustermesh-apiserver-server-cert``, which is used by the etcd container
      in the clustermesh-apiserver deployment. Not applicable if an external etcd
      cluster is used.

    * ``clustermesh-apiserver-admin-cert``, which is used by the apiserver/kvstoremesh
      containers in the clustermesh-apiserver deployment, to authenticate against the
      sidecar etcd instance. Not applicable if an external etcd cluster is used.

    * ``clustermesh-apiserver-remote-cert``, which is used by Cilium agents, or
      the kvstoremesh container in the clustermesh-apiserver deployment when
      KVStoreMesh is enabled, to authenticate against remote etcd instances.

    * ``clustermesh-apiserver-local-cert``, which is used by Cilium agents to
      authenticate against the local etcd instance. Only applicable if KVStoreMesh
      is enabled.

 #. Validate that the configuration for remote clusters is picked up correctly.
    For each remote cluster, an info log message ``New remote cluster
    configuration`` along with the remote cluster name must be logged in the
    ``cilium-agent`` logs.

    If the configuration is not found, check the following:

    * The ``cilium-clustermesh`` Kubernetes secret is present and correctly
      mounted by the Cilium agent pods.

    * The secret contains a file for each remote cluster with the filename matching
      the name of the remote cluster as provided by the ``--cluster-name`` argument
      or the ``cluster-name`` ConfigMap option.

    * Each file named after a remote cluster contains a valid etcd configuration
      consisting of the endpoints to reach the remote etcd cluster, and the path
      of the certificate and private key to authenticate against that etcd cluster.
      Additional files may be included in the secret to provide the certificate
      and private key themselves.

    * The ``/var/lib/cilium/clustermesh`` directory inside any of the Cilium agent
      pods contains the files mounted from the ``cilium-clustermesh`` secret.
      You can use
      ``kubectl exec -ti -n kube-system ds/cilium -c cilium-agent -- ls /var/lib/cilium/clustermesh``
      to list the files present.

 #. Validate that the connection to the remote cluster could be established.
    You will see a log message like this in the ``cilium-agent`` logs for each
    remote cluster::

       level=info msg="Connection to remote cluster established"

    If the connection failed, you will see a warning like this::

       level=warning msg="Unable to establish etcd connection to remote cluster"

    If the connection fails, check the following:

    * When KVStoreMesh is disabled, validate that the ``hostAliases`` section in the Cilium DaemonSet maps
      each remote cluster to the IP of the LoadBalancer that makes the remote
      control plane available; When KVStoreMesh is enabled,
      validate the ``hostAliases`` section in the clustermesh-apiserver Deployment.

    * Validate that a local node in the source cluster can reach the IP
      specified in the ``hostAliases`` section. When KVStoreMesh is disabled, the ``cilium-clustermesh``
      secret contains a configuration file for each remote cluster, it will
      point to a logical name representing the remote cluster;
      When KVStoreMesh is enabled, it exists in the ``cilium-kvstoremesh`` secret.

      .. code-block:: yaml

         endpoints:
         - https://cluster1.mesh.cilium.io:2379

      The name will *NOT* be resolvable via DNS outside the Cilium agent pods.
      The name is mapped to an IP using ``hostAliases``. Run ``kubectl -n
      kube-system get daemonset cilium -o yaml`` when KVStoreMesh is disabled,
      or run ``kubectl -n kube-system get deployment clustermesh-apiserver -o yaml`` when KVStoreMesh is enabled,
      grep for the FQDN to retrieve the IP that is configured. Then use ``curl`` to validate that the port is
      reachable.

    * A firewall between the local cluster and the remote cluster may drop the
      control plane connection. Ensure that port 2379/TCP is allowed.

State Propagation
-----------------

 #. Run ``cilium-dbg node list`` in one of the Cilium pods and validate that it
    lists both local nodes and nodes from remote clusters. If remote nodes are
    not present, validate that Cilium agents (or KVStoreMesh, if enabled)
    are correctly connected to the given remote cluster. Additionally, verify
    that the initial nodes synchronization from all clusters has completed.

 #. Validate the connectivity health matrix across clusters by running
    ``cilium-health status`` inside any Cilium pod. It will list the status of
    the connectivity health check to each remote node. If this fails, make sure
    that the network allows the health checking traffic as specified in the
    :ref:`firewall_requirements` section.

 #. Validate that identities are synchronized correctly by running ``cilium-dbg
    identity list`` in one of the Cilium pods. It must list identities from all
    clusters. You can determine what cluster an identity belongs to by looking
    at the label ``io.cilium.k8s.policy.cluster``. If remote identities are
    not present, validate that Cilium agents (or KVStoreMesh, if enabled)
    are correctly connected to the given remote cluster. Additionally, verify
    that the initial identities synchronization from all clusters has completed.

 #. Validate that the IP cache is synchronized correctly by running ``cilium-dbg
    bpf ipcache list`` or ``cilium-dbg map get cilium_ipcache``. The output must
    contain pod IPs from local and remote clusters. If remote IP addresses are
    not present, validate that Cilium agents (or KVStoreMesh, if enabled)
    are correctly connected to the given remote cluster. Additionally, verify
    that the initial IPs synchronization from all clusters has completed.

 #. When using global services, ensure that global services are configured with
    endpoints from all clusters. Run ``cilium-dbg service list`` in any Cilium pod
    and validate that the backend IPs consist of pod IPs from all clusters
    running relevant backends. You can further validate the correct datapath
    plumbing by running ``cilium-dbg bpf lb list`` to inspect the state of the eBPF
    maps.

    If this fails:

    * Run ``cilium-dbg debuginfo`` and look for the section ``k8s-service-cache``. In
      that section, you will find the contents of the service correlation
      cache. It will list the Kubernetes services and endpoints of the local
      cluster.  It will also have a section ``externalEndpoints`` which must
      list all endpoints of remote clusters.

      ::

          #### k8s-service-cache

          (*k8s.ServiceCache)(0xc00000c500)({
          [...]
           services: (map[k8s.ServiceID]*k8s.Service) (len=2) {
             (k8s.ServiceID) default/kubernetes: (*k8s.Service)(0xc000cd11d0)(frontend:172.20.0.1/ports=[https]/selector=map[]),
             (k8s.ServiceID) kube-system/kube-dns: (*k8s.Service)(0xc000cd1220)(frontend:172.20.0.10/ports=[metrics dns dns-tcp]/selector=map[k8s-app:kube-dns])
           },
           endpoints: (map[k8s.ServiceID]*k8s.Endpoints) (len=2) {
             (k8s.ServiceID) kube-system/kube-dns: (*k8s.Endpoints)(0xc0000103c0)(10.16.127.105:53/TCP,10.16.127.105:53/UDP,10.16.127.105:9153/TCP),
             (k8s.ServiceID) default/kubernetes: (*k8s.Endpoints)(0xc0000103f8)(192.168.60.11:6443/TCP)
           },
           externalEndpoints: (map[k8s.ServiceID]k8s.externalEndpoints) {
           }
          })

      The sections ``services`` and ``endpoints`` represent the services of the
      local cluster, the section ``externalEndpoints`` lists all remote
      services and will be correlated with services matching the same
      ``ServiceID``.
