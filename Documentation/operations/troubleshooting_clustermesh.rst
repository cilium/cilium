Cluster Mesh Troubleshooting
============================


Install the Cilium CLI
----------------------

.. include:: /installation/cli-download.rst

Generic
-------

 #. Validate that the ``cilium-xxx`` as well as the ``cilium-operator-xxx`` pods
    are healthy and ready.

    .. code-block:: shell-session

       cilium status

 #. Validate that Cluster Mesh is enabled correctly and operational:

    .. code-block:: shell-session

       cilium clustermesh status


Manual Verification of Setup
----------------------------

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

 #. Validate that ClusterMesh is healthy running ``cilium status --all-clusters`` inside each Cilium agent::

        ClusterMesh:   1/1 clusters ready, 10 global-services
           k8s-c2: ready, 3 nodes, 25 endpoints, 8 identities, 10 services, 0 failures (last: never)
           └  etcd: 1/1 connected, leases=0, lock lease-ID=7c028201b53de662, has-quorum=true: https://k8s-c2.mesh.cilium.io:2379 - 3.5.4 (Leader)
           └  remote configuration: expected=true, retrieved=true, cluster-id=3, kvstoremesh=false, sync-canaries=true
           └  synchronization status: nodes=true, endpoints=true, identities=true, services=true

 #. Validate that the required TLS secrets are set up properly. By default, the
    following TLS secrets must be available in the namespace in which Cilium is
    installed:

    * ``clustermesh-apiserver-server-cert``, which is used by the etcd container
      in the clustermesh-apiserver deployment. Not applicable if an external etcd
      cluster is used.

    * ``clustermesh-apiserver-admin-cert``, which is used by the apiserver/kvstoremesh
      containers in the clustermesh-apiserver deployment, to authenticate against the
      sidecar etcd instance. Not applicable if an external etcd cluster is used.

    * ``clustermesh-apiserver-remote-cert``, which is used by Cilium agents, and
      optionally the kvstoremesh container in the clustermesh-apiserver deployment,
      to authenticate against remote etcd instances (either internal or external).

    If any of the prior secrets is not configured correctly, there will be a potential
    error message like the following::

       level=warning msg="Error observed on etcd connection, reconnecting etcd" clusterName=eks-dev-1 config=/var/lib/cilium/clustermesh/eks-dev-1 error="not able to connect to any etcd endpoints" kvstoreErr="quorum check failed 12 times in a row: timeout while waiting for initial connection" kvstoreStatus="quorum check failed 12 times in a row: timeout while waiting for initial connection" subsys=clustermesh

    or::

        {"level":"warn","ts":"2022-06-08T14:06:29.198Z","caller":"clientv3/retry_interceptor.go:62","msg":"retrying of unary invoker failed","target":"passthrough:///https://eks-dev-1.mesh.cilium.io:2379","attempt":0,"error":"rpc error: code = DeadlineExceeded desc = latest balancer error: connection error: desc = \"transport: authentication handshake failed: remote error: tls: bad certificate\""}

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
      validate that the ``hostAliases`` section in the clustermesh-apiserver Deployment.

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
    lists both local nodes and nodes from remote clusters. If this discovery
    does not work, validate the following:

    * In each cluster, check that the kvstore contains information about
      *local* nodes by running:

      .. code-block:: shell-session

          cilium-dbg kvstore get --recursive cilium/state/nodes/v1/

      .. note::

         The kvstore will only contain nodes of the **local cluster**. It will
         **not** contain nodes of remote clusters. The state in the kvstore is
         used for other clusters to discover all nodes so it is important that
         local nodes are listed.

 #. Validate the connectivity health matrix across clusters by running
    ``cilium-health status`` inside any Cilium pod. It will list the status of
    the connectivity health check to each remote node.

    If this fails:

    * Make sure that the network allows the health checking traffic as
      specified in the section :ref:`firewall_requirements`.

 #. Validate that identities are synchronized correctly by running ``cilium-dbg
    identity list`` in one of the Cilium pods. It must list identities from all
    clusters. You can determine what cluster an identity belongs to by looking
    at the label ``io.cilium.k8s.policy.cluster``.

    If this fails:

    * Is the identity information available in the kvstore of each cluster? You
      can confirm this by running ``cilium-dbg kvstore get --recursive
      cilium/state/identities/v1/``.

      .. note::

         The kvstore will only contain identities of the **local cluster**. It
         will **not** contain identities of remote clusters. The state in the
         kvstore is used for other clusters to discover all identities so it is
         important that local identities are listed.

 #. Validate that the IP cache is synchronized correctly by running ``cilium-dbg
    bpf ipcache list`` or ``cilium-dbg map get cilium_ipcache``. The output must
    contain pod IPs from local and remote clusters.

    If this fails:

    * Is the IP cache information available in the kvstore of each cluster? You
      can confirm this by running ``cilium-dbg kvstore get --recursive
      cilium/state/ip/v1/``.

      .. note::

         The kvstore will only contain IPs of the **local cluster**. It will
         **not** contain IPs of remote clusters. The state in the kvstore is
         used for other clusters to discover all pod IPs so it is important
         that local identities are listed.

 #. When using global services, ensure that global services are configured with
    endpoints from all clusters. Run ``cilium-dbg service list`` in any Cilium pod
    and validate that the backend IPs consist of pod IPs from all clusters
    running relevant backends. You can further validate the correct datapath
    plumbing by running ``cilium-dbg bpf lb list`` to inspect the state of the eBPF
    maps.

    If this fails:

    * Are services available in the kvstore of each cluster? You can confirm
      this by running ``cilium-dbg kvstore get --recursive
      cilium/state/services/v1/``.

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
