Cluster Mesh Troubleshooting
============================


Install the Cilium CLI
----------------------

.. include:: ../gettingstarted/cli-download.rst

Generic
-------

 #. Validate that the ``cilium-xxx`` as well as the ``cilium-operator-xxx`` pods
    are healthy and ready.

    .. code-block:: shell-session

       cilium status

 #. Validate the Cluster Mesh is enabled correctly and operational:

    .. code-block:: shell-session

       cilium clustermesh status


Manual Verification of Setup
----------------------------

 #. Validate that the ClusterMesh subsystem is initialized by looking for a
    ``cilium-agent`` log message like this::

       level=info msg="Initializing ClusterMesh routing" path=/var/lib/cilium/clustermesh/ subsys=daemon

 #. Validate that the configuration for remote clusters is picked up correctly.
    For each remote cluster, an info log message ``New remote cluster
    configuration`` along with the remote cluster name must be logged in the
    ``cilium-agent`` logs.

    If the configuration is not found, check the following:

    * The Kubernetes secret ``clustermesh-secrets`` is imported correctly.

    * The secret contains a file for each remote cluster with the filename
      matching the name of the remote cluster.

    * The contents of the file in the secret is a valid etcd configuration
      consisting of the IP to reach the remote etcd as well as the required
      certificates to connect to that etcd.

    * Run a ``kubectl exec -ti [...] -- bash`` in one of the Cilium pods and check
      the contents of the directory ``/var/lib/cilium/clustermesh/``. It must
      contain a configuration file for each remote cluster along with all the
      required SSL certificates and keys. The filenames must match the cluster
      names as provided by the ``--cluster-name`` argument or ``cluster-name``
      ConfigMap option. If the directory is empty or incomplete, regenerate the
      secret again and ensure that the secret is correctly mounted into the
      DaemonSet.

 #. Validate that the connection to the remote cluster could be established.
    You will see a log message like this in the ``cilium-agent`` logs for each
    remote cluster::

       level=info msg="Connection to remote cluster established"

    If the connection failed, you will see a warning like this::

       level=warning msg="Unable to establish etcd connection to remote cluster"

    If the connection fails, check the following:

    * Validate that the ``hostAliases`` section in the Cilium DaemonSet maps
      each remote cluster to the IP of the LoadBalancer that makes the remote
      control plane available.

    * Validate that a local node in the source cluster can reach the IP
      specified in the ``hostAliases`` section. The ``clustermesh-secrets``
      secret contains a configuration file for each remote cluster, it will
      point to a logical name representing the remote cluster:

      .. code-block:: yaml

         endpoints:
         - https://cluster1.mesh.cilium.io:2379

      The name will *NOT* be resolvable via DNS outside of the cilium pod. The
      name is mapped to an IP using ``hostAliases``. Run ``kubectl -n
      kube-system get ds cilium -o yaml`` and grep for the FQDN to retrieve the
      IP that is configured. Then use ``curl`` to validate that the port is
      reachable.

    * A firewall between the local cluster and the remote cluster may drop the
      control plane connection. Ensure that port 2379/TCP is allowed.

State Propagation
-----------------

 #. Run ``cilium node list`` in one of the Cilium pods and validate that it
    lists both local nodes and nodes from remote clusters. If this discovery
    does not work, validate the following:

    * In each cluster, check that the kvstore contains information about
      *local* nodes by running:

      .. code-block:: shell-session

          cilium kvstore get --recursive cilium/state/nodes/v1/

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

 #. Validate that identities are synchronized correctly by running ``cilium
    identity list`` in one of the Cilium pods. It must list identities from all
    clusters. You can determine what cluster an identity belongs to by looking
    at the label ``io.cilium.k8s.policy.cluster``.

    If this fails:

    * Is the identity information available in the kvstore of each cluster? You
      can confirm this by running ``cilium kvstore get --recursive
      cilium/state/identities/v1/``.

      .. note::

         The kvstore will only contain identities of the **local cluster**. It
         will **not** contain identities of remote clusters. The state in the
         kvstore is used for other clusters to discover all identities so it is
         important that local identities are listed.

 #. Validate that the IP cache is synchronized correctly by running ``cilium
    bpf ipcache list`` or ``cilium map get cilium_ipcache``. The output must
    contain pod IPs from local and remote clusters.

    If this fails:

    * Is the IP cache information available in the kvstore of each cluster? You
      can confirm this by running ``cilium kvstore get --recursive
      cilium/state/ip/v1/``.

      .. note::

         The kvstore will only contain IPs of the **local cluster**. It will
         **not** contain IPs of remote clusters. The state in the kvstore is
         used for other clusters to discover all pod IPs so it is important
         that local identities are listed.

 #. When using global services, ensure that global services are configured with
    endpoints from all clusters. Run ``cilium service list`` in any Cilium pod
    and validate that the backend IPs consist of pod IPs from all clusters
    running relevant backends. You can further validate the correct datapath
    plumbing by running ``cilium bpf lb list`` to inspect the state of the eBPF
    maps.

    If this fails:

    * Are services available in the kvstore of each cluster? You can confirm
      this by running ``cilium kvstore get --recursive
      cilium/state/services/v1/``.

    * Run ``cilium debuginfo`` and look for the section ``k8s-service-cache``. In
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
