.. _clustermesh:

.. _gs_clustermesh:

***********************
Setting up Cluster Mesh
***********************

This is a step-by-step guide on how to build a mesh of Kubernetes clusters by
connecting them together, enabling pod-to-pod connectivity across all clusters,
define global services to load-balance between clusters and enforce security
policies to restrict access.

Prerequisites
#############

* PodCIDR ranges in all clusters must be non-conflicting.

* This guide and the referenced scripts assume that Cilium was installed using
  the :ref:`k8s_install_etcd_operator` instructions which leads to etcd being
  managed by Cilium using etcd-operator. You can use any way to manage etcd but
  you will have to adjust some of the scripts to account for different secret
  names and adjust the LoadBalancer to expose the etcd pods.

* Nodes in all clusters must have IP connectivity between each other. This
  requirement is typically met by establishing peering or VPN tunnels between
  the networks of the nodes of each cluster.

* All nodes must have a unique IP address assigned them. Node IPs of clusters
  being connected together may not conflict with each other.

* Cilium must be configured to use etcd as the kvstore, along with the identity
  allocation mode (``identityAllocationMode``). With the identity
  allocation mode set to ``kvstore``, this allows direct etcd connections,
  identity propagation across the clusters, and enables cross-cluster policy
  functionality. Consul is not currently supported with cluster mesh.

* It is highly recommended to use a TLS protected etcd cluster with Cilium. The
  server certificate of etcd must whitelist the host name ``*.mesh.cilium.io``.
  If you are using the ``cilium-etcd-operator`` as set up in the
  :ref:`k8s_install_etcd_operator` instructions then this is automatically
  taken care of.

* The network between clusters must allow the inter-cluster communication. The
  exact ports are documented in the :ref:`firewall_requirements` section.


Prepare the clusters
####################

Specify the cluster name and ID
===============================

Each cluster must be assigned a unique human-readable name. The name will be
used to group nodes of a cluster together. The cluster name is specified with
the ``--cluster-name=NAME`` argument or ``cluster-name`` ConfigMap option.

To ensure scalability of identity allocation and policy enforcement, each
cluster continues to manage its own security identity allocation. In order to
guarantee compatibility with identities across clusters, each cluster is
configured with a unique cluster ID configured with the ``--cluster-id=ID``
argument or ``cluster-id`` ConfigMap option. The value must be between 1 and
255.

.. code:: bash

   kubectl -n kube-system edit cm cilium-config
   [ ... add/edit ... ]
   cluster-name: cluster1
   cluster-id: "1"

Repeat this step for each cluster.

.. note::

   This can also be done by passing ``--set cluster.id=<id>`` and
   ``--set cluster.name=<name>`` to ``helm install`` when installing or
   updating Cilium.

.. _gs_clustermesh_expose_etcd:

Expose the Cilium etcd to other clusters
========================================

The Cilium etcd must be exposed to other clusters. There are many ways to
achieve this. The method documented in this guide will work with cloud
providers that implement the Kubernetes ``LoadBalancer`` service type, as well
as with services of type ``NodePort`` (assuming that nodes can reach each other
using their internal IPs):

.. tabs::
  .. group-tab:: GCP

    .. parsed-literal::

      apiVersion: v1
      kind: Service
      metadata:
        name: cilium-etcd-external
        annotations:
          cloud.google.com/load-balancer-type: "Internal"
          # if all the clusters are in the same region you can comment out this annotation
          networking.gke.io/internal-load-balancer-allow-global-access: "true"
      spec:
        type: LoadBalancer
        ports:
        - port: 2379
        selector:
          app: etcd
          etcd_cluster: cilium-etcd
          io.cilium/app: etcd-operator

  .. group-tab:: AWS

    .. parsed-literal::

      apiVersion: v1
      kind: Service
      metadata:
        name: cilium-etcd-external
        annotations:
          service.beta.kubernetes.io/aws-load-balancer-internal: 0.0.0.0/0
      spec:
        type: LoadBalancer
        ports:
        - port: 2379
        selector:
          app: etcd
          etcd_cluster: cilium-etcd
          io.cilium/app: etcd-operator

  .. group-tab:: NodePort

    .. parsed-literal::

      apiVersion: v1
      kind: Service
      metadata:
        name: cilium-etcd-external
      spec:
        type: NodePort
        ports:
        - port: 2379
        selector:
          app: etcd
          etcd_cluster: cilium-etcd
          io.cilium/app: etcd-operator

The example used here exposes the etcd cluster as managed by
``cilium-etcd-operator`` installed by the standard installation instructions as
an internal service which means that it is only exposed inside of a VPC and not
publicly accessible outside of the VPC. It is recommended to use a static IP
for the ServiceIP to avoid requiring to update the IP mapping as done in one of
the later steps.

If you are running the cilium-etcd-operator you can simply apply the following
service to expose etcd:

.. tabs::
  .. group-tab:: GCP

    .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/cilium-etcd-external-service/cilium-etcd-external-gke.yaml

  .. group-tab:: AWS

    .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/cilium-etcd-external-service/cilium-etcd-external-eks.yaml

  .. group-tab:: NodePort

    .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/cilium-etcd-external-service/cilium-etcd-external-nodeport.yaml


.. note::

   Make sure that you create the service in namespace in which cilium and/or
   etcd is running. Depending on which installation method you chose, this
   could be ``kube-system`` or ``cilium``.

Extract the TLS keys and generate the etcd configuration
========================================================

The cluster mesh control plane performs TLS based authentication and encryption.
For this purpose, the TLS keys and certificates of each etcd need to be made
available to all clusters that wish to connect.

1. Clone the ``cilium/clustermesh-tools`` repository. It contains scripts to
   extracts the secrets and generate a Kubernetes secret in form of a YAML
   file:

   .. code:: bash

      git clone https://github.com/cilium/clustermesh-tools.git
      cd clustermesh-tools

2. Ensure that the kubectl context is pointing to the cluster you want to
   extract the secret from.

3. Extract the TLS certificate, key and root CA authority.

   .. code:: bash

      ./extract-etcd-secrets.sh

   This will extract the keys that Cilium is using to connect to the etcd in
   the local cluster. The key files are written to
   ``config/<cluster-name>.*.{key|crt|-ca.crt}``

4. Repeat this step for all clusters you want to connect with each other.

5. Generate a single Kubernetes secret from all the keys and certificates
   extracted. The secret will contain the etcd configuration with the service
   IP or host name of the etcd including the keys and certificates to access
   it.

   .. code:: bash

      ./generate-secret-yaml.sh > clustermesh.yaml

.. note::

   The key files in ``config/`` and the secret represented as YAML are
   sensitive. Anyone gaining access to these files is able to connect to the
   etcd instances in the local cluster. Delete the files after the you are done
   setting up the cluster mesh.

Ensure that the etcd service names can be resolved
==================================================

For TLS authentication to work properly, agents will connect to etcd in remote
clusters using a pre-defined naming schema ``{clustername}.mesh.cilium.io``. In
order for DNS resolution to work on these virtual host name, the names are
statically mapped to the service IP via the ``/etc/hosts`` file.

1. The following script will generate the required segment which has to be
   inserted into the ``cilium`` DaemonSet:

    .. code:: bash

       ./generate-name-mapping.sh > ds.patch

    The ``ds.patch`` will look something like this:

    .. code:: bash

        spec:
          template:
            spec:
              hostAliases:
              - ip: "10.138.0.18"
                hostnames:
                - cluster1.mesh.cilium.io
              - ip: "10.138.0.19"
                hostnames:
                - cluster2.mesh.cilium.io

2. Apply the patch to all DaemonSets in all clusters:

   .. code:: bash

      kubectl -n kube-system patch ds cilium -p "$(cat ds.patch)"

Establish connections between clusters
######################################

1. Import the ``cilium-clustermesh`` secret that you generated in the last
chapter into all of your clusters:

.. code:: bash

    kubectl -n kube-system apply -f clustermesh.yaml

2. Restart the cilium-agent in all clusters so it picks up the new cluster
   name, cluster id and mounts the ``cilium-clustermesh`` secret. Cilium will
   automatically establish connectivity between the clusters.

.. code:: bash

    kubectl -n kube-system delete pod -l k8s-app=cilium

3. For global services to work (see below), also restart the cilium-operator:

.. code:: bash

    kubectl -n kube-system delete pod -l name=cilium-operator

Test pod connectivity between clusters
======================================


Run ``cilium node list`` to see the full list of nodes discovered. You can run
this command inside any Cilium pod in any cluster:

.. code:: bash

    $ kubectl -n kube-system exec -ti cilium-g6btl -- cilium node list
    Name                                                   IPv4 Address    Endpoint CIDR   IPv6 Address   Endpoint CIDR
    cluster5/ip-172-0-117-60.us-west-2.compute.internal    172.0.117.60    10.2.2.0/24     <nil>          f00d::a02:200:0:0/112
    cluster5/ip-172-0-186-231.us-west-2.compute.internal   172.0.186.231   10.2.3.0/24     <nil>          f00d::a02:300:0:0/112
    cluster5/ip-172-0-50-227.us-west-2.compute.internal    172.0.50.227    10.2.0.0/24     <nil>          f00d::a02:0:0:0/112
    cluster5/ip-172-0-51-175.us-west-2.compute.internal    172.0.51.175    10.2.1.0/24     <nil>          f00d::a02:100:0:0/112
    cluster7/ip-172-0-121-242.us-west-2.compute.internal   172.0.121.242   10.4.2.0/24     <nil>          f00d::a04:200:0:0/112
    cluster7/ip-172-0-58-194.us-west-2.compute.internal    172.0.58.194    10.4.1.0/24     <nil>          f00d::a04:100:0:0/112
    cluster7/ip-172-0-60-118.us-west-2.compute.internal    172.0.60.118    10.4.0.0/24     <nil>          f00d::a04:0:0:0/112


.. code:: bash

    $ kubectl exec -ti pod-cluster5-xxx -- curl <pod-ip-cluster7>
    [...]

Load-balancing with Global Services
###################################

Establishing load-balancing between clusters is achieved by defining a
Kubernetes service with identical name and namespace in each cluster and adding
the annotation ``io.cilium/global-service: "true"``` to declare it global.
Cilium will automatically perform load-balancing to pods in both clusters.

.. code-block:: yaml

   apiVersion: v1
   kind: Service
   metadata:
     name: rebel-base
     annotations:
       io.cilium/global-service: "true"
   spec:
     type: ClusterIP
     ports:
     - port: 80
     selector:
       name: rebel-base

Load-balancing only to a remote cluster
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


Deploying a simple example service
==================================

1. In cluster 1, deploy:

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/global-service-example/cluster1.yaml

2. In cluster 2, deploy:

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/global-service-example/cluster2.yaml

3. From either cluster, access the global service:

   .. code:: bash

      kubectl exec -ti xwing-xxx -- curl rebel-base

   You will see replies from pods in both clusters.


Security Policies
#################

As addressing and network security is decoupled, network security enforcement
automatically spans across clusters. Note that Kubernetes security policies are
not automatically distributed across clusters, it is your responsibility to
apply ``CiliumNetworkPolicy`` or ``NetworkPolicy`` in all clusters.

Allowing specific communication between clusters
================================================

The following policy illustrates how to allow particular pods to allow
communicate between two clusters. The cluster name refers to the name given via
the ``--cluster-name`` agent option or ``cluster-name`` ConfigMap option.

.. code-block:: yaml

    apiVersion: "cilium.io/v2"
    kind: CiliumNetworkPolicy
    metadata:
      name: "allow-cross-cluster"
    spec:
      description: "Allow x-wing in cluster1 to contact rebel-base in cluster2"
      endpointSelector:
        matchLabels:
          name: x-wing
          io.cilium.k8s.policy.cluster: cluster1
      egress:
      - toEndpoints:
        - matchLabels:
            name: rebel-base
            io.cilium.k8s.policy.cluster: cluster2

Setting up Hubble
#################

In a ClusterMesh context, Hubble Relay provides cross-cluster visibility
without any particular configuration.

When mutual TLS (mTLS) is enabled (default), TLS certificates for Hubble and
Hubble Relay need to be signed by the same Certificate Authority (CA) for both
clusters. This can be achieved by disabling automatic TLS certificate
generation and manually providing certificates as instructed in
:ref:`hubble_configure_tls_certs`.

Troubleshooting
###############

Use the following list of steps to troubleshoot issues with ClusterMesh:

Generic
=======

 #. Validate that the ``cilium-xxx`` as well as the ``cilium-operator-xxx`` pods
    are healthy and ready. It is important that the ``cilium-operator`` is
    healthy as well as it is responsible for synchronizing state from the local
    cluster into the kvstore. If this fails, check the logs of these pods to
    track the reason for failure.

 #. Validate that the ClusterMesh subsystem is initialized by looking for a
    ``cilium-agent`` log message like this:

    .. code:: bash

       level=info msg="Initializing ClusterMesh routing" path=/var/lib/cilium/clustermesh/ subsys=daemon

Control Plane Connectivity
==========================

 #. Validate that the configuration for remote clusters is picked up correctly.
    For each remote cluster, an info log message ``New remote cluster
    configuration`` along with the remote cluster name must be logged in the
    ``cilium-agent`` logs.

    If the configuration is now found, check the following:

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
    remote cluster:

    .. code:: bash

       level=info msg="Connection to remote cluster established"

    If the connection failed, you will see a warning like this:

    .. code:: bash

       level=warning msg="Unable to establish etcd connection to remote cluster"

    If the connection fails, the cause can be one of the following:

    * Validate that the ``hostAliases`` section in the Cilium DaemonSet maps
      each remote cluster to the IP of the LoadBalancer that makes the remote
      control plane available.

    * Validate that a local node in the source cluster can reach the IP
      specified in the ``hostAliases`` section. The ``clustermesh-secrets``
      secret contains a configuration file for each remote cluster, it will
      point to a logical name representing the remote cluster:

      .. code:: yaml

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
=================

 #. Run ``cilium node list`` in one of the Cilium pods and validate that it
    lists both local nodes and nodes from remote clusters. If this discovery
    does not work, validate the following:

    * In each cluster, check that the kvstore contains information about
      *local* nodes by running:

      .. code:: bash

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

    * Run ``cilium debuginfo`` and look for the section "k8s-service-cache". In
      that section, you will find the contents of the service correlation
      cache.  it will list the Kubernetes services and endpoints of the local
      cluster.  It will also have a section ``externalEndpoints`` which must
      list all endpoints of remote clusters.

      .. code::

          #### k8s-service-cache

          (*k8s.ServiceCache)(0xc00000c500)({
          [...]
           services: (map[k8s.ServiceID]*k8s.Service) (len=2) {
             (k8s.ServiceID) default/kubernetes: (*k8s.Service)(0xc000cd11d0)(frontend:172.20.0.1/ports=[https]/selector=map[]),
             (k8s.ServiceID) kube-system/kube-dns: (*k8s.Service)(0xc000cd1220)(frontend:172.20.0.10/ports=[metrics dns dns-tcp]/selector=map[k8s-app:kube-dns])
           },
           endpoints: (map[k8s.ServiceID]*k8s.Endpoints) (len=2) {
             (k8s.ServiceID) kube-system/kube-dns: (*k8s.Endpoints)(0xc0000103c0)(10.16.127.105:53/TCP,10.16.127.105:53/UDP,10.16.127.105:9153/TCP),
             (k8s.ServiceID) default/kubernetes: (*k8s.Endpoints)(0xc0000103f8)(192.168.33.11:6443/TCP)
           },
           externalEndpoints: (map[k8s.ServiceID]k8s.externalEndpoints) {
           }
          })

      The sections ``services`` and ``endpoints`` represent the services of the
      local cluster, the section ``externalEndpoints`` lists all remote
      services and will be correlated with services matching the same
      ``ServiceID``.


Limitations
###########

 * L7 security policies currently only work across multiple clusters if worker
   nodes have routes installed allowing to route pod IPs of all clusters. This
   is given when running in direct routing mode by running a routing daemon or
   ``--auto-direct-node-routes`` but won't work automatically when using
   tunnel/encapsulation mode.

 * The number of clusters that can be connected together is currently limited
   to 255. This limitation will be lifted in the future when running in direct
   routing mode or when running in encapsulation mode with encryption enabled.

Roadmap Ahead
#############

 * Future versions will put an API server before etcd to provide better
   scalability and simplify the installation to support any etcd support

 * Introduction of IPsec and use of ESP or utilization of the traffic class
   field in the IPv6 header will allow to use more than 8 bits for the
   cluster-id and thus support more than 256 clusters.
