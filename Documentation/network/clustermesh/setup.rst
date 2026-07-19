.. _clustermesh:
.. _gs_clustermesh:

***********************
Setting up Cluster Mesh
***********************

This is a step-by-step guide on how to build a mesh of Kubernetes clusters.
This guide shows you how to connect the clusters together, enable pod-to-pod
connectivity across all clusters, set up cross-cluster :ref:`service discovery
and load-balancing <gs_clustermesh_load_balancing>` and finally enforce security
policies to restrict access.

.. admonition:: Video
  :class: attention

  Aside from this step-by-step guide, if you would like to watch how Cilium's
  Clustermesh feature works, check out `eCHO Episode 41: Cilium Clustermesh <https://www.youtube.com/watch?v=VBOONHW65NU&t=342s>`__.

Prerequisites
#############

Cluster Addressing Requirements
===============================

* All clusters must be configured with the same datapath mode. Cilium install
  may default to :ref:`arch_overlay` or :ref:`native_routing` mode depending on
  the specific cloud environment.

* The Cilium versions of all clusters must differ by no more than one minor
  release. For example, Cilium ``1.18.x`` can connect to clusters running
  Cilium ``1.17.x`` or ``1.19.x``, but not ``1.16.x``.

* PodCIDR ranges in all clusters and all nodes must be non-conflicting and
  unique IP addresses.

* Nodes in all clusters must have IP connectivity between each other using the 
  configured InternalIP for each node. This requirement is typically met by establishing 
  peering or VPN tunnels between the networks of the nodes of each cluster.

* The network between clusters must allow the inter-cluster communication. The
  exact ports are documented in the :ref:`firewall_requirements` section.

.. note::

  For cloud-specific deployments, the following guides show how to meet the
  above requirements:

  .. toctree::
     :maxdepth: 1

     aks-clustermesh-prep
     eks-clustermesh-prep
     gke-clustermesh-prep

Additional Requirements for Native-routed Datapath Modes
--------------------------------------------------------

* Cilium in each cluster must be configured with a native routing CIDR that
  covers all the PodCIDR ranges across all connected clusters. Cluster CIDRs are
  typically allocated from the ``10.0.0.0/8`` private address space. When this
  is the case a native routing CIDR such as ``10.0.0.0/8`` should cover all
  clusters:

 * ConfigMap option ``ipv4-native-routing-cidr=10.0.0.0/8``
 * Helm option ``--set ipv4NativeRoutingCIDR=10.0.0.0/8``
 * ``cilium install`` option ``--set ipv4NativeRoutingCIDR=10.0.0.0/8``

* In addition to nodes, pods in all clusters must have IP connectivity between each other. This
  requirement is typically met by establishing peering or VPN tunnels between
  the networks of the nodes of each cluster

* The network between clusters must allow pod-to-pod inter-cluster communication
  across any ports that the pods may use. This is typically accomplished with
  firewall rules allowing pods in different clusters to reach each other on all
  ports.

Scaling Limitations
=============================

* By default, the maximum number of clusters that can be connected together using Cluster Mesh is
  255. By using the option ``maxConnectedClusters`` this limit can be set to 511, at the expense of
  lowering the maximum number of cluster-local identities. Reference the following table for valid
  configurations and their corresponding cluster-local identity limits:

+------------------------+------------+----------+----------+
| MaxConnectedClusters   | Maximum cluster-local identities |
+========================+============+==========+==========+
| 255 (default)          | 65535                            |
+------------------------+------------+----------+----------+
| 511                    | 32767                            |
+------------------------+------------+----------+----------+

* All clusters across a Cluster Mesh must be configured with the same ``maxConnectedClusters``
  value.

 * ConfigMap option ``max-connected-clusters=511``
 * Helm option ``--set clustermesh.maxConnectedClusters=511``
 * ``cilium install`` option ``--set clustermesh.maxConnectedClusters=511``

.. note::

   This option controls the bit allocation of numeric identities and will affect the maximum number
   of cluster-local identities that can be allocated. By default, cluster-local
   :ref:`security_identities` are limited to 65535, regardless of whether Cluster Mesh is used or
   not.

.. warning::
  ``MaxConnectedClusters`` can only be set once during Cilium installation and should not be
  changed for existing clusters. Changing this option on a live cluster may result in connection
  disruption and possible incorrect enforcement of network policies

Install the Cilium CLI
======================

.. include:: ../../installation/cli-download.rst

.. warning::

  Don't use the Cilium CLI *helm* mode to enable Cluster Mesh or connect clusters
  configured using the Cilium CLI operating in *classic* mode, as the two modes are
  not compatible with each other.

Prepare the Clusters
####################

For the rest of this tutorial, we will assume that you intend to connect two
clusters together with the kubectl configuration context stored in the
environment variables ``$CLUSTER1`` and ``$CLUSTER2``. This context name is the
same as you typically pass to ``kubectl --context``.

Specify the Cluster Name and ID
===============================

Cilium needs to be installed onto each cluster.

Each cluster must be assigned a unique human-readable name as well as a numeric
cluster ID (1-255). The cluster name must respect the following constraints:

* It must contain at most 32 characters;
* It must begin and end with a lower case alphanumeric character;
* It may contain lower case alphanumeric characters and dashes between.

It is best to assign both the cluster name and the cluster ID at installation time:

 * ConfigMap options ``cluster-name`` and ``cluster-id``
 * Helm options ``cluster.name`` and ``cluster.id``
 * Cilium CLI install options ``--set cluster.name`` and ``--set cluster.id``

Review :ref:`k8s_install_quick` for more details and use cases.

Example install using the Cilium CLI:

.. code-block:: shell-session

  cilium install --set cluster.name=$CLUSTER1 --set cluster.id=1 --context $CLUSTER1
  cilium install --set cluster.name=$CLUSTER2 --set cluster.id=2 --context $CLUSTER2

.. important::

   If you change the cluster ID and/or cluster name in a cluster with running
   workloads, you will need to restart all workloads. The cluster ID is used to
   generate the security identity and it will need to be re-created in order to
   establish access across clusters.

Configure TLS certificates
==========================

Cluster Mesh uses mTLS to secure control plane connections within and between
clusters. TLS certificates can be generated automatically or manually provided.

The following options are available to configure TLS certificates
automatically:

* cilium's `certgen <https://github.com/cilium/certgen>`__ (using a Kubernetes ``CronJob``)
* `cert-manager <https://cert-manager.io/>`__
* `Helm <https://helm.sh/docs/chart_template_guide/function_list/#gensignedcert>`__

Every cluster must trust the certificates presented by the other clusters. Use
a common root CA, or configure ``tls.caBundle`` with every trusted CA certificate.

.. tabs::

    .. group-tab:: CronJob (certgen)

        When using certgen, TLS certificates are generated at installation time
        and a Kubernetes ``CronJob`` is scheduled to renew them (regardless of
        their expiration date). The certgen method is easier to implement than
        cert-manager but less flexible.

        The following Helm values configure certgen:

        .. code-block:: yaml

          clustermesh:
            apiserver:
              tls:
                auto:
                  # enable automatic TLS certificate generation
                  enabled: true
                  # auto generate certificates using cronJob method
                  method: cronJob
                  # certificates validity duration in days (default 1 year)
                  certValidityDuration: 365
                  # schedule for certificate re-generation (crontab syntax)
                  schedule: "0 0 1 */4 *"

    .. group-tab:: cert-manager

        This method relies on `cert-manager <https://cert-manager.io/>`__ to generate
        the TLS certificates. cert-manager is the de facto way to manage TLS certificates
        on Kubernetes, and it has the following advantages compared to the other
        documented methods:

        * Support for multiple issuers (e.g. a custom CA,
          `Vault <https://www.vaultproject.io/>`__,
          `Let's Encrypt <https://letsencrypt.org/>`__,
          `Google's Certificate Authority Service <https://cloud.google.com/certificate-authority-service>`__,
          and more) allowing to choose the issuer fitting your organization's
          requirements.
        * Manages certificates via a
          `CRD <https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/>`__
          which is easier to inspect with Kubernetes tools than PEM files.

        **Installation steps:**

        #. First, install `cert-manager <https://cert-manager.io/docs/installation/>`__
           and setup an `issuer <https://cert-manager.io/docs/configuration/>`_.
           Please make sure that your issuer can create certificates for the
           configured Cluster Mesh API server names.
        #. Install or upgrade Cilium with the following Helm values:

        .. code-block:: yaml

          clustermesh:
            apiserver:
              tls:
                auto:
                  # enable automatic TLS certificate generation
                  enabled: true
                  # auto generate certificates using cert-manager
                  method: certmanager
                  # certificates validity duration in days (default 1 year)
                  certValidityDuration: 365
                  certManagerIssuerRef:
                    # Reference to cert-manager's issuer
                    group: cert-manager.io
                    kind: ClusterIssuer
                    name: ca-issuer

        During the first Cilium installation, cert-manager's webhook might not
        yet be available when Cilium creates its ``Certificate`` resources. See
        :ref:`troubleshooting_clustermesh_tls` if that occurs.

    .. group-tab:: Helm

        When using Helm, TLS certificates are (re-)generated every time Helm is used
        to install or upgrade Cilium.

        The following Helm values configure Helm certificate generation:

        .. code-block:: yaml

          clustermesh:
            apiserver:
              tls:
                auto:
                  # enable automatic TLS certificate generation
                  enabled: true
                  # auto generate certificates using helm method
                  method: helm
                  # certificates validity duration in days (default 1 year)
                  certValidityDuration: 365

        The downside of the Helm method is that while certificates are automatically
        generated, they are not automatically renewed.  Consequently, running
        ``helm upgrade`` is required when certificates are about to expire (i.e. before
        the configured ``clustermesh.apiserver.tls.auto.certValidityDuration``).

    .. group-tab:: User Provided Certificates

        In order to provide your own TLS certificates,
        ``clustermesh.apiserver.tls.auto.enabled`` must be set to ``false``,
        and the following fixed-name Secrets must be created in the
        namespace where Cilium is installed, which is typically ``kube-system``.

        The **Common Name (CN)** and **Subject Alternative Name (SAN)** of the
        certificates must be set as follows:

        * Server: CN ``clustermesh-apiserver.<namespace>.svc``. SANs must
          include ``clustermesh-apiserver.<namespace>.svc``,
          ``*.mesh.cilium.io``, ``127.0.0.1``, ``::1``, and every DNS name
          through which remote clusters reach the Cluster Mesh API Service
        * Admin: CN ``admin-<cluster-name>``
        * Remote: CN ``remote`` with the default ``migration`` authentication
          mode
        * Local: CN ``local-<cluster-name>``

        Once the certificates have been issued, create the following Secrets in
        the target namespace:

        * ``clustermesh-apiserver-server-cert``
        * ``clustermesh-apiserver-admin-cert``
        * ``clustermesh-apiserver-remote-cert``
        * ``clustermesh-apiserver-local-cert``

        Each Secret must contain the following keys:

        * ``tls.crt``: The certificate file
        * ``tls.key``: The private key file
        * ``ca.crt``: The CA certificate file

        After creating the Secrets, install or upgrade Cilium with automatic
        certificate generation disabled using the following Helm values:

        .. code-block:: yaml

           clustermesh:
             apiserver:
               tls:
                 auto:
                   enabled: false

    .. group-tab:: Custom Per-Pod Certificates

        If you want to provide TLS certificates directly to each pod rather than
        through Kubernetes Secrets, for example with HashiCorp Vault, the
        cert-manager CSI driver, or SPIFFE, configure a certificate agent and
        mount its output into the components.

        The external certificate agent is responsible for generating valid
        certificates. It must generate certificates with the same CN and SAN
        requirements as user-provided certificates.

        The following Helm values disable automatic certificate generation and
        the default Cluster Mesh certificate volumes:

        .. code-block:: yaml

          clustermesh:
            apiserver:
              tls:
                auto:
                  enabled: false
                disableDefaultVolumes: true

        You can then configure your certificate init containers using the
        following extension points:

        .. code-block:: yaml

          # Cilium agent
          extraInitContainers: []
          extraVolumes: []
          extraVolumeMounts: []

          operator:
            extraInitContainers: []
            extraVolumes: []
            extraVolumeMounts: []

          clustermesh:
            apiserver:
              extraInitContainers: []
              extraVolumes: []
              extraVolumeMounts: []
              kvstoremesh:
                extraVolumeMounts: []

        Disabling the default Cluster Mesh volumes also removes the peer
        configuration mounts.

        You need to mount ``cilium-clustermesh`` for the Cilium agent and operator,
        and ``cilium-kvstoremesh`` for KVStoreMesh, or provide equivalent peer
        configuration from your own integration. The exact values depend on your
        certificate management system and are out of scope for this guide.

For TLS troubleshooting, see :ref:`troubleshooting_clustermesh_tls`.

.. _enable_clustermesh:

Enable Cluster Mesh
===================

Enable all required components by running ``cilium clustermesh enable`` in the
context of both clusters. This will deploy the ``clustermesh-apiserver`` into
the cluster and generate all required certificates and import them as
Kubernetes secrets. It will also attempt to auto-detect the best service type
for the LoadBalancer to expose the Cluster Mesh control plane to other
clusters.

.. code-block:: shell-session

   cilium clustermesh enable --context $CLUSTER1
   cilium clustermesh enable --context $CLUSTER2

.. important::

   In some cases, the service type cannot be automatically detected and you need to specify it manually. This
   can be done with the option ``--service-type``. The possible values are:

   LoadBalancer:
     A Kubernetes service of type LoadBalancer is used to expose the control
     plane. This uses a stable LoadBalancer IP and is typically the best option. 

   NodePort:
     A Kubernetes service of type NodePort is used to expose the control plane.
     This requires stable Node IPs. If a node disappears, the Cluster Mesh may
     have to reconnect to a different node. If all nodes have become
     unavailable, you may have to re-connect the clusters to extract new node
     IPs.

   ClusterIP:
     A Kubernetes service of type ClusterIP is used to expose the control
     plane. This requires the ClusterIPs are routable between clusters. This is
     typically only available via the helm chart installation method.

Wait for the Cluster Mesh components to come up by invoking ``cilium
clustermesh status --wait``. If you are using a service of type LoadBalancer
then this will also wait for the LoadBalancer to be assigned an IP.

.. code-block:: shell-session

   cilium clustermesh status --context $CLUSTER1 --wait
   cilium clustermesh status --context $CLUSTER2 --wait

.. code-block:: shell-session

    ✅ Cluster access information is available:
      - 10.168.0.89:2379
    ✅ Service "clustermesh-apiserver" of type "LoadBalancer" found
    🔌 Cluster Connections:


Connect Clusters
================

Finally, connect the clusters. This step only needs to be done in one
direction. The connection will automatically be established in both directions:

.. code-block:: shell-session

    cilium clustermesh connect --context $CLUSTER1 --destination-context $CLUSTER2

It may take a bit for the clusters to be connected. You can run ``cilium
clustermesh status --wait`` to wait for the connection to be successful:

.. code-block:: shell-session

   cilium clustermesh status --context $CLUSTER1 --wait

The output will look something like this:

.. code-block:: shell-session

    ✅ Cluster access information is available:
      - 10.168.0.89:2379
    ✅ Service "clustermesh-apiserver" of type "LoadBalancer" found
    ⌛ Waiting (12s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (25s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (38s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (51s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (1m4s) for clusters to be connected: 2 nodes are not ready
    ⌛ Waiting (1m17s) for clusters to be connected: 1 nodes are not ready
    ✅ All 2 nodes are connected to all clusters [min:1 / avg:1.0 / max:1]
    🔌 Cluster Connections:
    - cilium-cli-ci-multicluster-2-168: 2/2 configured, 2/2 connected

If this step does not complete successfully, proceed to the troubleshooting
section.

Test Pod Connectivity Between Clusters
======================================

Congratulations, you have successfully connected your clusters together. You
can validate the connectivity by running the connectivity test in multi cluster
mode:

.. code-block:: shell-session

   cilium connectivity test --context $CLUSTER1 --multi-cluster $CLUSTER2

Next Steps
==========

Logical next steps to explore from here are:

 * :ref:`gs_clustermesh_load_balancing`
 * :ref:`gs_clustermesh_network_policy`

Troubleshooting
###############

Use the following list of steps to troubleshoot issues with ClusterMesh:

 #. Validate that Cilium pods are healthy and ready:

    .. code-block:: shell-session

       cilium status --context $CLUSTER1
       cilium status --context $CLUSTER2

 #. Validate that Cluster Mesh is enabled and operational:

    .. code-block:: shell-session

       cilium clustermesh status --context $CLUSTER1
       cilium clustermesh status --context $CLUSTER2

If you cannot resolve the issue with the above commands, see the
:ref:`troubleshooting_clustermesh` for a more detailed troubleshooting guide.
