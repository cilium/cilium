.. _k8s_install_alibabacloud:

**Installing Cilium on Alibaba Cloud ACK:**

This guide installs Cilium as the CNI in a new ACK BYOCNI cluster. Cilium
provides pod networking and network policy enforcement in both modes below.

**Create an ACK BYOCNI cluster:**

.. include:: requirements-generic.rst

Follow the `ACK custom CNI guide
<https://help.aliyun.com/en/ack/ack-managed-and-ack-dedicated/user-guide/use-a-custom-cni-plugin-in-an-ack-cluster>`_
to create an ACK managed Pro cluster through OpenAPI or Terraform. BYOCNI is
not available through the ACK console or on other cluster types.

Disable the ``kube-flannel-ds`` add-on at creation time. The following is an
add-on configuration fragment for the CreateCluster API, not a complete cluster
creation request:

.. code-block:: json

   {
     "addons": [
       {"name": "kube-flannel-ds", "disabled": true}
     ]
   }

Choose overlay networking or Alibaba Cloud ENI networking below. Both work
without ACK-assigned Node PodCIDRs. Leave CCM settings to your network plan;
CCM VPC routes are optional and are covered below.

On each node, ensure the CNI binary directory ``/opt/cni/bin`` has permissions
``0755`` so that Cilium's init containers can access it.

Configure ``kubectl`` and Helm for the new cluster. Nodes remain ``NotReady``
until Cilium is installed.

**Install Cilium:**

.. tabs::

   .. tab:: Overlay

      Choose a pod CIDR that does not overlap with your VPC or Service CIDRs.
      Allow node-to-node UDP port 8472 for VXLAN in security groups.

      .. cilium-helm-install::
         :namespace: kube-system
         :set: alibabacloud.enabled=false
               ipam.mode=cluster-pool
               ipam.operator.clusterPoolIPv4PodCIDRList=10.244.0.0/16
               ipam.operator.clusterPoolIPv4MaskSize=24
               routingMode=tunnel
               tunnelProtocol=vxlan
               enableIPv4Masquerade=true

      Cilium allocates pod CIDRs in ``CiliumNode`` resources and carries
      cross-node traffic over VXLAN. Outbound traffic is masqueraded to the
      node address.
      See :ref:`ipam_crd_cluster_pool` and :ref:`arch_overlay`.

      .. note::

         The managed API server cannot directly reach overlay pod IPs. Use
         reachable endpoints for webhooks and metrics-server, such as host
         networking, or the optional CCM route configuration below.

   .. tab:: ENI

      .. include:: alibabacloud-eni.rst

**Validate the installation:**

.. code-block:: shell-session

   kubectl get nodes
   cilium status --wait
   cilium connectivity test

Install the :ref:`Cilium CLI <install_cilium_cli>` before running the Cilium
commands. Also check any admission webhooks that your workloads require.
For ENI mode, confirm that pod IPs belong to the expected vSwitch with
``kubectl get ciliumnodes -o yaml``.

**Optional CCM routes for webhook access:**

CCM creates VPC routes from Kubernetes ``Node.spec.podCIDR``. Cilium cluster-pool
IPAM writes ``CiliumNode.spec.ipam.podCIDRs`` instead; it does not populate the
Kubernetes Node field. Enabling CCM routes alone therefore does not provide
access to cluster-pool overlay pods.

To let the managed API server reach webhook pod IPs through CCM routes, use
Kubernetes IPAM with native routing. At cluster creation, set both
``container_cidr`` (for example ``10.245.0.0/16``) and ``node_cidr_mask``
(for example ``24``), and set ``EnableCloudRoutes=true`` on the CCM add-on.
Install Cilium with the following values instead of the overlay settings:

.. code-block:: yaml

   ipam:
     mode: kubernetes
   routingMode: native
   ipv4NativeRoutingCIDR: 10.245.0.0/16

Kubernetes assigns each node a PodCIDR, Cilium allocates pod IPs from it, and
CCM routes that CIDR to the node. Allow the required webhook ports in security
groups. If neither creation parameter is set, ACK does not allocate Node
PodCIDRs and CCM has no PodCIDRs to route. See the `ACK custom CNI guide`_
for the API parameters and CCM configuration.
