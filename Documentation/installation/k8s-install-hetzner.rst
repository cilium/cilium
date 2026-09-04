.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _k8s_install_hetzner:

Hetzner Cloud
=============

This guide covers installing Cilium on `Hetzner Cloud
<https://www.hetzner.com/cloud>`_ private networks in native routing mode,
including multi-datacenter clusters.

**Default Configuration:**

================ =================== ===============
Datapath         IPAM                Datastore
================ =================== ===============
Native Routing   Kubernetes PodCIDR  Kubernetes CRD
================ =================== ===============

Prerequisites
-------------

* A Hetzner Cloud project with a `private network
  <https://docs.hetzner.com/cloud/networks/getting-started/creating-a-network>`_
  configured. Cluster nodes should attach to a subnet within that network
  (e.g. ``10.0.1.0/24``).
* Nodes may be private-only (no public IPv4). A gateway node or NAT router
  with a public IP is required for egress.
* For multi-datacenter clusters (nodes spread across ``fsn1``, ``nbg1``,
  ``hel1``), see the :ref:`hetzner_multi_dc` section below.

Install Cilium
--------------

Use the pod CIDR (``10.42.0.0/16`` in this example, adjust to match your
``--cluster-cidr``) as the native routing CIDR:

.. code-block:: shell-session

    helm install cilium cilium/cilium \
      --namespace kube-system \
      --set ipam.mode=kubernetes \
      --set kubeProxyReplacement=true \
      --set k8sServiceHost=<API_SERVER_IP> \
      --set k8sServicePort=6443 \
      --set routingMode=native \
      --set autoDirectNodeRoutes=true \
      --set ipv4NativeRoutingCIDR=10.42.0.0/16 \
      --set operator.replicas=1

Or as a Helm values file:

.. code-block:: yaml

    ipam:
      mode: kubernetes
    kubeProxyReplacement: true
    k8sServiceHost: <API_SERVER_IP>
    k8sServicePort: 6443
    routingMode: native
    autoDirectNodeRoutes: true
    # Set to Pod CIDR only, NOT the full Hetzner private network CIDR.
    # See the Common Issues section below for details.
    ipv4NativeRoutingCIDR: "10.42.0.0/16"
    operator:
      replicas: 1

With this configuration:

* **Pod-to-pod** (intra-cluster): Traffic is directly routed to destinations within ``10.42.0.0/16`` without masquerade.
* **Pod-to-external** (non-cluster hosts, Internet): Traffic to destinations outside ``10.42.0.0/16`` is masqueraded to the node's registered IP, satisfying Hetzner uRPF.

.. _hetzner_multi_dc:

Multi-Datacenter Clusters
--------------------------

Hetzner private networks provide direct L2 connectivity within a single
datacenter and are L3-routed between datacenters (``fsn1`` ↔ ``nbg1`` ↔
``hel1``). ``auto-direct-node-routes`` installs direct host routes between
nodes and relies on L2 ARP for next-hop resolution. Nodes in different DCs
cannot resolve each other via ARP across the L3 boundary.

Add ``directRoutingSkipUnreachable: true`` to prevent Cilium from installing
direct routes to nodes it cannot reach at L2 (cross-DC nodes). Traffic to
those nodes falls back to the Hetzner L3 router, which correctly routes it:

.. code-block:: yaml

    routingMode: native
    autoDirectNodeRoutes: true
    directRoutingSkipUnreachable: true
    ipv4NativeRoutingCIDR: "10.42.0.0/16"

Internal Load Balancer VIPs (L2 Announcements)
------------------------------------------------

To expose cluster-internal services at a stable private IP without
provisioning a public Hetzner Load Balancer, use Cilium's :ref:`lb_ipam`
together with L2 announcements:

.. code-block:: yaml

    l2announcements:
      enabled: true

When creating a ``CiliumL2AnnouncementPolicy``, pin the policy to a node in
the same datacenter as the hosts that will consume the VIP. ARP announcements
are not forwarded across the Hetzner L3 router between datacenters.

See :ref:`l2_announcements` for full configuration details.

.. _hetzner_common_issues:

Common Issues
-------------

.. _hetzner_urpf:

Unicast Reverse Path Forwarding (uRPF)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hetzner Cloud private networks implement `unicast reverse path forwarding
(uRPF)
<https://docs.hetzner.com/networking/networks/faq/#why-do-packets-with-source-ips-not-related-to-the-server-get-dropped>`_
at the virtual network gateway. The gateway validates every packet's source IP
against the IP prefixes registered to the originating server (assigned IPs,
alias IPs, or routes designating the server as a gateway). Packets with an
unrecognised source IP are silently dropped.

Pod IPs (e.g. ``10.42.0.0/16``) are not registered server prefixes. If
``ipv4-native-routing-cidr`` is set to the full private-network CIDR
(e.g. ``10.0.0.0/8``), Cilium will not masquerade pod traffic destined for
non-cluster hosts in that network, causing timeouts on connections from
Pod IPs towards IPs in the full private network CIDR range.

.. caution::

   Do **not** set ``ipv4-native-routing-cidr`` to the full Hetzner private
   network CIDR (e.g. ``10.0.0.0/8``). Set it to the pod CIDR only, as shown
   in the `Install Cilium`_ section above.

This failure is easily masked during testing: when ``auto-direct-node-routes``
is enabled Cilium installs direct host routes for peer pod CIDRs, so
pod-to-pod cross-node traffic bypasses the Hetzner gateway entirely. Only
traffic from pods to non-cluster hosts in the same private network (e.g.
other VMs, a separate k8s cluster, a gateway node) is affected.
