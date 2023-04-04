.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_wg:

********************************
WireGuard Transparent Encryption
********************************

This guide explains how to configure Cilium with transparent encryption of
traffic between Cilium-managed endpoints using `WireGuard® <https://www.wireguard.com/>`_.

.. admonition:: Video
  :class: attention

  Aside from this guide, you can also watch `eCHO episode 3: WireGuard <https://www.youtube.com/watch?v=-awkPi3D60E&t=475s>`__ on how
  WireGuard can encrypt network traffic.

When WireGuard is enabled in Cilium, the agent running on each cluster node
will establish a secure WireGuard tunnel between it and all other known nodes
in the cluster. Each node automatically creates its own encryption key-pair and
distributes its public key via the ``network.cilium.io/wg-pub-key`` annotation
in the Kubernetes ``CiliumNode`` custom resource object. Each node's public key
is then used by other nodes to decrypt and encrypt traffic from and to
Cilium-managed endpoints running on that node.

Packets are not encrypted when they are destined to the same node from which
they were sent. This behavior is intended. Encryption would provide no benefits
in that case, given that the raw traffic can be observed on the node anyway.

The WireGuard tunnel endpoint is exposed on UDP port ``51871`` on each node. If
you run Cilium in an environment that requires firewall rules to enable
connectivity, you will have to ensure that all Cilium cluster nodes can reach
each other via that port.

.. note::

   When running in the tunneling mode (i.e. with VXLAN or Geneve), pod to pod
   traffic will be sent only over the WireGuard tunnel which means that the
   packets will bypass the other tunnel, and thus they will be encapsulated
   only once.

Enable WireGuard in Cilium
==========================

Before you enable WireGuard in Cilium, please ensure that the Linux distribution
running on your cluster nodes has support for WireGuard in kernel mode
(i.e. ``CONFIG_WIREGUARD=m`` on Linux 5.6 and newer, or via the out-of-tree
WireGuard module on older kernels).
See `WireGuard Installation <https://www.wireguard.com/install/>`_ for details
on how to install the kernel module on your Linux distribution.

If your kernel or distribution does not support WireGuard, Cilium agent can be
configured to fall back on the user-space implementation via the
``--enable-wireguard-userspace-fallback`` flag. When this flag is enabled and
Cilium detects that the kernel has no native support for WireGuard, it
will fallback on the ``wireguard-go`` user-space implementation of WireGuard.
When running the user-space implementation, encryption and decryption of packets
is performed by the ``cilium-agent`` process. As a consequence, connectivity
between Cilium-managed endpoints will be unavailable whenever the
``cilium-agent`` process is restarted, such as during upgrades or configuration
changes. Running WireGuard in user-space mode is therefore not recommended for
production workloads that require high availability.

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. code-block:: shell-session

          cilium install --encryption wireguard

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.type=wireguard

WireGuard may also be enabled manually by setting setting the
``enable-wireguard: true`` option in the Cilium ``ConfigMap`` and restarting
each Cilium agent instance.

Validate the Setup
==================

Run a ``bash`` shell in one of the Cilium pods with
``kubectl -n kube-system exec -ti ds/cilium -- bash`` and execute the following
commands:

1. Check that WireGuard has been enabled (number of peers should correspond to
   a number of nodes subtracted by one):

   .. code-block:: shell-session

      cilium status | grep Encryption

      Encryption: Wireguard [cilium_wg0 (Pubkey: <..>, Port: 51871, Peers: 2)]

2. Install tcpdump

   .. code-block:: shell-session

      apt-get update
      apt-get -y install tcpdump

3. Check that traffic is sent via the ``cilium_wg0`` tunnel device:

   .. code-block:: shell-session

      tcpdump -n -i cilium_wg0

      tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
      listening on cilium_wg0, link-type RAW (Raw IP), capture size 262144 bytes
      15:05:24.643427 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [S], seq 476474887, win 64860, options [mss 1410,sackOK,TS val 648097391 ecr 0,nop,wscale 7], length 0
      15:05:24.644185 IP 10.244.3.78.8080 > 10.244.1.35.51116: Flags [S.], seq 4032860634, ack 476474888, win 64308, options [mss 1410,sackOK,TS val 4004186138 ecr 648097391,nop,wscale 7], length 0
      15:05:24.644238 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [.], ack 1, win 507, options [nop,nop,TS val 648097391 ecr 4004186138], length 0
      15:05:24.644277 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [P.], seq 1:81, ack 1, win 507, options [nop,nop,TS val 648097392 ecr 4004186138], length 80: HTTP: GET / HTTP/1.1
      15:05:24.644370 IP 10.244.3.78.8080 > 10.244.1.35.51116: Flags [.], ack 81, win 502, options [nop,nop,TS val 4004186139 ecr 648097392], length 0
      15:05:24.645536 IP 10.244.3.78.8080 > 10.244.1.35.51116: Flags [.], seq 1:1369, ack 81, win 502, options [nop,nop,TS val 4004186140 ecr 648097392], length 1368: HTTP: HTTP/1.1 200 OK
      15:05:24.645569 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [.], ack 1369, win 502, options [nop,nop,TS val 648097393 ecr 4004186140], length 0
      15:05:24.645578 IP 10.244.3.78.8080 > 10.244.1.35.51116: Flags [P.], seq 1369:2422, ack 81, win 502, options [nop,nop,TS val 4004186140 ecr 648097392], length 1053: HTTP
      15:05:24.645644 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [.], ack 2422, win 494, options [nop,nop,TS val 648097393 ecr 4004186140], length 0
      15:05:24.645752 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [F.], seq 81, ack 2422, win 502, options [nop,nop,TS val 648097393 ecr 4004186140], length 0
      15:05:24.646431 IP 10.244.3.78.8080 > 10.244.1.35.51116: Flags [F.], seq 2422, ack 82, win 502, options [nop,nop,TS val 4004186141 ecr 648097393], length 0
      15:05:24.646484 IP 10.244.1.35.51116 > 10.244.3.78.8080: Flags [.], ack 2423, win 502, options [nop,nop,TS val 648097394 ecr 4004186141], length 0

Troubleshooting
===============

When troubleshooting dropped or unencrypted packets between pods, the following
commands can be helpful:

.. code-block:: shell-session

   # From node A:
   cilium debuginfo --output json | jq .encryption
   {
     "wireguard": {
       "interfaces": [
         {
           "listen-port": 51871,
           "name": "cilium_wg0",
           "peer-count": 1,
           "peers": [
             {
               "allowed-ips": [
                 "10.154.1.107/32",
                 "10.154.1.195/32"
               ],
               "endpoint": "192.168.61.12:51871",
               "last-handshake-time": "2021-05-05T12:31:24.418Z",
               "public-key": "RcYfs/GEkcnnv6moK5A1pKnd+YYUue21jO9I08Bv0zo="
             }
           ],
           "public-key": "DrAc2EloK45yqAcjhxerQKwoYUbLDjyrWgt9UXImbEY="
         }
       ]
     }
   }
   # From node B:
   cilium debuginfo --output json | jq .encryption
   {
     "wireguard": {
       "interfaces": [
         {
           "listen-port": 51871,
           "name": "cilium_wg0",
           "peer-count": 1,
           "peers": [
             {
               "allowed-ips": [
                 "10.154.2.103/32",
                 "10.154.2.142/32"
               ],
               "endpoint": "192.168.61.11:51871",
               "last-handshake-time": "2021-05-05T12:31:24.631Z",
               "public-key": "DrAc2EloK45yqAcjhxerQKwoYUbLDjyrWgt9UXImbEY="
             }
           ],
           "public-key": "RcYfs/GEkcnnv6moK5A1pKnd+YYUue21jO9I08Bv0zo="
         }
       ]
     }
   }

For pod to pod packets to be successfully encrypted and decrypted, the following
must hold:

 - WireGuard public key of a remote node in the ``peers[*].public-key`` section
   matches the actual public key of the remote node (``public-key`` retrieved via
   the same command on the remote node).
 - ``peers[*].allowed-ips`` should contain a list of pod IP addresses running
   on the remote.

Cluster Mesh
============

WireGuard enabled Cilium clusters can be connected via :ref:`Cluster Mesh`. The
``clustermesh-apiserver`` will forward the necessary WireGuard public keys
automatically to remote clusters.
In such a setup, it is important to note that all participating clusters must
have WireGuard encryption enabled, i.e. mixed mode is currently not supported.
In addition, UDP traffic between nodes of different clusters on port ``51871``
must be allowed.

Node-to-Node Encryption (beta)
==============================

By default, WireGuard-based encryption only encrypts traffic between Cilium-managed
pods. To enable node-to-node encryption, which additionally also encrypts
node-to-node, pod-to-node and node-to-pod traffic, use the following configuration
options:

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. code-block:: shell-session

          cilium install --encryption wireguard --node-encryption

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.type=wireguard \\
             --set encryption.nodeEncryption=true

.. warning::

  Cilium automatically disables node-to-node encryption from and to
  Kubernetes control-plane nodes, i.e. any node with the
  ``node-role.kubernetes.io/control-plane`` label will opt-out of node-to-node
  encryption.

  This is done to ensure worker nodes are always able to communicate with the
  Kubernetes API to update their WireGuard public keys. With node-to-node
  encryption enabled, the connection to the kube-apiserver would also be
  encrypted with WireGuard. This creates a bootstrapping problem where the
  connection used to update the WireGuard public key is itself encrypted with
  the public key about to be replaced.
  This is problematic if a node needs to change its public key, for example
  because it generated a new private key after a node reboot or node
  re-provisioning.

  Therefore, by not encrypting the connection from and to the kube-apiserver
  host network with WireGuard, we ensure that worker nodes are
  never accidentally locked out from the control plane. Note that even if
  WireGuard node-to-node encryption is disabled on those nodes, the Kubernetes
  control-plane itself is usually still encrypted by Kubernetes itself using
  mTLS and that pod-to-pod traffic for any Cilium-manged pods on the
  control-plane nodes are also still encrypted via Cilium's WireGuard
  implementation.

  The label selector for matching the control-plane nodes which shall not
  participate in node-to-node encryption can be configured using the
  ``node-encryption-opt-out-labels`` ConfigMap option. It defaults to
  ``node-role.kubernetes.io/control-plane``.
  You may force node-to-node encryption from and to control-plane nodes by
  using an empty label selector with that option. Note that doing so is not
  recommended, as it will require you to always manually update a node's public
  key in its corresponding ``CiliumNode`` CRD when a worker node's public key
  changes, given that the worker node will be unable to do so itself.

Legal
=====

"WireGuard" is a registered trademark of Jason A. Donenfeld.
