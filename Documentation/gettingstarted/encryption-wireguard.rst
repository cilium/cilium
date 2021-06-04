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

When WireGuard is enabled in Cilium, the agent running on each cluster node
will establish a secure WireGuard tunnel between it and all other known nodes
in the cluster. Each node automatically creates its own encryption key-pair and
distributes its public key via the ``io.cilium.network.wg-pub-key`` annotation
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
             --set l7Proxy=false \\
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
               "endpoint": "192.168.34.12:51871",
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
               "endpoint": "192.168.34.11:51871",
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

Limitations
===========

WireGuard support in Cilium currently lacks the following features,
which may be resolved in upcoming Cilium releases:

 - Host-level encryption. Only traffic between two Cilium-managed endpoints
   (i.e. pod to pod traffic) is encrypted. Traffic between a Cilium-managed
   pod and a remote host, or traffic between two hosts running the Cilium
   agent will currently not be encrypted.
 - L7 policy enforcement and visibility
 - eBPF-based host routing
 - Support for older kernels via user-mode WireGuard

The current status of these limitations is tracked in :gh-issue:`15462`.

Legal
=====

"WireGuard" is a registered trademark of Jason A. Donenfeld.