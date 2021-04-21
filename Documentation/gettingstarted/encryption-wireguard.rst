.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_wg:

********************************
Wireguard Transparent Encryption
********************************

This guide explains how to configure Cilium with transparent encryption of
traffic between Cilium-managed endpoints using `Wireguard <https://www.wireguard.com/>`_.

When Wireguard is enabled in Cilium, the agent running on each cluster node
will establish a secure Wireguard tunnel between it and all other known nodes
in the cluster. Each node automatically creates its own encryption key-pair and
distributes its public key via the ``io.cilium.network.wg-pub-key`` annotation
in the Kubernetes ``CiliumNode`` custom resource object. Each node's public key
is then used by other nodes to decrypt and encrypt traffic from and to
Cilium-managed endpoints running on that node.

The Wireguard tunnel endpoint is exposed on UDP port ``51871`` on each node. If
you run Cilium in an environment that requires firewall rules to enable
connectivity, you will have to ensure that all Cilium cluster nodes can reach
each other via that port.

Enable Wireguard in Cilium
==========================

Before you enable Wireguard in Cilium, please ensure that the Linux distribution
running on your cluster nodes has support for Wireguard in kernel mode
(i.e. ``CONFIG_WIREGUARD=m`` on Linux 5.6 and newer, or via the out-of-tree
Wireguard module on older kernels).

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. code-block:: shell-session

          cilium install --config enable-wireguard=true --config enable-l7-proxy=false

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set l7Proxy=false \\
             --set wireguard.enabled=true

Wireguard may also be enabled manually by setting setting the
``enable-wireguard: true`` option in the Cilium ``ConfigMap`` and restarting
each Cilium agent instance.

.. note::

    Wireguard support in Cilium currently lacks the following features,
    which may be resolved in upcoming Cilium releases:

    - Host-level encryption. Only traffic between two Cilium-managed endpoints
      (i.e. pod to pod traffic) is encrypted. Traffic between a Cilium-managed
      pod and a remote host, or traffic between two hosts running the Cilium
      agent will currently not be encrypted.
    - L7 policy enforcement and visibility
    - eBPF-based host routing
    - Support for older kernels via user-mode Wireguard

   The current status of these limitations is tracked in :gh-issue:`15462`.


Validate the Setup
==================

Run a ``bash`` shell in one of the Cilium pods with ``kubectl -n <k8s namespace>
exec -ti ds/cilium -- bash`` and execute the following commands:

1. Install tcpdump

.. code:: shell-session

    apt-get update
    apt-get -y install tcpdump

2. Check that traffic is sent via the ``cilium_wg0`` tunnel device:

.. code-block:: shell-session

    $ tcpdump -n -i cilium_wg0
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
