.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption:

************************************
Transparent Encryption (stable/beta)
************************************

This guide explains how to configure Cilium to use IPsec based transparent
encryption using Kubernetes secrets to distribute the IPsec keys. After this
configuration is complete all traffic between Cilium
managed endpoints, as well as Cilium managed host traffic, will be encrypted
using IPsec. This guide uses Kubernetes secrets to distribute keys. Alternatively,
keys may be manually distributed but that is not shown here.

.. note::

    The encryption feature is stable in combination with the direct-routing and
    ENI datapath mode. In combination with encapsulation/tunneling, the feature
    is still in beta phase.

Generate & import the PSK
=========================

First create a Kubernetes secret for the IPsec keys to be stored.
This will generate the necessary IPsec keys which will be distributed as a
Kubernetes secret called ``cilium-ipsec-keys``. In this example we use
GMC-128-AES, but any of the supported
Linux algorithms may be used. To generate use the following

.. parsed-literal::

    $ kubectl create -n kube-system secret generic cilium-ipsec-keys \\
        --from-literal=keys="3 rfc4106(gcm(aes)) $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null| xxd -p -c 64)) 128"

The secret can be displayed with ``kubectl -n kube-system get secret`` and will be
listed as 'cilium-ipsec-keys'.

.. parsed-literal::
    $ kubectl -n kube-system get secrets cilium-ipsec-keys
    NAME                TYPE     DATA   AGE
    cilium-ipsec-keys   Opaque   1      176m

Enable Encryption in Cilium
===========================

.. include:: k8s-install-download-release.rst

Deploy Cilium release via Helm:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set global.encryption.enabled=true \\
      --set global.encryption.nodeEncryption=false

At this point the Cilium managed nodes will be using IPsec for all traffic. For further
information on Cilium's transparent encryption, see :ref:`arch_guide`.

Encryption interface
--------------------

If direct routing is being used an additional argument can be used to identify the
network facing interface. If no interface is specified the default route link is
chosen by inspecting the routing tables. This will work in many cases but depending
on routing rules users may need to specify the encryption interface as follows:

.. code:: bash

    --set global.encryption.interface=ethX

Node to node encryption
-----------------------

In order to enable node-to-node encryption, add:

.. code:: bash

    [...]
    --set global.encryption.enabled=true \
    --set global.encryption.nodeEncryption=true

Validate the Setup
==================

Run a ``bash`` shell in one of the Cilium pods with ``kubectl -n kube-system
exec -ti cilium-7cpsm -- bash`` and execute the following commands:

1. Install tcpdump

.. code:: bash

    apt-get update
    apt-get -y install tcpdump

2. Check that traffic is encrypted:

.. code:: bash

    tcpdump -n -i cilium_vxlan
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on cilium_vxlan, link-type EN10MB (Ethernet), capture size 262144 bytes
    15:16:21.626416 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e2), length 180
    15:16:21.626473 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e3), length 180
    15:16:21.627167 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579d), length 100
    15:16:21.627296 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579e), length 100
    15:16:21.627523 IP 10.60.0.1 > 10.60.1.1: ESP(spi=0x00000001,seq=0x579f), length 180
    15:16:21.627699 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e4), length 100
    15:16:21.628408 IP 10.60.1.1 > 10.60.0.1: ESP(spi=0x00000001,seq=0x57e5), length 100

Key Rotation
============

To replace cilium-ipsec-keys secret with a new keys,

.. code-block:: shell-session

    KEYID=$(kubectl get secret -n kube-system cilium-ipsec-keys -o yaml|grep keys: | awk '{print $2}' | base64 -d | awk '{print $1}')
    if [[ $KEYID -gt 15 ]]; then KEYID=0; fi
    data=$(echo "{\"stringData\":{\"keys\":\"$((($KEYID+1))) "rfc4106\(gcm\(aes\)\)" $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null| xxd -p -c 64)) 128\"}}")
    kubectl patch secret -n kube-system cilium-ipsec-keys -p="${data}" -v=1

Then restart cilium agents to transition to the new key. During transition the
new and old keys will be in use. The cilium agent keeps per endpoint data on
which key is used by each endpoint and will use the correct key if either side
has not yet been updated. In this way encryption will work as new keys are
rolled out.

The KEYID environment variable in the above example stores the current key ID
used by Cilium. The key variable is a uint8 with value between 0-16 and should
be monotonically increasing every re-key with a rollover from 16 to 0. The
cilium agent will default to KEYID of zero if its not specified in the secret.

Troubleshooting
===============

 * Make sure that the Cilium pods have kvstore connectivity:

   .. code:: bash

      cilium status
      KVStore:                Ok   etcd: 1/1 connected: http://127.0.0.1:31079 - 3.3.2 (Leader)
      [...]

 * Check for ``level=warning`` and ``level=error`` messages in the Cilium log files
 * Run a ``bash`` in a Cilium and validate the following:

   * Routing rules matching on fwmark:

     .. code:: bash

        ip rule list
        1:	from all fwmark 0xd00/0xf00 lookup 200
        1:	from all fwmark 0xe00/0xf00 lookup 200
        [...]

   * Content of routing table 200

     .. code:: bash

        ip route list table 200
        local 10.60.0.0/24 dev cilium_vxlan proto 50 scope host
        10.60.1.0/24 via 10.60.0.1 dev cilium_host

   * XFRM policy:

     .. code:: bash

        ip xfrm p
        src 10.60.1.1/24 dst 10.60.0.1/24
                dir fwd priority 0
                mark 0xd00/0xf00
                tmpl src 10.60.1.1 dst 10.60.0.1
                        proto esp spi 0x00000001 reqid 1 mode tunnel
        src 10.60.1.1/24 dst 10.60.0.1/24
                dir in priority 0
                mark 0xd00/0xf00
                tmpl src 10.60.1.1 dst 10.60.0.1
                        proto esp spi 0x00000001 reqid 1 mode tunnel
        src 10.60.0.1/24 dst 10.60.1.1/24
                dir out priority 0
                mark 0xe00/0xf00
                tmpl src 10.60.0.1 dst 10.60.1.1
                        proto esp spi 0x00000001 reqid 1 mode tunnel

   * XFRM state:

     .. code:: bash

        ip xfrm s
        src 10.60.0.1 dst 10.60.1.1
                proto esp spi 0x00000001 reqid 1 mode tunnel
                replay-window 0
                auth-trunc hmac(sha256) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546 96
                enc cbc(aes) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546
                anti-replay context: seq 0x0, oseq 0xe0c0, bitmap 0x00000000
                sel src 0.0.0.0/0 dst 0.0.0.0/0
        src 10.60.1.1 dst 10.60.0.1
                proto esp spi 0x00000001 reqid 1 mode tunnel
                replay-window 0
                auth-trunc hmac(sha256) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546 96
                enc cbc(aes) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546
                anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
                sel src 0.0.0.0/0 dst 0.0.0.0/0

Disabling Encryption
====================

To disable the encryption, regenerate the YAML with the option
``global.encryption.enabled=false``
