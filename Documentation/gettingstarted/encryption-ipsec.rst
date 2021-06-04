.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _encryption_ipsec:

****************************
IPsec Transparent Encryption
****************************

This guide explains how to configure Cilium to use IPsec based transparent
encryption using Kubernetes secrets to distribute the IPsec keys. After this
configuration is complete all traffic between Cilium-managed endpoints, as well
as Cilium-managed host traffic, will be encrypted using IPsec. This guide uses
Kubernetes secrets to distribute keys. Alternatively, keys may be manually
distributed, but that is not shown here.

Packets are not encrypted when they are destined to the same node from which
they were sent. This behavior is intended. Encryption would provide no benefits
in that case, given that the raw traffic can be observed on the node anyway.

Transparent encryption is not currently supported when chaining Cilium on top
of other CNI plugins. For more information, see :gh-issue:`15596`.

Generate & Import the PSK
=========================

First, create a Kubernetes secret for the IPsec configuration to be stored. The
example below demonstrates generation of the necessary IPsec configuration
which will be distributed as a Kubernetes secret called ``cilium-ipsec-keys``.
A Kubernetes secret should consist of one key-value pair where the key is the
name of the file to be mounted as a volume in cilium-agent pods, and the
value is an IPSec configuration in the following format::

    key-id encryption-algorithms PSK-in-hex-format key-size

.. note::

    ``Secret`` resources need to be deployed in the same namespace as Cilium!
    In our example, we use ``kube-system``.

In the example below, GMC-128-AES is used. However, any of the algorithms
supported by Linux may be used. To generate the secret, you may use the
following command:

.. code-block:: shell-session

    $ kubectl create -n kube-system secret generic cilium-ipsec-keys \
        --from-literal=keys="3 rfc4106(gcm(aes)) $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null | xxd -p -c 64)) 128"

The secret can be seen with ``kubectl -n kube-system get secrets`` and will be
listed as ``cilium-ipsec-keys``.

.. code-block:: shell-session

    $ kubectl -n kube-system get secrets cilium-ipsec-keys
    NAME                TYPE     DATA   AGE
    cilium-ipsec-keys   Opaque   1      176m

Enable Encryption in Cilium
===========================

.. tabs::

    .. group-tab:: Cilium CLI

       If you are deploying Cilium with the Cilium CLI, pass the following
       options:

       .. code-block:: shell-session

          cilium install --encryption ipsec

    .. group-tab:: Helm

       If you are deploying Cilium with Helm by following
       :ref:`k8s_install_helm`, pass the following options:

       .. parsed-literal::

           helm install cilium |CHART_RELEASE| \\
             --namespace kube-system \\
             --set encryption.enabled=true \\
             --set encryption.nodeEncryption=false \\
             --set encryption.type=ipsec

       ``encryption.enabled`` enables encryption of the traffic between Cilium-managed pods and
       ``encryption.nodeEncryption`` controls whether host traffic is encrypted.
       ``encryption.type`` specifies the encryption method and can be omitted
       as it defaults to ``ipsec``.

.. attention::

   When using Cilium in any direct routing configuration, ensure that the
   native routing CIDR is set properly. This is done using
   ``--native-routing-cidr=CIDR`` with the CLI or ``--set
   nativeRoutingCIDR=CIDR`` with Helm.

At this point the Cilium managed nodes will be using IPsec for all traffic. For further
information on Cilium's transparent encryption, see :ref:`ebpf_datapath`.

Encryption interface
--------------------

An additional argument can be used to identify the network-facing interface.
If direct routing is used and no interface is specified, the default route
link is chosen by inspecting the routing tables. This will work in many cases,
but depending on routing rules, users may need to specify the encryption
interface as follows:

.. tabs::

    .. group-tab:: Cilium CLI

       .. code-block:: shell-session

          cilium install --encryption ipsec --config encryption-interface=ethX

    .. group-tab:: Helm

       .. code-block:: shell-session

           --set encryption.ipsec.interface=ethX

.. _node_to_node_encryption:

Node-to-node encryption (beta)
------------------------------

In order to enable node-to-node encryption, add:

.. tabs::

    .. group-tab:: Cilium CLI

       .. code-block:: shell-session

          cilium install --encryption ipsec --node-encryption

    .. group-tab:: Helm

       .. code-block:: shell-session

           --set encryption.enabled=true \
           --set encryption.nodeEncryption=true \

.. note::

    Node-to-node encryption is a beta feature. Please provide feedback and file
    a GitHub issue if you experience any problems.

    Node-to-node encryption is tested and supported with direct routing modes.
    Using with encapsulation/tunneling is not currently tested or supported.

    Support with tunneling mode is tracked with :gh-issue:`13663`.

Validate the Setup
==================

Run a ``bash`` shell in one of the Cilium pods with
``kubectl -n kube-system exec -ti ds/cilium -- bash`` and execute the following
commands:

1. Install tcpdump

   .. code-block:: shell-session

       $ apt-get update
       $ apt-get -y install tcpdump

2. Check that traffic is encrypted. In the example below, this can be verified
   by the fact that packets carry the IP Encapsulating Security Payload (ESP).
   In the example below, ``eth0`` is the interface used for pod-to-pod
   communication. Replace this interface with ``cilium_vxlan`` if tunneling is enabled.

   .. code-block:: shell-session

       tcpdump -n -i eth0 esp
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

To replace cilium-ipsec-keys secret with a new key:

.. code-block:: shell-session

    KEYID=$(kubectl get secret -n kube-system cilium-ipsec-keys -o yaml | awk '/^\s*keys:/ {print $2}' | base64 -d | awk '{print $1}')
    if [[ $KEYID -gt 15 ]]; then KEYID=0; fi
    data=$(echo "{\"stringData\":{\"keys\":\"$((($KEYID+1))) "rfc4106\(gcm\(aes\)\)" $(echo $(dd if=/dev/urandom count=20 bs=1 2> /dev/null| xxd -p -c 64)) 128\"}}")
    kubectl patch secret -n kube-system cilium-ipsec-keys -p="${data}" -v=1

Then restart Cilium agents to transition to the new key with
``kubectl delete pod -n kube-system -l k8s-app=cilium``. During transition the
new and old keys will be in use. The Cilium agent keeps per endpoint data on
which key is used by each endpoint and will use the correct key if either side
has not yet been updated. In this way encryption will work as new keys are
rolled out.

The ``KEYID`` environment variable in the above example stores the current key
ID used by Cilium. The key variable is a uint8 with value between 0-16 and
should be monotonically increasing every re-key with a rollover from 16 to 0.
The Cilium agent will default to ``KEYID`` of zero if its not specified in the
secret.

Troubleshooting
===============

 * If the ``cilium`` Pods fail to start after enabling encryption, double-check if
   the IPSec ``Secret`` and Cilium are deployed in the same namespace together.

 * Make sure that the Cilium pods have kvstore connectivity:

   .. code-block:: shell-session

      cilium status
      KVStore:                Ok   etcd: 1/1 connected: http://127.0.0.1:31079 - 3.3.2 (Leader)
      [...]

 * Check for ``level=warning`` and ``level=error`` messages in the Cilium log files

   * If there is a warning message similar to ``Device eth0 does not exist``,
     use ``--set encryption.ipsec.interface=ethX`` to set the encryption
     interface.

 * Run a ``bash`` in a Cilium Pod and validate the following:

   * Routing rules matching on fwmark:

     .. code-block:: shell-session

        $ ip rule list
        1:	from all fwmark 0xd00/0xf00 lookup 200
        1:	from all fwmark 0xe00/0xf00 lookup 200
        [...]

   * Content of routing tables

     .. code-block:: shell-session

        $ ip route list table 200
        local 10.60.0.0/24 dev cilium_vxlan proto 50 scope host
        10.60.1.0/24 via 10.60.0.1 dev cilium_host

     In case of IPAM ENI mode, check if routing rules exist for the the IP
     address of ``cilium_host`` interface..

     .. code-block:: shell-session

         $ ip addr show cilium_host
         5: cilium_host@cilium_net: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 9001 qdisc noqueue state UP group default qlen 1000
         link/ether 96:b1:5c:82:75:a3 brd ff:ff:ff:ff:ff:ff
         inet 192.168.174.161/32 scope link cilium_host
            valid_lft forever preferred_lft forever
         inet6 fe80::94b1:5cff:fe82:75a3/64 scope link
            valid_lft forever preferred_lft forever

         $ ip rule | grep 192.168.174.161
         111:	from 192.168.174.161 to 192.168.0.0/16 lookup 11

   * XFRM policy:

     .. code-block:: shell-session

        $ ip xfrm p
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

   * XFRM stats with state:

    Check if the packets count increases as you send traffic.

    Following is the output from the source node.

    .. code-block:: shell-session

       $ ip -s xfrm s
       src 10.60.0.1 dst 10.60.1.1
               proto esp spi 0x00000001 reqid 1 mode tunnel
               replay-window 0
               auth-trunc hmac(sha256) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546 96
               enc cbc(aes) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546
               anti-replay context: seq 0x0, oseq 0xe0c0, bitmap 0x00000000
               sel src 0.0.0.0/0 dst 0.0.0.0/0
               lifetime config:
                 limit: soft (INF)(bytes), hard (INF)(bytes)
                 limit: soft (INF)(packets), hard (INF)(packets)
                 expire add: soft 0(sec), hard 0(sec)
                 expire use: soft 0(sec), hard 0(sec)
               lifetime current:
                 9507(bytes), 137(packets)
                 add 2021-02-10 08:20:09 use 2021-02-10 08:30:12
               stats:
                 replay-window 0 replay 0 failed 0

    Following is the output from the destination node.

    .. code-block:: shell-session

       $ ip -s xfrm s
       src 10.60.1.1 dst 10.60.0.1
               proto esp spi 0x00000001 reqid 1 mode tunnel
               replay-window 0
               auth-trunc hmac(sha256) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546 96
               enc cbc(aes) 0x6162636465666768696a6b6c6d6e6f70717273747576777a797a414243444546
               anti-replay context: seq 0x0, oseq 0xe0c0, bitmap 0x00000000
               sel src 0.0.0.0/0 dst 0.0.0.0/0
               lifetime config:
                 limit: soft (INF)(bytes), hard (INF)(bytes)
                 limit: soft (INF)(packets), hard (INF)(packets)
                 expire add: soft 0(sec), hard 0(sec)
                 expire use: soft 0(sec), hard 0(sec)
               lifetime current:
                 9507(bytes), 137(packets)
                 add 2021-02-10 08:20:09 use 2021-02-10 08:30:12
               stats:
                 replay-window 0 replay 0 failed 0

   * BPF program to decrypt traffic:

    Check if the BPF program to decrypt traffic is attached to all network facing
    interfaces, or matching the configuration of ``--encrypt-interface`` (if specified).

    .. code-block:: shell-session

        $ tc filter show dev eth0 ingress
        filter protocol all pref 1 bpf chain 0
        filter protocol all pref 1 bpf chain 0 handle 0x1 bpf_network.o:[from-network] direct-action not_in_hw id 1145 tag 51b408acf94aa23f jited

Disabling Encryption
====================

To disable the encryption, regenerate the YAML with the option
``encryption.enabled=false``
